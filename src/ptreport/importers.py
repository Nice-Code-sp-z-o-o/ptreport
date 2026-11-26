"""Parsers for scanner output files (Burp, Nessus, Nmap, ZAP, OpenVAS/Greenbone).

The input is untrusted. Hardening applied before anything reaches the XML parser:

* size limit (``MAX_BYTES``);
* the bytes are decoded by us (BOM / XML declaration, small allow-list of encodings) and the
  parser is fed a ``str``, so exotic declared encodings cannot hide markup;
* any ``<!ENTITY`` declaration is rejected (no entity expansion, no external entities);
* expat >= 2.4.1 is required (built-in amplification limits);
* only :mod:`xml.etree.ElementTree` is used, which never fetches external resources.

``parse()`` returns plain dicts whose findings/targets/evidence pass the validators in
:mod:`ptreport.validation`; persisting them is the caller's job.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import xml.etree.ElementTree as ET  # noqa: S405 - hardened below: no entities, str input, expat >= 2.4.1
from html.parser import HTMLParser

import pyexpat

from ptreport.cvss_service import CvssInvalid, score_vector
from ptreport.validation import (
    CONFIDENCE_LEVELS,
    HTTP_MESSAGE_MAX,
    LONG,
    SEVERITIES,
    SEVERITY_RANK,
    SHORT,
    normalize_cwe,
    validate_evidence,
    validate_finding,
    validate_target,
)

FORMATS = ("burp", "nessus", "nmap", "zap", "openvas")
LABELS = {"burp": "Burp Suite (XML)", "nessus": "Nessus (.nessus)", "nmap": "Nmap (XML, targets only)",
          "zap": "OWASP ZAP (XML)", "openvas": "OpenVAS / Greenbone (XML)"}
MAX_IMPORTED_FINDINGS = 2000
MAX_IMPORTED_TARGETS = 5000
MAX_BYTES = 50 * 1024 * 1024
RESPONSE_MAX = 200_000
OUTPUT_MAX = 20_000  # per-host scanner output kept in technical details
INSTANCE_MAX = 50
TRUNCATED = "[... truncated by ptreport ...]"

_ROOTS = {
    "issues": "burp",
    "NessusClientData_v2": "nessus",
    "nmaprun": "nmap",
    "OWASPZAPReport": "zap",
    "report": "openvas",
    "get_reports_response": "openvas",
}
_ENCODINGS = {"utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin-1", "latin1", "windows-1252",
              "cp1252", "utf-16", "utf-16le", "utf-16be"}
_DECL_ENCODING = re.compile(rb"""^<\?xml[^>]*?encoding\s*=\s*["']([A-Za-z0-9._-]+)["']""")
_ROOT_TAG = re.compile(r"<([A-Za-z_][\w.:-]*)")
_CWE_IN_TEXT = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)
_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CONFIDENCE_ORDER = {"certain": 2, "probable": 1, "unknown": 0, "": -1}


class ImportError_(ValueError):  # noqa: N801 - name avoids shadowing the builtin ImportError
    """Raised for files that cannot be imported; the message is safe to show to the user."""


# --------------------------------------------------------------------------- #
# Input hardening
# --------------------------------------------------------------------------- #

def _decode(data: bytes) -> str:
    if data.startswith(codecs.BOM_UTF8):
        return data[len(codecs.BOM_UTF8):].decode("utf-8", errors="replace")
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        raise ImportError_("Unsupported file encoding (UTF-32).")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    if data[:2] in (b"<\x00", b"\x00<"):
        return data.decode("utf-16-le" if data[0:1] == b"<" else "utf-16-be", errors="replace")
    encoding = "utf-8"
    m = _DECL_ENCODING.match(data.lstrip()[:200])
    if m:
        encoding = m.group(1).decode("ascii").lower()
        if encoding not in _ENCODINGS:
            raise ImportError_(f"Unsupported file encoding ({encoding[:30]}).")
        if encoding.startswith("utf-16"):
            encoding = "utf-8"  # declared but no BOM / NUL pattern: it is really 8-bit text
    return data.decode(encoding, errors="replace")


def _check_expat() -> None:
    if pyexpat.version_info < (2, 4, 1):
        raise ImportError_("This Python build uses an expat XML library older than 2.4.1; "
                           "importing scanner files is disabled for safety.")


def _load(data: bytes) -> ET.Element:
    if not isinstance(data, (bytes, bytearray)):
        raise ImportError_("Expected file contents as bytes.")
    if len(data) > MAX_BYTES:
        raise ImportError_(f"The file is too large (limit {MAX_BYTES // (1024 * 1024)} MB).")
    if not data.strip():
        raise ImportError_("The file is empty.")
    if b"<!entity" in bytes(data).replace(b"\x00", b"").lower():
        raise ImportError_("The file declares XML entities, which are not allowed.")
    text = _decode(bytes(data))
    if "<!entity" in text.lower():
        raise ImportError_("The file declares XML entities, which are not allowed.")
    _check_expat()
    try:
        return ET.fromstring(text)  # noqa: S314 - entity declarations rejected above, str input
    except ET.ParseError as exc:
        raise ImportError_(f"The file is not valid XML ({exc}).") from None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _root_name(text: str) -> str | None:
    pos, n = 0, len(text)
    while pos < n:
        while pos < n and text[pos] in " \t\r\n﻿":
            pos += 1
        if text.startswith("<?", pos):
            end = text.find("?>", pos)
        elif text.startswith("<!--", pos):
            end = text.find("-->", pos)
            end = end + 1 if end >= 0 else end
        elif text.startswith("<!", pos):
            bracket, close = text.find("[", pos), text.find(">", pos)
            if 0 <= bracket < close:
                close = text.find("]", bracket)
                close = text.find(">", close) if close >= 0 else -1
            end = close - 1 if close >= 0 else -1
        else:
            m = _ROOT_TAG.match(text, pos)
            return m.group(1).split(":")[-1] if m else None
        if end < 0:
            return None
        pos = end + 2
    return None


def detect_format(data: bytes) -> str | None:
    """Return the scanner format of ``data`` judged by its root element, or None."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    try:
        head = _decode(bytes(data[:65536]))
    except ImportError_:
        return None
    return _ROOTS.get(_root_name(head) or "")


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #

def _line(value: str | None, limit: int = SHORT) -> str:
    text = _CONTROL.sub(" ", value or "")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _clip(value: str | None, limit: int = LONG) -> str:
    text = (value or "").replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(text) > limit:
        text = text[: limit - len(TRUNCATED) - 2].rstrip() + "\n" + TRUNCATED
    return text


def _plain(value: str | None) -> str:
    """Normalise plain scanner text: LF line ends, trimmed lines, at most one blank line."""
    text = (value or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in text.split("\n")]
    out = "\n".join(lines).strip("\n")
    return re.sub(r"\n{3,}", "\n\n", out).strip()


def _fence(text: str, limit: int = OUTPUT_MAX) -> str:
    body = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip("\n").replace("```", "'''")
    if len(body) > limit:
        body = body[:limit].rstrip() + "\n" + TRUNCATED
    return f"```\n{body}\n```"


def _join(*parts: str) -> str:
    return "\n\n".join(p.strip() for p in parts if p and p.strip())


def _unique(items) -> list:
    seen, out = set(), []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _urls(text: str) -> list[str]:
    return [u.rstrip(".,;:)") for u in _URL_IN_TEXT.findall(text or "")]


def _txt(el: ET.Element | None, path: str) -> str:
    if el is None:
        return ""
    found = el.find(path)
    return (found.text or "").strip() if found is not None and found.text else ""


class _HTMLText(HTMLParser):
    _BLOCK = {"p", "div", "ul", "ol", "table", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
              "section", "article", "dl", "dt", "dd"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []
        self.skip = 0
        self.pre = 0
        self.li = 0
        self.bullet = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        elif tag == "br":
            self.parts.append("\n")
        elif tag == "li":
            self.li += 1
            self.parts.append("\n")
            self.bullet = True
        elif tag == "pre":
            self.parts.append("\n\n```\n")
            self.pre += 1
        elif tag in ("td", "th"):
            self.parts.append(" ")
        elif tag in self._BLOCK and not self.li:
            self.parts.append("\n\n")
        if tag == "a":
            href = dict(attrs).get("href") or ""
            if href.lower().startswith(("http://", "https://")):
                self.links.append(href.strip())

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        elif tag == "li":
            self.li = max(0, self.li - 1)
            self.parts.append("\n")
        elif tag == "pre" and self.pre:
            self.pre -= 1
            self.parts.append("\n```\n\n")
        elif tag in self._BLOCK and not self.li:
            self.parts.append("\n\n")

    def handle_data(self, data):
        if self.skip:
            return
        if self.pre:
            self.parts.append(data.replace("```", "'''"))
            return
        if self.bullet and data.strip():
            self.parts.append("- ")
            self.bullet = False
        self.parts.append(re.sub(r"\s+", " ", data))

    def result(self) -> str:
        out: list[str] = []
        in_fence = False
        for raw in "".join(self.parts).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            if raw.strip() == "```":
                in_fence = not in_fence
                out.append("```")
            elif in_fence:
                out.append(raw.rstrip())
            else:
                out.append(re.sub(r"[ \t]+", " ", raw).strip())
        text = re.sub(r"\n{3,}", "\n\n", "\n".join(out))
        # keep consecutive list items together (</li><li> yields a blank line in between)
        text = re.sub(r"(?m)^(- .*)\n\n(?=- )", r"\1\n", text)
        return text.strip()


def html_to_text(html: str | None) -> tuple[str, list[str]]:
    """Convert scanner HTML to the plain-text conventions of ``rendering``; also return link URLs."""
    if not html or not html.strip():
        return "", []
    parser = _HTMLText()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML must never break an import
        return _plain(re.sub(r"<[^>]+>", " ", html)), []
    return parser.result(), parser.links


def _cvss(vectors: str | list[str], title: str, warnings: list[str]) -> tuple[str, str]:
    """Return (version, vector) of the first candidate ``score_vector`` accepts, else ("", "")."""
    candidates = [v.strip() for v in ([vectors] if isinstance(vectors, str) else vectors) if v and v.strip()]
    for vector in candidates:
        try:
            result = score_vector(vector)
        except CvssInvalid:
            continue
        return result.version, result.vector
    if candidates:
        warnings.append(f"{_line(title, 80)}: CVSS vector ignored because it is invalid "
                        f"({_line(candidates[0], 80)}).")
    return "", ""


def _cwe(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    m = _CWE_IN_TEXT.search(value)
    return normalize_cwe(m.group(1) if m else value) or ""


def _worst(a: str, b: str) -> str:
    return a if SEVERITY_RANK[a] <= SEVERITY_RANK[b] else b


# --------------------------------------------------------------------------- #
# Result builder
# --------------------------------------------------------------------------- #

class _Result:
    def __init__(self, fmt: str, include_info: bool) -> None:
        self.fmt = fmt
        self.include_info = include_info
        self.targets: list[dict] = []
        self._target_index: dict[tuple[str, str], str] = {}
        self.findings: list[dict] = []
        self.warnings: list[str] = []
        self.skipped_info = 0

    def target(self, name: str, kind: str, address: str, description: str = "") -> str:
        address = _line(address, 2048)
        name = _line(name, 200) or address[:200] or "Unnamed target"
        ident = (kind, address or name)
        if ident in self._target_index:
            return self._target_index[ident]
        key = f"t{len(self.targets) + 1}"
        self._target_index[ident] = key
        self.targets.append({"key": key, "name": name, "kind": kind, "address": address,
                             "description": _clip(description)})
        return key

    def keep(self, severity: str) -> bool:
        if severity == "info" and not self.include_info:
            self.skipped_info += 1
            return False
        return True

    def finding(self, *, title: str, severity: str, confidence: str = "", cvss_vector: str | list[str] = "", cwe: str = "",
                description: str = "", impact: str = "", technical_details: str = "", poc: str = "",
                remediation: str = "", refs: list[str] | None = None, target_keys: list[str] | None = None,
                evidence: list[dict] | None = None) -> None:
        if severity not in SEVERITIES or confidence not in ("",) + CONFIDENCE_LEVELS:
            raise ValueError("internal: invalid severity/confidence")
        title = _line(title) or "Untitled finding"
        version, vector = _cvss(cvss_vector, title, self.warnings)
        self.findings.append({
            "key": f"f{len(self.findings) + 1}",
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "cvss_version": version,
            "cvss_vector": vector,
            "cwe": _cwe(cwe),
            "description": _clip(description),
            "impact": _clip(impact),
            "technical_details": _clip(technical_details),
            "poc": _clip(poc),
            "remediation": _clip(remediation),
            "refs": _clip("\n".join(_unique(_line(r, 2000) for r in (refs or [])))),
            "target_keys": _unique(target_keys or []),
            "evidence": evidence or [],
            "source": self.fmt,
        })

    def done(self) -> dict:
        if self.skipped_info:
            self.warnings.append(f"Skipped {self.skipped_info} informational item(s); "
                                 "enable 'include informational' to import them.")
        if not self.findings and self.fmt != "nmap":
            self.warnings.append("No findings were found in the file.")
        return {"format": self.fmt, "targets": self.targets, "findings": self.findings,
                "warnings": self.warnings}


def _evidence(title: str, request: str, response: str) -> dict | None:
    request = (request or "").replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    response = (response or "").replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    if not request.strip():
        return None
    if len(request) > HTTP_MESSAGE_MAX:
        request = request[: HTTP_MESSAGE_MAX - len(TRUNCATED) - 2] + "\n" + TRUNCATED
    if len(response) > RESPONSE_MAX:
        response = response[:RESPONSE_MAX] + "\n" + TRUNCATED
    return {"title": _line(title) or "HTTP request", "request": request, "response": response}


# --------------------------------------------------------------------------- #
# Burp Suite
# --------------------------------------------------------------------------- #

_BURP_SEVERITY = {"high": "high", "medium": "medium", "low": "low", "information": "info", "info": "info"}
_BURP_CONFIDENCE = {"certain": "certain", "firm": "probable", "tentative": "unknown"}


def _burp_message(el: ET.Element | None, warnings: list[str]) -> str:
    if el is None or not el.text:
        return ""
    if (el.get("base64") or "").lower() == "true":
        try:
            raw = base64.b64decode("".join(el.text.split()), validate=False)
        except (binascii.Error, ValueError):
            warnings.append("A Burp request/response could not be base64-decoded and was skipped.")
            return ""
        return raw.decode("utf-8", errors="replace")
    return el.text


def _parse_burp(root: ET.Element, res: _Result) -> None:
    groups: dict[tuple[str, str], list[ET.Element]] = {}
    for issue in root.iter("issue"):
        sev_raw = _txt(issue, "severity").lower()
        if sev_raw == "false positive":
            continue
        if sev_raw not in _BURP_SEVERITY:
            res.warnings.append(f"Burp issue '{_line(_txt(issue, 'name'), 80)}' has unknown severity; "
                                "imported as informational.")
        groups.setdefault((_txt(issue, "type"), _txt(issue, "name")), []).append(issue)

    for (_type, name), issues in groups.items():
        severity = "info"
        confidence = ""
        for issue in issues:
            severity = _worst(severity, _BURP_SEVERITY.get(_txt(issue, "severity").lower(), "info"))
            conf = _BURP_CONFIDENCE.get(_txt(issue, "confidence").lower(), "")
            if _CONFIDENCE_ORDER[conf] > _CONFIDENCE_ORDER[confidence]:
                confidence = conf
        if not res.keep(severity):
            continue
        first = issues[0]
        background, links = html_to_text(_txt(first, "issueBackground"))
        rem_background, rem_links = html_to_text(_txt(first, "remediationBackground"))
        references, ref_links = html_to_text(_txt(first, "references"))
        classes_html = _txt(first, "vulnerabilityClassifications")
        classes, class_links = html_to_text(classes_html)
        refs = links + rem_links + ref_links + _urls(references) + class_links

        target_keys: list[str] = []
        evidence: list[dict] = []
        locations: list[str] = []
        details: list[tuple[str, str]] = []
        rem_details: list[str] = []
        for issue in issues:
            host_el = issue.find("host")
            url = _txt(issue, "host")
            ip = host_el.get("ip", "") if host_el is not None else ""
            if url:
                target_keys.append(res.target(url, "web", url, f"IP: {ip}" if ip else ""))
            loc = _txt(issue, "location") or _txt(issue, "path")
            label = _line(f"{url}{loc}" if loc.startswith("/") else f"{url} {loc}".strip())
            locations.append(label)
            detail, dl = html_to_text(_txt(issue, "issueDetail"))
            rem_detail, rl = html_to_text(_txt(issue, "remediationDetail"))
            refs += dl + rl
            if detail:
                details.append((label, detail))
            if rem_detail:
                rem_details.append(rem_detail)
            for rr in issue.findall("requestresponse"):
                ev = _evidence(loc or url, _burp_message(rr.find("request"), res.warnings),
                               _burp_message(rr.find("response"), res.warnings))
                if ev:
                    evidence.append(ev)

        locations = _unique(locations)
        if len(issues) > 1:
            detail_text = "Affected locations:\n\n" + "\n".join(f"- {loc}" for loc in locations)
            per_location = [f"**{_line(lbl, 200)}**\n\n{d}" for lbl, d in details]
            if len(_unique(d for _, d in details)) == 1:
                per_location = [details[0][1]]
            detail_text = _join(detail_text, *per_location)
        else:
            detail_text = details[0][1] if details else ""
        res.finding(
            title=name, severity=severity, confidence=confidence,
            cwe=classes_html,
            description=_join(background, detail_text),
            remediation=_join(rem_background, *_unique(rem_details)),
            refs=refs, target_keys=target_keys, evidence=evidence,
        )


# --------------------------------------------------------------------------- #
# Nessus
# --------------------------------------------------------------------------- #

_NESSUS_SEVERITY = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}


def _parse_nessus(root: ET.Element, res: _Result) -> None:
    groups: dict[str, dict] = {}
    for host in root.iter("ReportHost"):
        props = {t.get("name", ""): (t.text or "").strip() for t in host.iter("tag")}
        ip = props.get("host-ip") or host.get("name", "")
        fqdn = props.get("host-fqdn") or props.get("hostname") or ""
        name = fqdn or ip or host.get("name", "")
        desc = f"OS: {props['operating-system']}" if props.get("operating-system") else ""
        tkey = res.target(name, "host", ip or name, desc)
        for item in host.iter("ReportItem"):
            severity = _NESSUS_SEVERITY.get((item.get("severity") or "").strip(), "info")
            plugin = item.get("pluginID") or item.get("pluginName") or "?"
            group = groups.setdefault(plugin, {"item": item, "severity": severity, "hosts": [], "out": []})
            group["severity"] = _worst(group["severity"], severity)
            group["hosts"].append(tkey)
            where = f"{name}:{item.get('port', '0')}/{item.get('protocol', 'tcp')}"
            group["out"].append((where, item.findtext("plugin_output") or ""))

    for plugin, group in groups.items():
        if not res.keep(group["severity"]):
            continue
        item = group["item"]
        solution = _plain(item.findtext("solution"))
        if solution.lower() in ("n/a", "none"):
            solution = ""
        vector = [_txt(item, "cvss3_vector"), _txt(item, "cvss4_vector"), _txt(item, "cvss_vector")]
        refs = _plain(item.findtext("see_also")).split("\n")
        refs += [(c.text or "").strip() for c in item.findall("cve")]
        lines = ["Affected:", ""] + [f"- {w}" for w in _unique(w for w, _ in group["out"])]
        outputs = [f"**{_line(w, 200)}**\n\n{_fence(o)}" for w, o in group["out"] if o.strip()]
        res.finding(
            title=item.get("pluginName") or f"Nessus plugin {plugin}",
            severity=group["severity"],
            cvss_vector=vector,
            cwe=_txt(item, "cwe"),
            description=_join(_plain(item.findtext("synopsis")), _plain(item.findtext("description"))),
            technical_details=_join("\n".join(lines), *outputs),
            remediation=solution,
            refs=[r.strip() for r in refs],
            target_keys=group["hosts"],
        )


# --------------------------------------------------------------------------- #
# Nmap
# --------------------------------------------------------------------------- #

def _cell(value: str) -> str:
    return _line(value, 200).replace("|", "\\|") or "-"


def _parse_nmap(root: ET.Element, res: _Result) -> None:
    up = 0
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addrs = {a.get("addrtype"): a.get("addr", "") for a in host.findall("address")}
        address = addrs.get("ipv4") or addrs.get("ipv6") or ""
        if not address:
            continue
        up += 1
        hostnames = _unique(h.get("name", "") for h in host.iter("hostname"))
        rows = []
        for port in host.iter("port"):
            state = (port.find("state").get("state", "") if port.find("state") is not None else "")
            if state not in ("open", "open|filtered"):
                continue
            svc = port.find("service")
            name = product = ""
            if svc is not None:
                name = svc.get("name", "")
                product = " ".join(x for x in (svc.get("product"), svc.get("version"), svc.get("extrainfo")) if x)
            rows.append(f"| {_cell(port.get('portid', '') + '/' + port.get('protocol', ''))} | {_cell(state)} "
                        f"| {_cell(name)} | {_cell(product)} |")
        parts = []
        if len(hostnames) > 1:
            parts.append("Hostnames: " + ", ".join(hostnames))
        if rows:
            parts.append("\n".join(["| Port | State | Service | Version |", "|---|---|---|---|", *rows]))
        else:
            parts.append("No open ports found.")
        osmatch = host.find("os/osmatch")
        if osmatch is not None and osmatch.get("name"):
            parts.append(f"OS guess: {osmatch.get('name')} ({osmatch.get('accuracy', '?')}%)")
        res.target(hostnames[0] if hostnames else address, "host", address, _join(*parts))
    if not up:
        res.warnings.append("No hosts that are up were found in the Nmap file.")


# --------------------------------------------------------------------------- #
# OWASP ZAP
# --------------------------------------------------------------------------- #

_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_ZAP_CONFIDENCE = {"4": "certain", "3": "certain", "2": "probable", "1": "unknown"}


def _parse_zap(root: ET.Element, res: _Result) -> None:
    groups: dict[tuple[str, str], dict] = {}
    false_positives = 0
    for site in root.iter("site"):
        site_name = site.get("name") or site.get("host") or ""
        tkey = res.target(site_name, "web", site_name) if site_name else None
        for alert in site.iter("alertitem"):
            conf_raw = _txt(alert, "confidence")
            if conf_raw == "0":
                false_positives += 1
                continue
            name = _txt(alert, "alert") or _txt(alert, "name")
            g = groups.setdefault((_txt(alert, "pluginid"), name), {
                "alert": alert, "name": name, "severity": "info", "confidence": "", "targets": [],
                "instances": [], "count": 0})
            g["severity"] = _worst(g["severity"], _ZAP_RISK.get(_txt(alert, "riskcode"), "info"))
            conf = _ZAP_CONFIDENCE.get(conf_raw, "")
            if _CONFIDENCE_ORDER[conf] > _CONFIDENCE_ORDER[g["confidence"]]:
                g["confidence"] = conf
            if tkey:
                g["targets"].append(tkey)
            instances = alert.findall("instances/instance")
            g["instances"] += instances
            count = _txt(alert, "count")
            g["count"] += max(int(count) if count.isdigit() else 0, len(instances))
    if false_positives:
        res.warnings.append(f"Skipped {false_positives} ZAP alert(s) marked as false positive.")

    for g in groups.values():
        if not res.keep(g["severity"]):
            continue
        alert = g["alert"]
        desc, l1 = html_to_text(_txt(alert, "desc"))
        solution, l2 = html_to_text(_txt(alert, "solution"))
        other, l3 = html_to_text(_txt(alert, "otherinfo"))
        reference, l4 = html_to_text(_txt(alert, "reference"))
        lines = []
        for inst in g["instances"][:INSTANCE_MAX]:
            extra = [f"{label}: {_line(_txt(inst, tag), 200)}" for tag, label in
                     (("param", "param"), ("attack", "attack"), ("evidence", "evidence")) if _txt(inst, tag)]
            entry = f"- {_line(_txt(inst, 'method'), 20)} {_line(_txt(inst, 'uri'), 2000)}".rstrip()
            lines.append(entry + (f" ({', '.join(extra)})" if extra else ""))
        rest = max(g["count"], len(g["instances"])) - len(lines)
        if rest > 0:
            lines.append(f"- and {rest} more")
        details = ("Instances:\n\n" + "\n".join(lines)) if lines else ""
        cwe = _txt(alert, "cweid")
        res.finding(
            title=g["name"] or "ZAP alert", severity=g["severity"], confidence=g["confidence"],
            cwe=cwe if cwe.isdigit() and int(cwe) > 0 else "",
            description=desc, remediation=solution,
            technical_details=_join(details, other),
            refs=l1 + l2 + l3 + l4 + _urls(reference),
            target_keys=g["targets"],
        )


# --------------------------------------------------------------------------- #
# OpenVAS / Greenbone
# --------------------------------------------------------------------------- #

_OPENVAS_THREAT = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "log": "info"}


def _nvt_tags(raw: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    last = None
    for piece in (raw or "").split("|"):
        key, sep, value = piece.partition("=")
        if sep and re.fullmatch(r"[a-z_]+", key.strip()):
            last = key.strip()
            tags[last] = value
        elif last:
            tags[last] += "|" + piece
    return {k: v.strip() for k, v in tags.items()}


def _parse_openvas(root: ET.Element, res: _Result) -> None:
    groups: dict[str, dict] = {}
    for result in root.iter("result"):
        nvt = result.find("nvt")
        if nvt is None:
            continue
        severity = _OPENVAS_THREAT.get(_txt(result, "threat").lower())
        if severity is None:  # False Positive / Debug / unknown
            continue
        host_el = result.find("host")
        ip = (host_el.text or "").strip() if host_el is not None else ""
        hostname = _txt(host_el, "hostname") if host_el is not None else ""
        tkey = res.target(hostname or ip, "host", ip or hostname) if (ip or hostname) else None
        oid = nvt.get("oid") or _txt(nvt, "name")
        g = groups.setdefault(oid, {"nvt": nvt, "name": _txt(nvt, "name") or _txt(result, "name"),
                                    "severity": severity, "targets": [], "out": []})
        g["severity"] = _worst(g["severity"], severity)
        if tkey:
            g["targets"].append(tkey)
        g["out"].append((f"{hostname or ip}:{_txt(result, 'port') or 'general'}", result.findtext("description") or ""))

    for oid, g in groups.items():
        if not res.keep(g["severity"]):
            continue
        nvt = g["nvt"]
        tags = _nvt_tags(_txt(nvt, "tags"))
        vector = tags.get("cvss_base_vector", "")
        if not vector or vector.lower() == "none":
            vector = next((_txt(s, "value") for s in nvt.iter("severity") if _txt(s, "value")), "")
        refs = []
        for ref in nvt.iter("ref"):
            kind, rid = (ref.get("type") or "").lower(), (ref.get("id") or "").strip()
            if kind in ("cve", "url", "cert-bund", "dfn-cert") and rid:
                refs.append(rid)
        solution = _plain(_txt(nvt, "solution")) or _plain(tags.get("solution", ""))
        lines = ["Affected:", ""] + [f"- {w}" for w in _unique(w for w, _ in g["out"])]
        outputs = [f"**{_line(w, 200)}**\n\n{_fence(o)}" for w, o in g["out"] if o.strip()]
        res.finding(
            title=g["name"] or f"OpenVAS NVT {oid}", severity=g["severity"],
            cvss_vector=vector if vector.lower() != "none" else "",
            description=_join(_plain(tags.get("summary")), _plain(tags.get("insight")),
                              f"Affected software: {_plain(tags['affected'])}" if tags.get("affected") else ""),
            impact=_plain(tags.get("impact")),
            technical_details=_join("\n".join(lines),
                                    f"Detection method: {_plain(tags['vuldetect'])}" if tags.get("vuldetect") else "",
                                    *outputs),
            remediation=solution,
            refs=refs,
            target_keys=g["targets"],
        )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

_PARSERS = {"burp": _parse_burp, "nessus": _parse_nessus, "nmap": _parse_nmap, "zap": _parse_zap,
            "openvas": _parse_openvas}


def parse(data: bytes, fmt: str | None = None, include_info: bool = False) -> dict:
    """Parse a scanner file into importable targets and findings (see module docstring)."""
    if fmt is not None and fmt not in FORMATS:
        raise ImportError_(f"Unknown format; choose one of: {', '.join(FORMATS)}.")
    root = _load(data)
    detected = _ROOTS.get(_local(root.tag))
    if detected is None:
        raise ImportError_("Unrecognised file: expected a Burp, Nessus, Nmap, ZAP or OpenVAS XML report.")
    if fmt is not None and fmt != detected:
        raise ImportError_(f"The file looks like a {detected} report, not {fmt}.")
    res = _Result(detected, include_info)
    _PARSERS[detected](root, res)
    return res.done()


def clean(parsed: dict) -> dict:
    """Run the importer output through the same validators as manual input; drop what does not pass.

    Shared by the web upload and ``ptreport import-scan``; the result is what gets staged/applied."""
    warnings = list(parsed.get("warnings", []))
    findings = []
    for f in parsed["findings"][:MAX_IMPORTED_FINDINGS]:
        clean_f, errors = validate_finding({**f, "status": "open"}, target_ids_raw=[])
        if errors:
            warnings.append(f"Skipped \"{f.get('title', '')[:80]}\": " + "; ".join(errors.values()))
            continue
        evidence = []
        for e in f.get("evidence", []):
            ev, ev_errors = validate_evidence({**e, "source": "import"})
            if not ev_errors:
                evidence.append(ev)
        clean_f.pop("target_ids", None)
        findings.append({**clean_f, "key": f["key"], "target_keys": list(f.get("target_keys", [])),
                         "evidence": evidence})
    if len(parsed["findings"]) > MAX_IMPORTED_FINDINGS:
        warnings.append(f"Only the first {MAX_IMPORTED_FINDINGS} findings were read.")
    targets = []
    for t in parsed["targets"][:MAX_IMPORTED_TARGETS]:
        clean_t, errors = validate_target(t)
        if errors:
            warnings.append(f"Skipped target \"{t.get('name', '')[:80]}\": " + "; ".join(errors.values()))
            continue
        targets.append({**clean_t, "key": t["key"]})
    if len(parsed["targets"]) > MAX_IMPORTED_TARGETS:
        warnings.append(f"Only the first {MAX_IMPORTED_TARGETS} targets were read.")
    known = {t["key"] for t in targets}
    for f in findings:
        f["target_keys"] = [k for k in f["target_keys"] if k in known]
    return {"format": parsed["format"], "targets": targets, "findings": findings, "warnings": warnings}
