"""Imports of AI / analysis tool results into the AI queue: SARIF 2.1.0, ptai proof capsules, proposal JSON.

Every file becomes *proposals* (see :mod:`ptreport.proposals`); nothing is written to the report itself. The input
is untrusted: size limit, UTF-8 only, nesting depth limit, every value type-checked, and every proposal goes
through the proposal validators (invalid ones are skipped with a warning, the rest is imported).

* **SARIF 2.1.0** (``ptai export --sarif``, Semgrep, CodeQL, ...): one finding proposal per result. Title from the
  rule's shortDescription / name or the message; severity from ``properties.security-severity`` (0-10) or the
  level; CWE from rule tags (``CWE-79``, ``external/cwe/cwe-79``), properties or a ``CWE-n`` rule id; URL locations
  become targets, file locations code evidence (with the region's snippet); ``webRequest`` / ``webResponse`` become
  HTTP evidence; ``properties.verdict`` (ptai) the verdict. Results of kind pass/notApplicable, absent baseline
  results and suppressed results are skipped; identical results are imported once.
* **ptai proof capsule** (``capsule_schema_version`` 1, as written by pentest-ai's ``engine/capsule.py``): the
  finding, the receipt's verdict, oracle and replay counts, request/response when the receipt has them; the
  capsule itself is attached as an evidence file. A refuted verdict is skipped; an integrity mismatch is reported
  and downgrades ``verified`` to ``candidate``.
* **ptreport proposal JSON v1**: as documented in ``docs/integrations.md``.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import re
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from ptreport import proposals, repo

FORMATS = ("sarif", "ptai", "ptreport")
LABELS = {"sarif": "SARIF 2.1.0", "ptai": "ptai proof capsule", "ptreport": "ptreport proposal JSON"}
MAX_BYTES = 50 * 1024 * 1024
MAX_DEPTH = 64
MAX_RESULTS = 2000
MAX_LOCATIONS = 20
SNIPPET_MAX = 20_000

# pentest-ai bug classes -> CWE (only where the mapping is unambiguous)
BUG_CLASS_CWE = {
    "xss": "CWE-79", "xss_reflected": "CWE-79", "xss_stored": "CWE-79", "xss_dom": "CWE-79",
    "sqli": "CWE-89", "sql_injection": "CWE-89", "command_injection": "CWE-78", "os_command_injection": "CWE-78",
    "rce": "CWE-94", "code_injection": "CWE-94", "ssti": "CWE-1336", "ssrf": "CWE-918", "xxe": "CWE-611",
    "path_traversal": "CWE-22", "lfi": "CWE-22", "open_redirect": "CWE-601", "idor": "CWE-639", "bola": "CWE-639",
    "csrf": "CWE-352", "cors_misconfiguration": "CWE-942", "deserialization": "CWE-502", "jwt_none": "CWE-347",
    "crlf_injection": "CWE-93", "header_injection": "CWE-113", "nosql_injection": "CWE-943",
}
_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
_LANG_BY_EXT = {"c": "c", "h": "c", "cc": "cpp", "cpp": "cpp", "cxx": "cpp", "hpp": "cpp", "hh": "cpp",
                "s": "asm", "asm": "asm", "java": "java", "kt": "java", "py": "python"}
_CWE_TAG = re.compile(r"(?:^|[/:\s])cwe[-_/ ]?(\d{1,5})\b", re.IGNORECASE)
_ARG = re.compile(r"\{(\d+)\}")


class ImportError_(ValueError):  # noqa: N801 - mirrors ptreport.importers.ImportError_
    """A file that cannot be imported; the message is safe to show."""


# ------------------------------------------------------------------ loading --

def load_json(data: bytes) -> Any:
    if not isinstance(data, (bytes, bytearray)):
        raise ImportError_("Expected file contents as bytes.")
    if len(data) > MAX_BYTES:
        raise ImportError_(f"The file is too large (limit {MAX_BYTES // (1024 * 1024)} MB).")
    data = bytes(data)
    if data.startswith(codecs.BOM_UTF8):
        data = data[len(codecs.BOM_UTF8):]
    if not data.strip():
        raise ImportError_("The file is empty.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ImportError_("The file is not UTF-8 text.") from None
    try:
        doc = json.loads(text)
    except RecursionError:
        raise ImportError_(f"The JSON is nested too deeply (limit {MAX_DEPTH} levels).") from None
    except ValueError as exc:
        raise ImportError_(f"The file is not valid JSON ({str(exc)[:120]}).") from None
    stack = [(doc, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ImportError_(f"The JSON is nested too deeply (limit {MAX_DEPTH} levels).")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return doc


def detect(doc: Any) -> str | None:
    if isinstance(doc, dict):
        if isinstance(doc.get("runs"), list) and (
                doc.get("version") == "2.1.0" or "sarif" in str(doc.get("$schema", "")).lower()):
            return "sarif"
        if "capsule_schema_version" in doc or isinstance(doc.get("capsules"), list):
            return "ptai"
        if doc.get("format") == proposals.SCHEMA_FORMAT or "kind" in doc:
            return "ptreport"
    if isinstance(doc, list) and doc and isinstance(doc[0], dict):
        if "capsule_schema_version" in doc[0]:
            return "ptai"
        if "kind" in doc[0]:
            return "ptreport"
    return None


# ------------------------------------------------------------------ helpers --

def _s(value: Any, limit: int = 300) -> str:
    """A single-line string from an untrusted value (non-strings become '')."""
    if not isinstance(value, str):
        return ""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", value).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _t(value: Any, limit: int = 200_000) -> str:
    """Multi-line text from an untrusted value."""
    if not isinstance(value, str):
        return ""
    text = value.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n").strip()
    return text if len(text) <= limit else text[: limit - 40].rstrip() + "\n[... truncated by ptreport ...]"


def _d(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _l(value: Any, limit: int = 10_000) -> list:
    return value[:limit] if isinstance(value, list) else []


def _msg(value: Any, args: list | None = None) -> str:
    """SARIF message / multiformatMessageString: text (or markdown), with {0} placeholders filled."""
    obj = _d(value)
    text = obj.get("text") if isinstance(obj.get("text"), str) else obj.get("markdown")
    if not isinstance(text, str):
        text = value if isinstance(value, str) else ""
    if args:
        text = _ARG.sub(lambda m: str(args[int(m.group(1))]) if int(m.group(1)) < len(args)
                        and isinstance(args[int(m.group(1))], (str, int, float)) else m.group(0), text)
    return text


def _severity_from_score(score: Any) -> str | None:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if not 0 <= value <= 10:
        return None
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low" if value > 0 else "info"


def _cwe_from(*candidates: Any) -> str:
    for c in candidates:
        values = c if isinstance(c, list) else [c]
        for v in values:
            if isinstance(v, int) and not isinstance(v, bool) and v > 0:
                return f"CWE-{v}"
            if isinstance(v, str):
                m = _CWE_TAG.search(" " + v)
                if m and int(m.group(1)) > 0:
                    return f"CWE-{int(m.group(1))}"
    return ""


def _fence(text: str, lang: str = "") -> str:
    body = text.replace("```", "'''")
    return f"```{lang}\n{body}\n```"


def _dedupe_key(item: dict) -> str:
    return hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


# -------------------------------------------------------------------- SARIF --

def _http_request(wr: dict) -> str:
    method = _s(wr.get("method"), 20) or "GET"
    target = _s(wr.get("target"), 8000)
    protocol = _s(wr.get("protocol"), 10) or "HTTP"
    version = _s(wr.get("version"), 10) or "1.1"
    path, host = target or "/", ""
    if re.match(r"^https?://", target, re.IGNORECASE):
        try:
            parts = urlsplit(target)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            host = parts.netloc.rsplit("@", 1)[-1]
        except ValueError:
            pass
    headers = {k: v for k, v in _d(wr.get("headers")).items() if isinstance(k, str) and isinstance(v, str)}
    lines = [f"{method} {path} {protocol}/{version}"]
    if host and not any(k.lower() == "host" for k in headers):
        lines.append(f"Host: {host}")
    lines += [f"{_s(k, 200)}: {_s(v, 8000)}" for k, v in list(headers.items())[:200]]
    return "\r\n".join(lines) + "\r\n\r\n" + _body(wr.get("body"))


def _http_response(resp: dict) -> str:
    if resp.get("noResponseReceived") is True:
        return ""
    status = resp.get("statusCode")
    if isinstance(status, bool) or not isinstance(status, int):
        return ""
    protocol = _s(resp.get("protocol"), 10) or "HTTP"
    version = _s(resp.get("version"), 10) or "1.1"
    lines = [f"{protocol}/{version} {status} {_s(resp.get('reasonPhrase'), 100)}".rstrip()]
    headers = {k: v for k, v in _d(resp.get("headers")).items() if isinstance(k, str) and isinstance(v, str)}
    lines += [f"{_s(k, 200)}: {_s(v, 8000)}" for k, v in list(headers.items())[:200]]
    return "\r\n".join(lines) + "\r\n\r\n" + _body(resp.get("body"))


def _body(body: Any) -> str:
    """SARIF artifactContent: text, or binary (base64) shown as text when it is UTF-8."""
    obj = _d(body)
    if isinstance(obj.get("text"), str):
        return _t(obj["text"], 1_000_000)
    if isinstance(obj.get("binary"), str):
        try:
            raw = base64.b64decode(obj["binary"], validate=True)
        except (binascii.Error, ValueError):
            return ""
        try:
            return _t(raw.decode("utf-8"), 1_000_000)
        except UnicodeDecodeError:
            return f"[binary body, {len(raw)} bytes]"
    return ""


def _location(loc: dict) -> dict:
    """{url} for web locations, {file, lines, logical, snippet} for code locations."""
    phys = _d(loc.get("physicalLocation"))
    art = _d(phys.get("artifactLocation"))
    uri = _s(art.get("uri"), 2000)
    region = _d(phys.get("region"))
    context = _d(phys.get("contextRegion"))
    logical = next((_s(x.get("fullyQualifiedName") or x.get("name"), 200) for x in map(_d, _l(loc.get(
        "logicalLocations"), 5)) if x.get("fullyQualifiedName") or x.get("name")), "")
    if re.match(r"^https?://", uri, re.IGNORECASE):
        return {"url": uri}
    if uri.lower().startswith("file://"):
        uri = re.sub(r"^file://[^/]*", "", uri)
    start, end = region.get("startLine"), region.get("endLine")
    lines = ""
    if isinstance(start, int) and not isinstance(start, bool) and start > 0:
        lines = f"{start}" + (f"-{end}" if isinstance(end, int) and not isinstance(end, bool) and end > start else "")
    snippet = _msg(region.get("snippet")) or _msg(context.get("snippet"))
    if not uri and not logical:
        return {}
    return {"file": uri, "lines": lines, "logical": logical, "snippet": _t(snippet, SNIPPET_MAX)}


def _sarif_result(run: dict, result: dict, rules: dict, rule_list: list, tool: dict, warnings: list,
                  counters: dict) -> dict | None:
    kind = result.get("kind")
    if kind in ("pass", "notApplicable"):
        counters["pass"] += 1
        return None
    if result.get("baselineState") == "absent":
        counters["absent"] += 1
        return None
    suppressions = _l(result.get("suppressions"), 50)
    if any(_d(s).get("status") in (None, "accepted") for s in suppressions):
        counters["suppressed"] += 1
        return None
    rule_ref = _d(result.get("rule"))
    rule_id = _s(result.get("ruleId") or rule_ref.get("id"), 200)
    index = result.get("ruleIndex", rule_ref.get("index"))
    rule = {}
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rule_list):
        rule = _d(rule_list[index])
    elif rule_id in rules:
        rule = rules[rule_id]
    elif "/" in rule_id and rule_id.split("/")[0] in rules:  # ruleId "parent/child"
        rule = rules[rule_id.split("/")[0]]
    rule_id = rule_id or _s(rule.get("id"), 200)
    props = {**_d(rule.get("properties")), **_d(result.get("properties"))}

    verdict = props.get("verdict") if isinstance(props.get("verdict"), str) else ""
    if verdict == "refuted":
        counters["refuted"] += 1
        return None
    if verdict not in ("verified", "candidate"):
        verdict = ""
    message = _msg(result.get("message"), _l(_d(result.get("message")).get("arguments"), 50))
    title = _s(_msg(rule.get("shortDescription")), 300) or _s(rule.get("name"), 300) or \
        _s(message.split("\n", 1)[0], 300) or _s(rule_id, 300) or "Untitled result"
    level = result.get("level") or _d(rule.get("defaultConfiguration")).get("level") or "warning"
    severity = _severity_from_score(props.get("security-severity")) or \
        _severity_from_score(props.get("cvss_score")) or _LEVEL_SEVERITY.get(level, "medium")
    cwe = _cwe_from(props.get("cwe_id"), props.get("cwe"), props.get("tags"), rule_id)
    full = _t(_msg(rule.get("fullDescription")))
    description = "\n\n".join(p for p in (full, _t(message) if _t(message) not in (full, title) else "") if p)
    help_text = _t(_msg(rule.get("help")))
    vector = props.get("cvss_vector") or props.get("cvssVector") or props.get("cvss")
    data: dict[str, Any] = {
        "title": title, "severity": severity, "cwe": cwe, "description": description, "remediation": help_text,
        "refs": _s(rule.get("helpUri"), 2000) if re.match(r"^https?://", str(rule.get("helpUri", ""))) else "",
        "targets": [], "evidence": [], "code_evidence": [], "match": {"rule_id": rule_id}}
    if isinstance(vector, str) and vector.startswith(("CVSS:", "AV:")):
        data["cvss_vector"] = _s(vector, 512)

    details, files = [], []
    if rule_id:
        details.append(f"Rule: `{rule_id}`")
    for loc in map(_d, _l(result.get("locations"), MAX_LOCATIONS)):
        place = _location(loc)
        if place.get("url"):
            target = proposals.target_from_address(place["url"])
            if target not in data["targets"]:
                data["targets"].append(target)
            details.append(f"Location: {place['url']}")
        elif place:
            where = place["file"] + (f":{place['lines']}" if place["lines"] else "")
            location = " ".join(x for x in (where, place["logical"]) if x)[:300]
            files.append(place["file"])
            details.append(f"Location: `{location}`")
            if place["snippet"]:
                ext = place["file"].rsplit(".", 1)[-1].lower() if "." in place["file"] else ""
                name = place["file"].replace("\\", "/").rsplit("/", 1)[-1] or place["logical"] or "Code"
                data["code_evidence"].append({
                    "title": _s(name + (f", line{'s' if '-' in place['lines'] else ''} {place['lines']}"
                                        if place["lines"] else ""), 300),
                    "location": location, "language": _LANG_BY_EXT.get(ext, "text"), "code": place["snippet"]})
    oracle = props.get("oracle_kind")
    replay = _d(props.get("replay"))
    if isinstance(oracle, str) or replay:
        line = "Verification: " + (verdict or "no verdict")
        if isinstance(oracle, str):
            line += f", oracle `{_s(oracle, 80)}`"
        if isinstance(replay.get("successes"), int) and isinstance(replay.get("attempts"), int):
            line += f", replayed {replay['successes']}/{replay['attempts']}"
        details.append(line + ".")
    data["technical_details"] = "\n".join(f"- {d}" for d in details)
    data["match"]["files"] = files[:MAX_LOCATIONS]

    wreq, wresp = _d(result.get("webRequest")), _d(result.get("webResponse"))
    if wreq:
        data["evidence"].append({"title": title, "request": _http_request(wreq),
                                 "response": _http_response(wresp) if wresp else ""})
        if not data["targets"] and re.match(r"^https?://", str(wreq.get("target", "")), re.IGNORECASE):
            data["targets"].append(proposals.target_from_address(_s(wreq["target"], 2048)))
    elif wresp:
        warnings.append(f"{title[:80]}: a webResponse without a webRequest was left out.")
    return {"kind": "finding", "verdict": verdict, "source": tool, "data": data}


def _parse_sarif(doc: dict, warnings: list) -> list[dict]:
    if doc.get("version") != "2.1.0":
        warnings.append(f"SARIF version {str(doc.get('version'))[:20]!r} is not 2.1.0; read as 2.1.0.")
    items: list[dict] = []
    counters = {"pass": 0, "absent": 0, "suppressed": 0, "refuted": 0}
    total = 0
    for run in map(_d, _l(doc.get("runs"), 100)):
        tool_obj = _d(run.get("tool"))
        driver = _d(tool_obj.get("driver"))
        rule_list = _l(driver.get("rules"))
        rules = {r["id"]: r for r in map(_d, rule_list) if isinstance(r.get("id"), str)}
        for ext in map(_d, _l(tool_obj.get("extensions"), 50)):
            for r in map(_d, _l(ext.get("rules"))):
                if isinstance(r.get("id"), str):
                    rules.setdefault(r["id"], r)
        invocation = _d((_l(run.get("invocations"), 1) or [{}])[0])
        run_id = _s(_d(run.get("automationDetails")).get("id"), 100) or \
            _s(_d(invocation.get("properties")).get("engagement_id"), 100)
        tool = {"tool": _s(driver.get("name"), 100) or "SARIF",
                "version": _s(driver.get("version") or driver.get("semanticVersion"), 50), "run_id": run_id}
        for result in map(_d, _l(run.get("results"), MAX_RESULTS + 1)):
            total += 1
            if total > MAX_RESULTS:
                warnings.append(f"Only the first {MAX_RESULTS} results were read.")
                break
            item = _sarif_result(run, result, rules, rule_list, tool, warnings, counters)
            if item is not None:
                items.append(item)
    for key, text in (("pass", "passing / not applicable result(s)"), ("absent", "result(s) absent from the scan "
                      "(baseline state 'absent'; absence never marks a finding fixed)"),
                      ("suppressed", "suppressed result(s)"), ("refuted", "result(s) refuted by the tool's verifier")):
        if counters[key]:
            warnings.append(f"Skipped {counters[key]} {text}.")
    return items


# --------------------------------------------------------------------- ptai --

def capsule_integrity(capsule: dict) -> str:
    """pentest-ai's drift check: SHA-256 of the canonical capsule without its integrity field."""
    body = {k: v for k, v in capsule.items() if k != "integrity_sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
                          .encode("utf-8")).hexdigest()


def _parse_capsule(cap: dict, raw: bytes | None, warnings: list) -> dict | None:
    finding, receipt = _d(cap.get("finding")), _d(cap.get("receipt"))
    if cap.get("capsule_schema_version") != 1:
        warnings.append(f"Capsule schema version {str(cap.get('capsule_schema_version'))[:10]!r} is not 1; read "
                        "with the version 1 fields.")
    title = _s(finding.get("title"), 300) or _s(finding.get("bug_class"), 300) or "ptai finding"
    verdict = receipt.get("verdict") if isinstance(receipt.get("verdict"), str) else ""
    if verdict == "refuted":
        warnings.append(f"{title[:80]}: refuted by ptai's verifier, skipped.")
        return None
    verdict = verdict if verdict in ("verified", "candidate") else ""
    integrity = cap.get("integrity_sha256")
    integrity_ok = isinstance(integrity, str) and integrity == capsule_integrity(cap)
    if isinstance(integrity, str) and not integrity_ok:
        warnings.append(f"{title[:80]}: the capsule's integrity SHA-256 does not match its content (edited after "
                        "ptai built it)" + ("; verdict lowered to candidate." if verdict == "verified" else "."))
        if verdict == "verified":
            verdict = "candidate"
    severity = _s(finding.get("severity"), 20).lower()
    severity = proposals.SEVERITY_ALIASES.get(severity, severity)
    if severity not in ("critical", "high", "medium", "low", "info"):
        warnings.append(f"{title[:80]}: no usable severity in the capsule, set to info; adjust it when you accept.")
        severity = "info"
    bug_class = _s(finding.get("bug_class"), 100)
    target_url = _s(finding.get("target"), 2048)
    recipe = _d(finding.get("verification_recipe"))
    evidence = _d(receipt.get("evidence"))
    replay = _d(receipt.get("replay"))
    oracle = _s(receipt.get("oracle_kind"), 80)

    details = []
    if bug_class:
        details.append(f"Bug class: `{bug_class}`")
    if target_url:
        details.append(f"Target: {target_url}")
    line = f"Verification: {verdict or 'no verdict'}"
    if oracle:
        line += f" by the `{oracle}` oracle"
    if recipe.get("oracle"):
        line += f" (recipe `{_s(recipe.get('oracle'), 80)}`" + (
            f" on parameter `{_s(recipe.get('param'), 80)}`" if recipe.get("param") else "") + ")"
    if isinstance(replay.get("successes"), int) and isinstance(replay.get("attempts"), int):
        line += f", replayed {replay['successes']}/{replay['attempts']}"
    details.append(line + ".")
    if _s(evidence.get("diff"), 2000):
        details.append(f"Oracle result: {_s(evidence.get('diff'), 2000)}")
    if _s(evidence.get("canary"), 300):
        details.append(f"Canary: `{_s(evidence.get('canary'), 300)}`")
    for artifact in _l(evidence.get("artifacts"), 20):
        if _s(artifact, 300):
            details.append(f"Artifact: {_s(artifact, 300)}")
    if isinstance(integrity, str):
        details.append(f"Capsule integrity SHA-256: `{_s(integrity, 64)}` "
                       f"({'matches' if integrity_ok else 'does NOT match'} the content)")
    technical = "\n".join(f"- {d}" for d in details)
    excerpt = _t(finding.get("evidence"), 4000)
    if excerpt:
        technical += "\n\nResponse excerpt:\n\n" + _fence(excerpt)
    poc = ""
    if _t(replay.get("curl"), 20_000):
        poc = "Replay request:\n\n" + _fence(_t(replay.get("curl"), 20_000), "bash")
    poc = (poc + "\n\n" if poc else "") + "Re-check the proof with `ptai replay` on the attached capsule."

    data: dict[str, Any] = {
        "title": title, "severity": severity, "cwe": _cwe_from(finding.get("cwe_id"), finding.get("cwe")) or
        BUG_CLASS_CWE.get(bug_class.lower(), ""),
        "description": f"Reported by pentest-ai (ptai); verdict of its verifier: {verdict or 'none'}.",
        "technical_details": technical, "poc": poc,
        "targets": [proposals.target_from_address(target_url)] if target_url else [],
        "evidence": [], "code_evidence": [], "files": [], "match": {"rule_id": bug_class}}
    request = _t(evidence.get("request"), 5_000_000)
    if request:
        data["evidence"].append({"title": f"{title} (ptai {oracle or 'verifier'})"[:300], "request": request,
                                 "response": _t(evidence.get("response"), 5_000_000)})
    blob = raw if raw is not None else json.dumps(cap, ensure_ascii=False, indent=2).encode("utf-8")
    if len(blob) <= 25 * 1024 * 1024:
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", _s(finding.get("id"), 60)) or "finding"
        data["files"].append({"filename": f"ptai-capsule-{name}.json", "description": "ptai proof capsule",
                              "data_base64": base64.b64encode(blob).decode("ascii")})
    source = {"tool": "ptai", "version": _s(cap.get("ptai_version"), 50), "run_id": _s(finding.get("id"), 100)}
    return {"kind": "finding", "verdict": verdict, "source": source, "data": data}


def _parse_ptai(doc: Any, raw: bytes, warnings: list) -> list[dict]:
    if isinstance(doc, dict) and "capsule_schema_version" in doc:
        capsules, single = [doc], True
    else:
        capsules, single = (doc.get("capsules") if isinstance(doc, dict) else doc), False
    items = []
    for i, cap in enumerate(_l(capsules, MAX_RESULTS)):
        if not isinstance(cap, dict) or not isinstance(cap.get("finding"), dict):
            warnings.append(f"Capsule #{i + 1}: not a ptai proof capsule, skipped.")
            continue
        item = _parse_capsule(cap, raw if single else None, warnings)
        if item:
            items.append(item)
    return items


# --------------------------------------------------------------------- main --

def parse(data: bytes, fmt: str | None = None) -> dict:
    """File contents -> {"format", "items": raw proposals, "warnings"}. Raises :class:`ImportError_`."""
    if fmt is not None and fmt not in FORMATS:
        raise ImportError_(f"Unknown format; choose one of: {', '.join(FORMATS)}.")
    doc = load_json(data)
    detected = detect(doc)
    if detected is None:
        raise ImportError_("Unrecognised file: expected SARIF 2.1.0, a ptai proof capsule or ptreport proposal JSON.")
    if fmt is not None and fmt != detected:
        raise ImportError_(f"The file looks like {LABELS[detected]}, not {LABELS[fmt]}.")
    warnings: list[str] = []
    if detected == "sarif":
        items = _parse_sarif(doc, warnings)
    elif detected == "ptai":
        items = _parse_ptai(doc, bytes(data), warnings)
    else:
        try:
            items = proposals.normalise_items(doc)
        except proposals.ProposalError as exc:
            raise ImportError_("; ".join(exc.errors.values())) from None
        if len(items) > MAX_RESULTS:
            warnings.append(f"Only the first {MAX_RESULTS} proposals were read.")
            items = items[:MAX_RESULTS]
    unique, seen = [], set()
    for item in items:
        key = _dedupe_key(item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    if len(unique) < len(items):
        warnings.append(f"{len(items) - len(unique)} identical result(s) were imported once.")
    return {"format": detected, "items": unique, "warnings": warnings}


def prepare(conn: sqlite3.Connection, report_id: int, parsed: dict) -> dict:
    """Validate each proposal on its own: invalid ones are dropped with a warning, the rest can be submitted.

    Also tells, per valid proposal, what it will become (new finding, possible duplicate, retest result)."""
    report = repo.get_report(conn, report_id)
    findings = repo.list_findings(conn, report_id)
    retest = bool(report.get("retest_of")) and parsed["format"] in ("sarif", "ptai")
    valid, plan, warnings = [], [], list(parsed["warnings"])
    for i, item in enumerate(parsed["items"], 1):
        record, errors = proposals.validate_proposal(conn, report_id, item)
        if errors:
            title = _s(_d(_d(item).get("data")).get("title") or _d(item).get("title"), 80) or f"item #{i}"
            warnings.append(f"Skipped \"{title}\": " + "; ".join(f"{k}: {v}" for k, v in list(errors.items())[:3]))
            continue
        valid.append(item)
        action, other = record["kind"], None
        if record["kind"] == "finding":
            match = proposals.retest_match(record["data"], findings) if retest else None
            dup = None if match else proposals.duplicate_of(record["data"], findings)
            action, other = ("retest", match) if match else ("finding", dup[0] if dup else None)
        plan.append({"record": record, "action": action, "finding": other})
    return {"format": parsed["format"], "items": valid, "plan": plan, "warnings": warnings,
            "retest_matching": retest}


def submit(conn: sqlite3.Connection, report_id: int, prepared: dict) -> list[int]:
    if not prepared["items"]:
        return []
    return proposals.submit(conn, report_id, prepared["items"], retest_matching=prepared["retest_matching"])
