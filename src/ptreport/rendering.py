"""Safe rendering helpers for user-supplied text.

Free-text fields are plain text with one extension: fenced code blocks
(```lang ... ```) and inline `code`. Everything is HTML-escaped first, so
payloads such as ``<script>`` in a PoC are always shown, never executed.
"""

from __future__ import annotations

import re
from typing import Any

from markupsafe import Markup, escape

from ptreport.cvss_service import rating_for_score, vector_strip
from ptreport.cwe import cwe_name, cwe_url
from ptreport.validation import file_kind

_FENCE_OPEN = re.compile(r"^(`{3,})\s*([A-Za-z0-9_+.#-]*)\s*$")
_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_URL = re.compile(r"^https?://[^\s<>\"']+$", re.IGNORECASE)


def parse_blocks(text: str) -> list[tuple[str, str, str]]:
    """Split text into ("text", "", body) and ("code", lang, body) blocks."""
    blocks: list[tuple[str, str, str]] = []
    buf: list[str] = []
    lines = (text or "").split("\n")
    i = 0
    while i < len(lines):
        m = _FENCE_OPEN.match(lines[i])
        if m:
            fence, lang = m.group(1), m.group(2)
            j = i + 1
            while j < len(lines) and not (
                lines[j].strip().startswith(fence) and set(lines[j].strip()) == {"`"}
            ):
                j += 1
            if j < len(lines):  # properly closed fence
                if buf:
                    blocks.append(("text", "", "\n".join(buf)))
                    buf = []
                blocks.append(("code", lang, "\n".join(lines[i + 1:j])))
                i = j + 1
                continue
        buf.append(lines[i])
        i += 1
    if buf:
        blocks.append(("text", "", "\n".join(buf)))
    return blocks


_HEADING = re.compile(r"^(#{1,3})\s+(\S.*)$")
_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
_TABLE_SEP = re.compile(r"^\s*\|(\s*:?-{3,}:?\s*\|)+\s*$")


def _pad(cells: list[str], width: int, fill: str = "") -> list[str]:
    return (cells + [fill] * width)[:width]


def _table_cells(line: str) -> list[str]:
    inner = line.strip()[1:-1]
    cells = re.split(r"(?<!\\)\|", inner)
    return [c.strip().replace("\\|", "|") for c in cells]
_BULLET = re.compile(r"^\s*[-*•]\s+(\S.*)$")
_INLINE = re.compile(r"`([^`\n]+)`|\*\*([^*\n]+)\*\*|(https?://[^\s<>\"'`]+)")
_URL_TRAIL = ".,;:)"


def text_blocks(body: str) -> list[tuple[str, object]]:
    """Structure of a plain-text block: ("heading", (level, text)), ("list", [items]), ("para", [lines]),
    ("table", {"header": [...], "rows": [[...]], "align": [...]}) for Markdown pipe tables.

    "# x"/"## x" is a level-2 heading (subsection), "### x" a level-3 heading; "- x" lines form a list.
    """
    blocks: list[tuple[str, object]] = []
    para: list[str] = []
    items: list[str] = []

    def flush() -> None:
        nonlocal para, items
        if para:
            blocks.append(("para", para))
        if items:
            blocks.append(("list", items))
        para, items = [], []

    gap = False  # a blank line after list items: the list continues only if another item follows
    lines = body.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        # a Markdown pipe table: header row, separator row (|---|:--:|), body rows
        if _TABLE_ROW.match(line) and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            flush()
            gap = False
            header = _table_cells(line)
            aligns = [("center" if c.startswith(":") and c.endswith(":") else "right" if c.endswith(":")
                       else "left") for c in _table_cells(lines[i + 1])]
            rows = []
            i += 2
            while i < len(lines) and _TABLE_ROW.match(lines[i]):
                rows.append(_table_cells(lines[i]))
                i += 1
            width = max([len(header)] + [len(r) for r in rows])
            blocks.append(("table", {"header": _pad(header, width), "rows": [_pad(r, width) for r in rows],
                                     "align": _pad(aligns, width, "left")}))
            continue
        i += 1
        heading = _HEADING.match(line)
        bullet = _BULLET.match(line)
        if not line.strip():
            if para:
                blocks.append(("para", para))
                para = []
            gap = bool(items)
            continue
        if gap and not bullet:
            flush()
        gap = False
        if heading:
            flush()
            blocks.append(("heading", (3 if len(heading.group(1)) == 3 else 2, heading.group(2).strip())))
        elif bullet:
            if para:
                blocks.append(("para", para))
                para = []
            items.append(bullet.group(1))
        elif items and line[:1].isspace():
            items[-1] += " " + line.strip()  # wrapped list item
        else:
            if items:
                blocks.append(("list", items))
                items = []
            para.append(line)
    flush()
    return blocks


def inline_tokens(text: str) -> list[tuple[str, str]]:
    """Split a line into ("text"|"code"|"bold"|"url", value) tokens."""
    out: list[tuple[str, str]] = []
    pos = 0
    for m in _INLINE.finditer(text):
        if m.start() > pos:
            out.append(("text", text[pos:m.start()]))
        if m.group(1) is not None:
            out.append(("code", m.group(1)))
        elif m.group(2) is not None:
            out.append(("bold", m.group(2)))
        else:
            url, trail = m.group(3), ""
            while url and url[-1] in _URL_TRAIL:
                url, trail = url[:-1], url[-1] + trail
            out.append(("url", url))
            if trail:
                out.append(("text", trail))
        pos = m.end()
    if pos < len(text):
        out.append(("text", text[pos:]))
    return out


def _inline_html(text: str) -> str:
    parts = []
    for kind, value in inline_tokens(text):
        if kind == "code":
            parts.append(f"<code>{escape(value)}</code>")
        elif kind == "bold":
            parts.append(f"<strong>{escape(value)}</strong>")
        elif kind == "url" and _URL.match(value):
            parts.append(f'<a href="{escape(value)}" rel="noopener noreferrer">{escape(value)}</a>')
        else:
            parts.append(str(escape(value)))
    return "".join(parts)


def _render_text(body: str) -> Markup:
    out = []
    for kind, data in text_blocks(body):
        if kind == "heading":
            level, title = data
            tag = "h3" if level == 2 else "h4"
            out.append(f'<{tag} class="rt-h">{_inline_html(title)}</{tag}>')
        elif kind == "list":
            out.append('<ul class="rt-list">' + "".join(f"<li>{_inline_html(i)}</li>" for i in data) + "</ul>")
        elif kind == "table":
            def cell(tag: str, text: str, align: str) -> str:
                cls = f' class="al-{align}"' if align != "left" else ""
                return f"<{tag}{cls}>{_inline_html(text)}</{tag}>"
            head = "".join(cell("th", c, a) for c, a in zip(data["header"], data["align"], strict=True))
            body = "".join("<tr>" + "".join(cell("td", c, a) for c, a in zip(row, data["align"], strict=True)) + "</tr>"
                           for row in data["rows"])
            out.append(f'<div class="rt-table-wrap"><table class="tbl rt-table"><thead><tr>{head}</tr></thead>'
                       f"<tbody>{body}</tbody></table></div>")
        else:
            out.append('<p class="rt">' + "<br>".join(_inline_html(line) for line in data) + "</p>")
    return Markup("\n".join(out))  # noqa: S704 - every fragment escaped above


def richtext(text: str) -> Markup:
    parts = []
    for kind, lang, body in parse_blocks(text):
        if kind == "code":
            cls = f' class="lang-{escape(lang)}"' if lang else ""
            parts.append(f"<pre><code{cls}>{escape(body)}</code></pre>")
        else:
            parts.append(str(_render_text(body)))
    return Markup("\n".join(parts))  # noqa: S704 - every fragment escaped above


def reference_list(text: str) -> Markup:
    items = []
    for line in (text or "").split("\n"):
        line = line.strip()
        if not line:
            continue
        if _URL.match(line):
            items.append(
                f'<li><a href="{escape(line)}" rel="noopener noreferrer">{escape(line)}</a></li>'
            )
        else:
            items.append(f"<li>{escape(line)}</li>")
    html = "<ul class=\"refs\">" + "".join(items) + "</ul>" if items else ""
    return Markup(html)  # noqa: S704 - every item escaped above


SEVERITY_LABELS = {
    "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"},
    "pl": {"critical": "Krytyczna", "high": "Wysoka", "medium": "Średnia", "low": "Niska", "info": "Informacyjna"},
}
STATUS_LABELS = {
    "en": {"open": "Open", "fixed": "Fixed", "risk_accepted": "Risk accepted", "false_positive": "False positive"},
    "pl": {"open": "Otwarta", "fixed": "Naprawiona", "risk_accepted": "Ryzyko zaakceptowane", "false_positive": "Fałszywie pozytywna"},
}
TARGET_KIND_LABELS = {
    "en": {"web": "Web application", "api": "API", "host": "Host", "network": "Network range",
           "mobile": "Mobile application", "cloud": "Cloud", "wireless": "Wireless", "other": "Other"},
    "pl": {"web": "Aplikacja webowa", "api": "API", "host": "Host", "network": "Zakres sieci",
           "mobile": "Aplikacja mobilna", "cloud": "Chmura", "wireless": "Sieć bezprzewodowa", "other": "Inne"},
}

REPORT_LABELS = {
    "en": {
        "report": "Penetration Test Report", "client": "Client", "assessor": "Assessor(s)",
        "period": "Testing period", "toc": "Contents", "executive_summary": "Executive summary",
        "scope": "Scope", "targets": "Targets", "target": "Target", "type": "Type",
        "address": "Address", "description": "Description", "methodology": "Methodology",
        "summary": "Summary of findings", "findings": "Findings", "id": "ID", "title": "Title",
        "severity": "Severity", "cvss": "CVSS", "vector": "Vector", "cwe": "CWE",
        "status": "Status", "affected": "Affected targets", "impact": "Impact",
        "technical_details": "Technical details", "poc": "Proof of Concept",
        "evidence": "HTTP evidence", "request": "Request", "response": "Response",
        "remediation": "Remediation", "references": "References", "count": "Count",
        "total": "Total", "no_findings": "No findings were identified.", "generated": "Generated",
        "confidence": "Confidence", "figure": "Figure", "screenshots": "Screenshots",
        "prepared_by": "Prepared by", "contact": "Contact", "version": "Version", "report_date": "Report date",
        "version_history": "Report version history", "date": "Date",
        "author": "Author", "finding_history": "History", "status_change": "Status",
        "table_of_findings": "Table of findings", "results_summary": "Results summary", "no": "No.",
        "ungrouped": "Informative note", "mitigation": "Mitigation", "fingerprint": "Document fingerprint (SHA-256)",
        "chart_severity": "Findings by severity", "chart_targets": "Findings per target",
        "chart_matrix": "CVSS score versus severity", "cvss_score": "CVSS score", "number_of_findings": "Findings",
        "no_cvss": "No CVSS", "retest_summary": "Retest summary", "retest": "Retest",
        "retest_result": "Retest result", "retest_date": "Retest date", "retest_notes": "Retest notes",
        "original_report": "Original report", "original_date": "original report dated",
        "attached_files": "Attached files", "file_name": "File", "file_size": "Size", "sha256": "SHA-256",
    },
    "pl": {
        "report": "Raport z testów penetracyjnych", "client": "Klient", "assessor": "Testujący",
        "period": "Okres testów", "toc": "Spis treści", "executive_summary": "Podsumowanie dla kierownictwa",
        "scope": "Zakres", "targets": "Cele testów", "target": "Cel", "type": "Typ",
        "address": "Adres", "description": "Opis", "methodology": "Metodyka",
        "summary": "Podsumowanie podatności", "findings": "Podatności", "id": "ID", "title": "Tytuł",
        "severity": "Ryzyko", "cvss": "CVSS", "vector": "Wektor", "cwe": "CWE",
        "status": "Status", "affected": "Podatne cele", "impact": "Wpływ",
        "technical_details": "Szczegóły techniczne", "poc": "Proof of Concept",
        "evidence": "Dowody HTTP", "request": "Żądanie", "response": "Odpowiedź",
        "remediation": "Rekomendacje", "references": "Referencje", "count": "Liczba",
        "total": "Razem", "no_findings": "Nie zidentyfikowano podatności.", "generated": "Wygenerowano",
        "confidence": "Pewność", "figure": "Rysunek", "screenshots": "Zrzuty ekranu",
        "prepared_by": "Wykonawca", "contact": "Kontakt", "version": "Wersja", "report_date": "Data raportu",
        "version_history": "Historia wersji raportu", "date": "Data",
        "author": "Autor", "finding_history": "Historia", "status_change": "Status",
        "table_of_findings": "Zestawienie podatności", "results_summary": "Podsumowanie wyników", "no": "Lp.",
        "ungrouped": "Uwagi informacyjne", "mitigation": "Zalecenia", "fingerprint": "Odcisk dokumentu (SHA-256)",
        "chart_severity": "Podatności według ryzyka", "chart_targets": "Podatności według celu",
        "chart_matrix": "Wynik CVSS a ryzyko", "cvss_score": "Wynik CVSS", "number_of_findings": "Liczba",
        "no_cvss": "Brak CVSS", "retest_summary": "Podsumowanie retestu", "retest": "Retest",
        "retest_result": "Wynik retestu", "retest_date": "Data retestu", "retest_notes": "Uwagi z retestu",
        "original_report": "Raport pierwotny", "original_date": "raport pierwotny z dnia",
        "attached_files": "Załączone pliki", "file_name": "Plik", "file_size": "Rozmiar", "sha256": "SHA-256",
    },
}


CONFIDENCE_LABELS = {
    "en": {"certain": "Certain", "probable": "Probable", "unknown": "Unknown"},
    "pl": {"certain": "Pewna", "probable": "Prawdopodobna", "unknown": "Nieznana"},
}

RETEST_LABELS = {
    "en": {"fixed": "Fixed", "partially_fixed": "Partially fixed", "not_fixed": "Not fixed",
           "not_tested": "Not tested", "": "Not retested"},
    "pl": {"fixed": "Usunięta", "partially_fixed": "Usunięta częściowo", "not_fixed": "Nieusunięta",
           "not_tested": "Nie testowano", "": "Nie zweryfikowano"},
}

CVSS_RATING_LABELS = {
    "en": {"none": "None", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"},
    "pl": {"none": "Brak", "low": "Niska", "medium": "Średnia", "high": "Wysoka", "critical": "Krytyczna"},
}


def cvss_rating_label(finding: dict, lang: str = "en") -> str:
    rating = rating_for_score(finding.get("cvss_score"), finding.get("cvss_version", ""))
    return CVSS_RATING_LABELS.get(lang, CVSS_RATING_LABELS["en"]).get(rating, "")


def labels_for(lang: str, overrides: dict | None = None) -> dict:
    """Report wording for a language with the user's overrides from Settings applied.

    Override keys: "sev.<severity>", "status.<status>", "conf.<confidence>", "retest.<result>", or any
    report label key."""
    lang = lang if lang in REPORT_LABELS else "en"
    out = {
        "L": dict(REPORT_LABELS[lang]),
        "sev": dict(SEVERITY_LABELS[lang]),
        "status": dict(STATUS_LABELS[lang]),
        "conf": dict(CONFIDENCE_LABELS[lang]),
        "retest": dict(RETEST_LABELS[lang]),
    }
    for key, value in (overrides or {}).items():
        if not value:
            continue
        group, _, name = key.partition(".")
        if name and group in ("sev", "status", "conf", "retest") and name in out[group]:
            out[group][name] = value
        elif key in out["L"]:
            out["L"][key] = value
    return out


def history_text(entry: dict, lang: str = "en", status_labels: dict | None = None) -> str:
    """Human text of a finding history entry; status entries are described in the report's language."""
    if entry.get("kind") == "status" and entry.get("status_to"):
        labels = status_labels or STATUS_LABELS.get(lang, STATUS_LABELS["en"])
        label = REPORT_LABELS.get(lang, REPORT_LABELS["en"])["status_change"]
        old = labels.get(entry.get("status_from"), entry.get("status_from") or "")
        new = labels.get(entry["status_to"], entry["status_to"])
        text = f"{label}: {old} → {new}" if old else f"{label}: {new}"
        return f"{text}. {entry['description']}" if entry.get("description") else text
    return entry.get("description", "")


def cvss_rating_key(finding: dict) -> str:
    return rating_for_score(finding.get("cvss_score"), finding.get("cvss_version", ""))


def human_size(size: Any) -> str:
    """1536 -> '1.5 KB' (binary units, as file managers show them)."""
    try:
        value = float(size)
    except (TypeError, ValueError):
        return ""
    if value < 1024:
        return f"{int(value)} B"
    for unit in ("KB", "MB", "GB"):
        value /= 1024
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
    return ""


def init_app(app) -> None:
    app.jinja_env.filters["filesize"] = human_size
    app.jinja_env.filters["file_kind"] = file_kind
    app.jinja_env.filters["cvss_rating_label"] = cvss_rating_label
    app.jinja_env.filters["cvss_rating_key"] = cvss_rating_key
    app.jinja_env.filters["cvss_rating_name"] = (
        lambda r, lang="en": CVSS_RATING_LABELS.get(lang, CVSS_RATING_LABELS["en"]).get(r, r))
    app.jinja_env.filters["richtext"] = richtext
    app.jinja_env.filters["reference_list"] = reference_list
    app.jinja_env.filters["cwe_name"] = cwe_name
    app.jinja_env.filters["cwe_url"] = cwe_url
    app.jinja_env.filters["vector_strip"] = vector_strip
    app.jinja_env.globals["SEVERITY_LABELS"] = SEVERITY_LABELS
    app.jinja_env.globals["STATUS_LABELS"] = STATUS_LABELS
    app.jinja_env.globals["RETEST_LABELS"] = RETEST_LABELS
    app.jinja_env.globals["CONFIDENCE_LABELS"] = CONFIDENCE_LABELS
    app.jinja_env.globals["TARGET_KIND_LABELS"] = TARGET_KIND_LABELS
