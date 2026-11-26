"""Report assembly plus HTML / Markdown / JSON export and JSON import."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import json
import re
import sqlite3
import zipfile
from datetime import datetime, timezone
from typing import Any

from flask import current_app, render_template, url_for

from ptreport import __version__, repo
from ptreport.cwe import cwe_name, cwe_url
from ptreport.db import transaction
from ptreport.cvss_service import rating_for_score
from ptreport.rendering import (
    CODE_LANGUAGE_LABELS,
    human_size,
    history_text,
    labels_for,
    cvss_rating_label,
    REPORT_LABELS,
    TARGET_KIND_LABELS,
)
from ptreport.validation import (
    FILE_MAX_PER_FINDING,
    IMAGE_MAX_PER_FINDING,
    SEVERITIES,
    check_file_quota,
    is_sha256,
    is_timestamp,
    validate_attachment,
    validate_file,
    validate_code_evidence,
    validate_cwe_note,
    validate_history_entry,
    validate_note,
    validate_report_version,
    validate_section,
    validate_evidence,
    validate_finding,
    validate_origin,
    validate_report,
    validate_target,
)

EXPORT_FORMAT = "ptreport"
EXPORT_VERSION = 1


def build_context(conn: sqlite3.Connection, report_id: int, inline_images: bool = False) -> dict | None:
    """Everything a report view or export needs.

    Screenshots are numbered as figures across the report. With ``inline_images`` each one carries a
    ``data:`` URI and its raw bytes (exports); otherwise it points at the app's attachment URL (preview, UI).
    """
    report = repo.get_report(conn, report_id)
    if report is None:
        return None
    targets = repo.list_targets(conn, report_id)
    findings = repo.list_findings(conn, report_id)
    settings = repo.get_settings(conn)
    all_attachments = [a for f in findings for a in f["attachments"]]
    blobs = repo.attachment_data(conn, [a["id"] for a in all_attachments]) if inline_images else {}
    for figure, att in enumerate(all_attachments, start=1):
        att["figure"] = figure
        if inline_images:
            mime, data = blobs[att["id"]]
            att["data"] = data
            att["src"] = f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
        else:
            att["src"] = url_for("web.attachment_file", attachment_id=att["id"], v=att["sha256"][:12])
    lang = report["language"] if report["language"] in REPORT_LABELS else "en"
    labels = labels_for(lang, repo.get_label_overrides(conn).get(lang))
    L = labels["L"]
    for f in findings:
        f["display_id"] = repo.finding_display_id(report, f, settings)
        for h in f["history"]:
            h["text"] = history_text(h, lang, labels["status"])
        f["history_has_author"] = any(h["author"] for h in f["history"])
    versions = repo.list_report_versions(conn, report_id)
    used = {f["cvss_version"] for f in findings if f["cvss_version"]}
    cvss_versions = [v for v in ("4.0", "3.1", "3.0", "2.0") if v in used]
    brand = repo.get_brand(conn)
    if brand["logo"]:
        logo = brand["logo"]
        logo["src"] = f"data:{logo['mime']};base64,{base64.b64encode(logo['data']).decode('ascii')}"

    default_titles = {
        "executive_summary": L["executive_summary"], "scope": L["scope"], "methodology": L["methodology"],
        "summary": L["summary"], "findings_table": L["table_of_findings"], "charts": L["results_summary"],
        "findings": L["findings"], "retest_summary": L["retest_summary"], "text": "",
    }
    all_sections = repo.list_sections(conn, report_id)
    sections = []
    for sec in all_sections:
        if sec["enabled"]:
            sections.append({**sec, "title": sec["title"] or default_titles.get(sec["kind"], "")})

    groups = []
    if report["group_by_cwe"]:
        for g in repo.finding_groups(findings, repo.list_cwe_notes(conn, report_id)):
            default = (f"{g['cwe']}: {cwe_name(g['cwe'])}" if cwe_name(g["cwe"]) else g["cwe"]) if g["cwe"] \
                else L["ungrouped"]
            library = repo.cwe_texts(conn, g["cwe"]) if g["cwe"] else {"description": "", "mitigation": ""}
            groups.append({**g, "title": g["title"] or default, "title_custom": bool(g["title"]),
                           "own_description": g["description"], "own_mitigation": g["mitigation"],
                           "description": g["description"] or library["description"],
                           "mitigation": g["mitigation"] or library["mitigation"]})

    per_target = []
    for t in targets:
        tcounts = {s: 0 for s in SEVERITIES}
        for f in findings:
            if any(x["id"] == t["id"] for x in f["targets"]):
                tcounts[f["severity"]] += 1
        per_target.append({"name": t["name"], "counts": tcounts, "total": sum(tcounts.values())})
    ratings = ("none", "low", "medium", "high", "critical")
    matrix = {s: {r: 0 for r in (*ratings, "")} for s in SEVERITIES}
    for f in findings:
        matrix[f["severity"]][rating_for_score(f["cvss_score"], f["cvss_version"])] += 1

    original = repo.get_report(conn, report["retest_of"]) if report.get("retest_of") else None
    retest_counts = {k: 0 for k in labels["retest"]}
    for f in findings:
        retest_counts[f["retest_result"] if f["retest_result"] in retest_counts else ""] += 1

    ctx = {
        "original_report": original,
        "retest_labels": labels["retest"],
        "retest_counts": retest_counts,
        "cvss_header": "CVSS " + " / ".join(cvss_versions) if cvss_versions else "CVSS",
        "brand": brand,
        "sections": sections,
        "all_sections": all_sections,
        "groups": groups,
        "per_target": per_target,
        "matrix": matrix,
        "ratings": ratings,
        "sev_labels": labels["sev"],
        "status_labels": labels["status"],
        "conf_labels": labels["conf"],
        "code_lang_labels": CODE_LANGUAGE_LABELS[lang],
        "fingerprint": "",
        "cwe_notes": [{**n, "title_override": n["title"]} for n in repo.list_cwe_notes(conn, report_id).values()],
        "report": report,
        "all_versions": versions,
        "versions": versions if report["show_version_history"] else [],
        "versions_have_author": any(v["author"] for v in versions),
        "show_finding_history": bool(report["show_finding_history"]),
        "targets": targets,
        "findings": findings,
        "counts": repo.severity_counts(findings),
        "severities": SEVERITIES,
        "L": L,
        "lang": lang,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    if inline_images:
        # fingerprint of the report's content (what the JSON export holds), shown in the PDF
        content = to_json(ctx)
        content.pop("exported_with", None)
        ctx["fingerprint"] = hashlib.sha256(
            json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    return ctx


DOWNLOAD_FORMATS = {"html": ("text/html", "html"), "md": ("text/markdown", "md"),
                    "json": ("application/json", "json"), "pdf": ("application/pdf", "pdf"),
                    "tex": ("application/zip", "zip")}


def render_download(conn: sqlite3.Connection, report_id: int, fmt: str) -> tuple[bytes, str, str] | None:
    """The file behind the web "Export" buttons and ``ptreport export``: (body, mimetype, file name).

    Returns None when the report does not exist. Needs an app context (templates, LaTeX template from the DB);
    PDF/TeX may raise :class:`ptreport.latex.LatexError`."""
    from ptreport import latex

    ctx = build_context(conn, report_id, inline_images=True)
    if ctx is None:
        return None
    mimetype, ext = DOWNLOAD_FORMATS[fmt]
    if fmt == "html":
        css = current_app.open_resource("static/report.css").read().decode("utf-8")
        body: bytes = render_template("export/report.html", inline_css=css, preview=False, **ctx).encode("utf-8")
    elif fmt == "md":
        body = to_markdown(ctx).encode("utf-8")
    elif fmt == "json":
        add_originals(conn, ctx)  # backups keep the untouched originals of edited screenshots
        file_ids = [x["id"] for f in ctx["findings"] for x in f["files"]]
        doc = to_json(ctx, file_blobs=repo.file_data(conn, file_ids))
        # working notes travel with the backup, but are not report content (not in the fingerprint)
        doc["notes"] = [{f: n[f] for f in repo.NOTE_FIELDS} for n in reversed(repo.list_notes(conn, report_id))]
        body = json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
    else:
        source, files = latex.render(ctx, repo.get_latex_template(conn))
        if fmt == "pdf":
            body = latex.compile_pdf(source, files, volatile=ctx["generated_at"])
        else:
            body = tex_zip(source, files)
    return body, mimetype, safe_filename(ctx["report"]["title"], ext)


def tex_zip(source: str, files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.tex", source)
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("README.txt", "Compile with: tectonic report.tex  (or: xelatex report.tex, twice)\n")
    return buffer.getvalue()


def safe_filename(title: str, ext: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", title).strip("._-")[:80] or "report"
    return f"{stem}.{ext}"


# ---------------------------------------------------------------- markdown --

def _fence(body: str, lang: str = "") -> str:
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{body}\n{fence}"


MD_CODE_LANG = {"c": "c", "cpp": "cpp", "asm": "asm", "pseudo": "c", "java": "java", "python": "python"}


def _md_escape_inline(text: str) -> str:
    return re.sub(r"([\\`*_\[\]<>|#])", r"\\\1", text)


def _md_body(text: str) -> str:
    """Report text inside a "## n Section": its own "## Heading" lines move one level down."""
    return re.sub(r"(?m)^(#{1,3})(\s)", r"#\1\2", text or "")


def to_markdown(ctx: dict) -> str:
    r, L, lang = ctx["report"], ctx["L"], ctx["lang"]
    sev, status, kinds = ctx["sev_labels"], ctx["status_labels"], TARGET_KIND_LABELS[lang]
    out: list[str] = [f"# {_md_escape_inline(r['title'])}", ""]
    meta = [
        (L["client"], r["client_name"]),
        (L["assessor"], r["assessor"]),
        (L["period"], " – ".join(d for d in (r["start_date"], r["end_date"]) if d)),
        (L["prepared_by"], r["vendor_name"]),
        (L["contact"], r["vendor_contact"]),
        (L["version"], r["report_version"]),
        (L["report_date"], r["report_date"] or ""),
        ("", r["classification"]),
    ]
    for label, value in meta:
        if value:
            out.append(f"**{label}:** {_md_escape_inline(value)}  " if label else f"**{_md_escape_inline(value)}**  ")
    out.append("")
    if ctx["versions"]:
        out.extend([f"## {L['version_history']}", "",
                    f"| {L['version']} | {L['date']} | {L['author']} | {L['description']} |", "|---|---|---|---|"])
        out.extend(f"| {_md_escape_inline(v['version'])} | {v['date'] or ''} | {_md_escape_inline(v['author'])} | "
                   f"{_md_escape_inline(v['description'])} |" for v in ctx["versions"])
        out.append("")

    def findings_table() -> None:
        if not ctx["findings"]:
            out.extend([L["no_findings"], ""])
            return
        out.extend([f"| {L['no']} | {L['id']} | {L['title']} | {L['severity']} | {ctx['cvss_header']} | {L['status']} |",
                    "|---|---|---|---|---|---|"])
        for i, f in enumerate(ctx["findings"], start=1):
            score = f"{f['cvss_score']:.1f} {cvss_rating_label(f, lang)}" if f["cvss_score"] is not None else "—"
            out.append(f"| {i:02d}. | {f['display_id']} | {_md_escape_inline(f['title'])} | {sev[f['severity']]} | "
                       f"{score} | {status.get(f['status'], f['status'])} |")
        out.append("")

    def severity_counts() -> None:
        out.extend([f"| {L['severity']} | {L['count']} |", "|---|---|"])
        out.extend(f"| {sev[s]} | {ctx['counts'][s]} |" for s in SEVERITIES)
        out.extend([f"| **{L['total']}** | **{len(ctx['findings'])}** |", ""])

    def charts() -> None:
        out.extend([f"**{L['chart_severity']}**", ""])
        severity_counts()
        if ctx["per_target"]:
            out.extend([f"**{L['chart_targets']}**", "",
                        "| " + " | ".join([L["target"], *(sev[s] for s in SEVERITIES), L["total"]]) + " |",
                        "|" + "---|" * (len(SEVERITIES) + 2)])
            out.extend("| " + " | ".join([_md_escape_inline(t["name"]), *(str(t["counts"][s]) for s in SEVERITIES),
                                          str(t["total"])]) + " |" for t in ctx["per_target"])
            out.append("")

    def retest_summary() -> None:
        rl, orig = ctx["retest_labels"], ctx["original_report"]
        if orig:
            dated = f" ({L['original_date']} {orig['report_date']})" if orig["report_date"] else ""
            out.extend([f"{L['original_report']}: **{_md_escape_inline(orig['title'])}**{dated}", ""])
        if not ctx["findings"]:
            out.extend([L["no_findings"], ""])
            return
        out.extend([", ".join(f"{label}: **{ctx['retest_counts'][k]}**" for k, label in rl.items()
                              if ctx["retest_counts"][k]), ""])
        out.extend([f"| {L['id']} | {L['title']} | {L['severity']} | {L['retest_result']} | {L['retest_date']} |",
                    "|---|---|---|---|---|"])
        out.extend(f"| {f['display_id']} | {_md_escape_inline(f['title'])} | {sev[f['severity']]} | "
                   f"{rl.get(f['retest_result'], '')} | {f['retest_date'] or ''} |" for f in ctx["findings"])
        out.append("")

    def finding(f: dict, depth: str) -> None:
        tag = f" · {status[f['status']]}" if f["status"] != "open" else ""
        out.extend([f"{depth} {f['display_id']}: {_md_escape_inline(f['title'])}{tag}", ""])
        out.append(f"- **{L['severity']}:** {sev[f['severity']]}")
        if f["cvss_vector"]:
            rating = cvss_rating_label(f, lang)
            out.append(f"- **CVSS {f['cvss_version']}:** {f['cvss_score']:.1f} {rating} (`{f['cvss_vector']}`)")
        if f["cwe"] and not ctx["groups"]:
            name = cwe_name(f["cwe"])
            out.append(f"- **{L['cwe']}:** [{f['cwe']}{': ' + name if name else ''}]({cwe_url(f['cwe'])})")
        out.append(f"- **{L['status']}:** {status.get(f['status'], f['status'])}")
        if f["confidence"]:
            out.append(f"- **{L['confidence']}:** {ctx['conf_labels'][f['confidence']]}")
        if f["retest_result"]:
            when = f" ({f['retest_date']})" if f["retest_date"] else ""
            out.append(f"- **{L['retest']}:** {ctx['retest_labels'][f['retest_result']]}{when}")
        if f["targets"]:
            names = ", ".join(_md_escape_inline(t["name"] + (f" ({t['address']})" if t["address"] else ""))
                              for t in f["targets"])
            out.append(f"- **{L['affected']}:** {names}")
        out.append("")
        sub = depth + "#"
        for key in ("description", "impact", "technical_details", "poc"):
            if f[key]:
                out.extend([f"{sub} {L[key]}", "", f[key], ""])
        if f["retest_notes"]:
            out.extend([f"{sub} {L['retest_notes']}", "", f["retest_notes"], ""])
        for a in f["attachments"]:
            caption = f"{L['figure']} {a['figure']}" + (f": {_md_escape_inline(a['caption'])}" if a["caption"] else "")
            if a.get("src", "").startswith("data:"):
                out.extend([f"![{caption}]({a['src']})", ""])
            out.extend([f"*{caption}*", ""])
        if f["evidence"]:
            out.extend([f"{sub} {L['evidence']}", ""])
            for e in f["evidence"]:
                if e["title"]:
                    out.extend([f"**{_md_escape_inline(e['title'])}**", ""])
                out.extend([f"*{L['request']}:*", "", _fence(e["request"], "http"), ""])
                if e["response"]:
                    out.extend([f"*{L['response']}:*", "", _fence(e["response"], "http"), ""])
        if f.get("code_evidence"):
            out.extend([f"{sub} {L['code_evidence']}", ""])
            for c in f["code_evidence"]:
                if c["title"]:
                    out.extend([f"**{_md_escape_inline(c['title'])}**", ""])
                location = c["location"].replace("`", "'")
                where = f"*{L['code_location']}:* `{location}` · " if location else ""
                out.extend([where + ctx["code_lang_labels"][c["language"]], "",
                            _fence(c["code"], MD_CODE_LANG.get(c["language"], "")), ""])
                if c["note"]:
                    out.extend([c["note"], ""])
        if f["files"]:
            out.extend([f"{sub} {L['attached_files']}", "",
                        f"| {L['file_name']} | {L['file_size']} | {L['sha256']} |", "|---|---:|---|"])
            for x in f["files"]:
                name = _md_escape_inline(x["filename"])
                if x["description"]:
                    name += f"<br>*{_md_escape_inline(x['description'])}*"
                out.append(f"| {name} | {human_size(x['size'])} | `{x['sha256']}` |")
            out.append("")
        if f["remediation"]:
            out.extend([f"{sub} {L['remediation']}", "", f["remediation"], ""])
        if f["refs"]:
            out.extend([f"{sub} {L['references']}", ""])
            out.extend(f"- {line.strip()}" for line in f["refs"].split("\n") if line.strip())
            out.append("")
        if ctx["show_finding_history"] and f["history"]:
            out.extend([f"{sub} {L['finding_history']}", ""])
            out.extend(f"- {h['date'] or ''}" + (f" ({_md_escape_inline(h['author'])})" if h["author"] else "")
                       + f": {_md_escape_inline(h['text'])}" for h in f["history"])
            out.append("")

    n_sec = n_sub = 0
    for sec in ctx["sections"]:
        if sec["numbered"]:
            if sec["level"] == 1:
                n_sec, n_sub = n_sec + 1, 0
                number = f"{n_sec} "
            else:
                n_sub += 1
                number = f"{n_sec}.{n_sub} "
        else:
            number = ""
        depth = "##" if sec["level"] == 1 else "###"
        out.extend([f"{depth} {number}{_md_escape_inline(sec['title'])}", ""])
        kind = sec["kind"]
        if kind in ("executive_summary", "scope", "methodology") and r[kind]:
            out.extend([_md_body(r[kind]), ""])
        if kind == "scope" and ctx["targets"]:
            out.extend([f"**{L['targets']}**", "", f"| {L['target']} | {L['type']} | {L['address']} |", "|---|---|---|"])
            out.extend(f"| {_md_escape_inline(t['name'])} | {kinds.get(t['kind'], t['kind'])} | "
                       f"{_md_escape_inline(t['address'])} |" for t in ctx["targets"])
            out.append("")
        elif kind == "summary":
            severity_counts()
            findings_table()
        elif kind == "findings_table":
            findings_table()
        elif kind == "charts":
            charts()
        elif kind == "retest_summary":
            retest_summary()
        elif kind == "findings":
            if not ctx["findings"]:
                out.extend([L["no_findings"], ""])
            elif ctx["groups"]:
                for g in ctx["groups"]:
                    out.extend([f"{depth}# {_md_escape_inline(g['title'])}", ""])
                    if g["description"]:
                        out.extend([g["description"], ""])
                    for f in g["findings"]:
                        finding(f, depth + "##")
                    if g["mitigation"]:
                        out.extend([f"{depth}## {L['mitigation']}", "", g["mitigation"], ""])
            else:
                for f in ctx["findings"]:
                    finding(f, depth + "#")
        if sec["body"]:
            out.extend([_md_body(sec["body"]), ""])
    return "\n".join(out).rstrip() + "\n"


def add_originals(conn: sqlite3.Connection, ctx: dict) -> None:
    """Attach the untouched originals of edited screenshots, so the JSON backup can restore them later."""
    attachments = [a for f in ctx["findings"] for a in f["attachments"] if a["edited"]]
    originals = repo.attachment_originals(conn, [a["id"] for a in attachments])
    for a in attachments:
        if a["id"] in originals:
            a["original"] = originals[a["id"]]


def _attachment_json(a: dict) -> dict:
    out = {"caption": a["caption"], "mime": a["mime"], "data_base64": base64.b64encode(a["data"]).decode("ascii")}
    if a.get("original"):
        mime, data = a["original"]
        out["original"] = {"mime": mime, "data_base64": base64.b64encode(data).decode("ascii"),
                           "edited_at": a["edited_at"]}
    return out


def _import_original(original: Any) -> tuple[dict, dict]:
    """The untouched original of an edited screenshot in a JSON backup (same checks as any upload)."""
    if not isinstance(original, dict) or not isinstance(original.get("data_base64"), str):
        return {}, {"file": "must be an object with data_base64"}
    try:
        raw = base64.b64decode(original["data_base64"], validate=True)
    except (binascii.Error, ValueError):
        return {}, {"file": "data_base64 is not valid base64"}
    clean, errors = validate_attachment("", raw)
    if errors:
        return {}, errors
    edited_at = original.get("edited_at")
    if not (isinstance(edited_at, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", edited_at)):
        edited_at = None
    return {"original_mime": clean["mime"], "original_data": clean["data"], "edited_at": edited_at}, {}


def _file_json(x: dict, blobs: dict[int, bytes] | None) -> dict:
    out = {f: x[f] for f in repo.FILE_FIELDS}
    if blobs is not None:
        out["data_base64"] = base64.b64encode(blobs[x["id"]]).decode("ascii")
    return out


def to_json(ctx: dict, file_blobs: dict[int, bytes] | None = None) -> dict:
    """The report as a JSON document. Files carry their bytes (base64) only when ``file_blobs`` is given;
    without it (the content fingerprint) their SHA-256 stands for the content."""
    r = ctx["report"]
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported_with": f"ptreport {__version__}",
        "report": {f: r[f] for f in repo.REPORT_FIELDS},
        "targets": [{"ref": t["id"], **{f: t[f] for f in repo.TARGET_FIELDS}} for t in ctx["targets"]],
        "findings": [
            {
                **{f: fd[f] for f in repo.FINDING_FIELDS if f not in ("severity", "cvss_score")},
                "severity": fd["severity"],
                "position": fd["position"],
                "origin": fd.get("origin", ""),
                "targets": [t["id"] for t in fd["targets"]],
                "evidence": [{f: e[f] for f in repo.EVIDENCE_FIELDS} for e in fd["evidence"]],
                "history": [{f: h[f] for f in repo.HISTORY_FIELDS} for h in fd["history"]],
                "attachments": [_attachment_json(a) for a in fd["attachments"]],
                "files": [_file_json(x, file_blobs) for x in fd["files"]],
                "code_evidence": [{f: c[f] for f in repo.CODE_FIELDS} for c in fd.get("code_evidence", [])],
            }
            for fd in ctx["findings"]
        ],
        "versions": [{"version": v["version"], "date": v["date"], "author": v["author"],
                      "description": v["description"]} for v in ctx["all_versions"]],
        "sections": [{f: s[f] for f in repo.SECTION_FIELDS} for s in ctx["all_sections"]],
        "cwe_notes": [{"cwe": g["cwe"], "title": g["title_override"], "description": g["description"],
                       "mitigation": g["mitigation"], "position": g["position"]} for g in ctx["cwe_notes"]],
    }


class ImportError_(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _collect(prefix: str, errors: dict, sink: list[str]) -> None:
    sink.extend(f"{prefix}: {field}: {msg}" for field, msg in errors.items())


MAX_IMPORT_ITEMS = 5000


def _import_files(i: int, files_in: Any) -> tuple[list[dict], list[str]]:
    """Evidence files of one imported finding: same validation as an upload, and the bytes must match the
    SHA-256 (and size) recorded in the export, so a corrupted or altered file is rejected."""
    files: list[dict] = []
    problems: list[str] = []
    files_in = files_in or []
    if not isinstance(files_in, list) or len(files_in) > FILE_MAX_PER_FINDING:
        return [], [f"finding #{i}: files must be a list of at most {FILE_MAX_PER_FINDING} files"]
    for j, x in enumerate(files_in, 1):
        where = f"finding #{i} file #{j}"
        if not isinstance(x, dict) or not isinstance(x.get("data_base64"), str):
            problems.append(f"{where}: must be an object with data_base64")
            continue
        if not is_sha256(x.get("sha256")):
            problems.append(f"{where}: sha256 must be 64 lowercase hex characters")
            continue
        try:
            raw = base64.b64decode(x["data_base64"], validate=True)
        except (binascii.Error, ValueError):
            problems.append(f"{where}: data_base64 is not valid base64")
            continue
        clean, errs = validate_file(x.get("filename"), x.get("description", ""), raw)
        if errs:
            _collect(where, errs, problems)
            continue
        if not hmac.compare_digest(clean["sha256"], x["sha256"]):
            problems.append(f"{where} ({clean['filename']}): SHA-256 does not match the file content")
            continue
        if "size" in x and x["size"] != clean["size"]:
            problems.append(f"{where} ({clean['filename']}): size does not match the file content")
            continue
        if is_timestamp(x.get("uploaded_at")):
            clean["uploaded_at"] = x["uploaded_at"]
        files.append(clean)
    quota = check_file_quota(0, 0, [x["size"] for x in files])
    if quota:
        problems.append(f"finding #{i}: {quota}")
    return files, problems


def import_json(conn: sqlite3.Connection, payload: Any) -> int:
    """Validate an exported document fully, then insert it as a new report."""
    problems: list[str] = []
    if not isinstance(payload, dict) or payload.get("format") != EXPORT_FORMAT:
        raise ImportError_(["Not a ptreport export file."])
    if payload.get("version") != EXPORT_VERSION:
        raise ImportError_([f"Unsupported export version {payload.get('version')!r}."])

    report_data, errs = validate_report(payload.get("report") or {})
    _collect("report", errs, problems)

    targets_in = payload.get("targets") or []
    findings_in = payload.get("findings") or []
    if not isinstance(targets_in, list) or not isinstance(findings_in, list):
        raise ImportError_(["'targets' and 'findings' must be lists."])
    if len(targets_in) > MAX_IMPORT_ITEMS or len(findings_in) > MAX_IMPORT_ITEMS:
        raise ImportError_(["Too many items in import file."])

    targets: list[tuple[Any, dict]] = []
    for i, t in enumerate(targets_in, 1):
        if not isinstance(t, dict):
            problems.append(f"target #{i}: must be an object")
            continue
        clean, errs = validate_target(t)
        _collect(f"target #{i}", errs, problems)
        ref = t.get("ref")
        if isinstance(ref, bool) or not isinstance(ref, (int, str)):
            ref = None
        targets.append((ref, clean))
    known_refs = {ref for ref, _ in targets if ref is not None}

    findings: list[tuple[dict, list, list[dict], list[dict], list[dict], list[dict], list[dict]]] = []
    seen_external_ids: set[str] = set()
    for i, f in enumerate(findings_in, 1):
        if not isinstance(f, dict):
            problems.append(f"finding #{i}: must be an object")
            continue
        refs = f.get("targets") or []
        if not isinstance(refs, list) or any(
            isinstance(r, bool) or not isinstance(r, (int, str)) or r not in known_refs for r in refs
        ):
            problems.append(f"finding #{i}: references unknown targets")
            refs = []
        clean, errs = validate_finding(f, target_ids_raw=[])
        _collect(f"finding #{i}", errs, problems)
        clean["origin"], origin_error = validate_origin(f.get("origin"))
        if origin_error:
            problems.append(f"finding #{i}: origin: {origin_error}")
        ext = clean.get("external_id", "")
        if ext and ext.lower() in seen_external_ids:
            problems.append(f"finding #{i}: duplicate finding ID {ext}")
        seen_external_ids.add(ext.lower())
        evidence = []
        ev_in = f.get("evidence") or []
        if not isinstance(ev_in, list):
            problems.append(f"finding #{i}: evidence must be a list")
            ev_in = []
        for j, e in enumerate(ev_in, 1):
            if not isinstance(e, dict):
                problems.append(f"finding #{i} evidence #{j}: must be an object")
                continue
            ev_clean, ev_errs = validate_evidence({**e, "source": e.get("source") or "import"})
            _collect(f"finding #{i} evidence #{j}", ev_errs, problems)
            evidence.append(ev_clean)
        attachments = []
        att_in = f.get("attachments") or []
        if not isinstance(att_in, list) or len(att_in) > IMAGE_MAX_PER_FINDING:
            problems.append(f"finding #{i}: attachments must be a list of at most {IMAGE_MAX_PER_FINDING} images")
            att_in = []
        for j, a in enumerate(att_in, 1):
            if not isinstance(a, dict) or not isinstance(a.get("data_base64"), str):
                problems.append(f"finding #{i} screenshot #{j}: must be an object with data_base64")
                continue
            try:
                raw = base64.b64decode(a["data_base64"], validate=True)
            except (binascii.Error, ValueError):
                problems.append(f"finding #{i} screenshot #{j}: data_base64 is not valid base64")
                continue
            att_clean, att_errs = validate_attachment(a.get("caption", ""), raw)
            _collect(f"finding #{i} screenshot #{j}", att_errs, problems)
            original = a.get("original")
            if original is not None:
                orig_clean, orig_errs = _import_original(original)
                _collect(f"finding #{i} screenshot #{j} original", orig_errs, problems)
                att_clean.update(orig_clean)
            attachments.append(att_clean)
        code = []
        code_in = f.get("code_evidence") or []
        if not isinstance(code_in, list) or len(code_in) > MAX_IMPORT_ITEMS:
            problems.append(f"finding #{i}: code_evidence must be a list")
            code_in = []
        for j, c in enumerate(code_in, 1):
            if not isinstance(c, dict):
                problems.append(f"finding #{i} code evidence #{j}: must be an object")
                continue
            c_clean, c_errs = validate_code_evidence(c)
            _collect(f"finding #{i} code evidence #{j}", c_errs, problems)
            code.append(c_clean)
        files, file_problems = _import_files(i, f.get("files"))
        problems.extend(file_problems)
        history = []
        hist_in = f.get("history") or []
        if not isinstance(hist_in, list) or len(hist_in) > MAX_IMPORT_ITEMS:
            problems.append(f"finding #{i}: history must be a list")
            hist_in = []
        for j, h in enumerate(hist_in, 1):
            if not isinstance(h, dict):
                problems.append(f"finding #{i} history #{j}: must be an object")
                continue
            h_clean, h_errs = validate_history_entry(h)
            _collect(f"finding #{i} history #{j}", h_errs, problems)
            history.append(h_clean)
        findings.append((clean, refs, evidence, attachments, files, history, code))

    versions = []
    versions_in = payload.get("versions") or []
    if not isinstance(versions_in, list) or len(versions_in) > MAX_IMPORT_ITEMS:
        problems.append("'versions' must be a list")
        versions_in = []
    for i, ver in enumerate(versions_in, 1):
        if not isinstance(ver, dict):
            problems.append(f"version #{i}: must be an object")
            continue
        ver_clean, ver_errs = validate_report_version(ver)
        _collect(f"version #{i}", ver_errs, problems)
        versions.append(ver_clean)

    sections = []
    sections_in = payload.get("sections") or []
    if not isinstance(sections_in, list) or len(sections_in) > 200:
        problems.append("'sections' must be a list of at most 200 sections")
        sections_in = []
    for i, sec in enumerate(sections_in, 1):
        if not isinstance(sec, dict):
            problems.append(f"section #{i}: must be an object")
            continue
        sec_clean, sec_errs = validate_section(sec)
        _collect(f"section #{i}", sec_errs, problems)
        sections.append(sec_clean)

    cwe_notes = []
    notes_in = payload.get("cwe_notes") or []
    if not isinstance(notes_in, list) or len(notes_in) > MAX_IMPORT_ITEMS:
        problems.append("'cwe_notes' must be a list")
        notes_in = []
    for i, note in enumerate(notes_in, 1):
        if not isinstance(note, dict):
            problems.append(f"CWE note #{i}: must be an object")
            continue
        note_clean, note_errs = validate_cwe_note(note)
        _collect(f"CWE note #{i}", note_errs, problems)
        position = note.get("position")
        note_clean["position"] = position if isinstance(position, int) and 0 <= position <= 10_000 else 0
        cwe_notes.append(note_clean)

    work_notes = []
    work_in = payload.get("notes") or []
    if not isinstance(work_in, list) or len(work_in) > MAX_IMPORT_ITEMS:
        problems.append("'notes' must be a list")
        work_in = []
    for i, note in enumerate(work_in, 1):
        if not isinstance(note, dict):
            problems.append(f"note #{i}: must be an object")
            continue
        note_clean, note_errs = validate_note(note)
        _collect(f"note #{i}", note_errs, problems)
        work_notes.append(note_clean)

    if problems:
        raise ImportError_(problems[:50])

    with transaction(conn):
        report_id = repo.create_report(conn, report_data)
        ref_map = {}
        for ref, data in targets:
            new_id = repo.create_target(conn, report_id, data)
            if ref is not None:
                ref_map[ref] = new_id
        for clean, refs, evidence, attachments, files, history, code in findings:
            clean["target_ids"] = sorted({ref_map[r] for r in refs})
            finding_id = repo.create_finding(conn, report_id, clean)
            finding = {"id": finding_id, "report_id": report_id}
            for ev in evidence:
                repo.create_evidence(conn, finding, ev)
            for item in code:
                repo.create_code_evidence(conn, finding, item)
            for att in attachments:
                repo.create_attachment(conn, finding, att)
            for item in files:
                repo.create_file(conn, finding, item)
            for entry in history:
                repo.create_history_entry(conn, finding, entry)
        for ver in versions:
            repo.create_report_version(conn, report_id, ver)
        if sections:
            repo.replace_sections(conn, report_id, sections)
        for note in cwe_notes:
            repo.save_cwe_note(conn, report_id, note["cwe"], note, position=note["position"])
        for note in work_notes:
            repo.create_note(conn, report_id, note)
    return report_id
