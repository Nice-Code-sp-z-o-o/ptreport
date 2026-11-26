"""Browser UI (server-rendered, CSRF protected)."""

from __future__ import annotations

from datetime import date
import json
import re

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from ptreport import ai, export, ids, importers, latex, repo
from ptreport.cvss_service import METRIC_DEFINITIONS, CvssInvalid, score_vector
from ptreport.cwe import catalogue_version as cwe_catalogue_version
from ptreport.cwe import cwe_choices, cwe_name, cwe_reference
from ptreport.cwe import search as cwe_search
from ptreport.db import get_db, transaction
from ptreport.rendering import (
    CONFIDENCE_LABELS,
    REPORT_LABELS,
    RETEST_LABELS,
    SEVERITY_LABELS,
    STATUS_LABELS,
    history_text,
    labels_for,
)
from ptreport.security import regenerate_api_token
from ptreport.validation import (
    IMAGE_MAX_BYTES,
    IMAGE_MAX_PER_FINDING,
    CONFIDENCE_LEVELS,
    FINDING_STATUSES,
    LANGUAGES,
    RETEST_RESULTS,
    SEVERITIES,
    TARGET_KINDS,
    TEMPLATE_FIELDS,
    validate_evidence,
    validate_attachment,
    validate_ai_settings,
    validate_brand_color,
    validate_cwe_note,
    validate_finding,
    validate_history_entry,
    validate_note,
    validate_report_version,
    validate_section,
    validate_report,
    validate_settings,
    validate_target,
    validate_template,
)

bp = Blueprint("web", __name__)


def _report_or_404(report_id: int) -> dict:
    report = repo.get_report(get_db(), report_id)
    if report is None:
        abort(404)
    return report


def _target_or_404(target_id: int) -> tuple[dict, dict]:
    target = repo.get_target(get_db(), target_id)
    if target is None:
        abort(404)
    return target, _report_or_404(target["report_id"])


def _finding_or_404(finding_id: int) -> tuple[dict, dict]:
    finding = repo.get_finding(get_db(), finding_id)
    if finding is None:
        abort(404)
    return finding, _report_or_404(finding["report_id"])


# ---------------------------------------------------------------- reports --

def _retest_mode(ctx: dict) -> bool:
    return bool(ctx["original_report"]) or any(f["retest_result"] for f in ctx["findings"])


@bp.get("/")
def index():
    return render_template("index.html", reports=repo.list_reports(get_db()))


def _report_form(report: dict | None, values: dict, errors: dict, status: int = 200):
    return (
        render_template(
            "reports/form.html", report=report, values=values, errors=errors, languages=LANGUAGES,
            global_id_format=repo.get_settings(get_db())["id_format"],
        ),
        status,
    )


@bp.route("/reports/new", methods=["GET", "POST"])
def report_new():
    if request.method == "GET":
        defaults = repo.get_settings(get_db())
        return _report_form(None, {"finding_prefix": defaults["default_prefix"],
                                   "language": defaults["default_language"]}, {})
    data, errors = validate_report(request.form)
    if errors:
        return _report_form(None, request.form, errors, 422)
    report_id = repo.create_report(get_db(), data)
    flash("Report created.", "success")
    return redirect(url_for("web.report_detail", report_id=report_id))


@bp.get("/reports/<int:report_id>")
def report_detail(report_id: int):
    if repo.get_report(get_db(), report_id) is None:
        abort(404)
    repo.ensure_sections(get_db(), report_id)
    ctx = export.build_context(get_db(), report_id)
    return render_template("reports/detail.html", section_kinds=SECTION_KIND_LABELS, addable_kinds=ADDABLE_KINDS,
                           retest_mode=_retest_mode(ctx), note_count=repo.count_notes(get_db(), report_id), **ctx)


@bp.route("/reports/<int:report_id>/edit", methods=["GET", "POST"])
def report_edit(report_id: int):
    report = _report_or_404(report_id)
    if request.method == "GET":
        return _report_form(report, report, {})
    data, errors = validate_report(request.form)
    if errors:
        return _report_form(report, request.form, errors, 422)
    repo.update_report(get_db(), report_id, data)
    flash("Report saved.", "success")
    return redirect(url_for("web.report_detail", report_id=report_id))


@bp.post("/reports/<int:report_id>/delete")
def report_delete(report_id: int):
    _report_or_404(report_id)
    repo.delete_report(get_db(), report_id)
    flash("Report deleted.", "success")
    return redirect(url_for("web.index"))


# ---------------------------------------------------------------- targets --

def _target_form(report: dict, target: dict | None, values: dict, errors: dict, status: int = 200):
    return (
        render_template(
            "targets/form.html", report=report, target=target, values=values, errors=errors,
            kinds=TARGET_KINDS,
        ),
        status,
    )


@bp.route("/reports/<int:report_id>/targets/new", methods=["GET", "POST"])
def target_new(report_id: int):
    report = _report_or_404(report_id)
    if request.method == "GET":
        return _target_form(report, None, {"kind": "web",
                                           "return_to_finding": request.args.get("return_to_finding", "")}, {})
    data, errors = validate_target(request.form)
    if errors:
        return _target_form(report, None, request.form, errors, 422)
    repo.create_target(get_db(), report_id, data)
    flash("Target added.", "success")
    back = request.form.get("return_to_finding", "")
    if back.isdigit():
        finding = repo.get_finding(get_db(), int(back))
        if finding and finding["report_id"] == report_id:
            return redirect(url_for("web.finding_edit", finding_id=finding["id"], _anchor="targets"))
    if request.form.get("add_another"):
        return redirect(url_for("web.target_new", report_id=report_id))
    return redirect(url_for("web.report_detail", report_id=report_id, _anchor="targets"))


@bp.post("/reports/<int:report_id>/targets/quick")
def target_quick_new(report_id: int):
    """Create a target from the finding editor without leaving it (JSON answer, CSRF via header)."""
    _report_or_404(report_id)
    data, errors = validate_target(request.form)
    if errors:
        return jsonify(error="validation_failed", errors=errors), 422
    target_id = repo.create_target(get_db(), report_id, data)
    target = repo.get_target(get_db(), target_id)
    return jsonify(target={k: target[k] for k in ("id", "name", "kind", "address")}), 201


@bp.route("/targets/<int:target_id>/edit", methods=["GET", "POST"])
def target_edit(target_id: int):
    target, report = _target_or_404(target_id)
    if request.method == "GET":
        return _target_form(report, target, target, {})
    data, errors = validate_target(request.form)
    if errors:
        return _target_form(report, target, request.form, errors, 422)
    repo.update_target(get_db(), target, data)
    flash("Target saved.", "success")
    return redirect(url_for("web.report_detail", report_id=report["id"], _anchor="targets"))


@bp.post("/targets/<int:target_id>/delete")
def target_delete(target_id: int):
    target, report = _target_or_404(target_id)
    repo.delete_target(get_db(), target)
    flash("Target deleted.", "success")
    return redirect(url_for("web.report_detail", report_id=report["id"], _anchor="targets"))


# --------------------------------------------------------------- findings --

def _finding_form(report: dict, finding: dict | None, values: dict, errors: dict,
                  selected_targets: list[int], status: int = 200, *,
                  evidence_values: dict | None = None, evidence_errors: dict | None = None,
                  attachment_values: dict | None = None, attachment_errors: dict | None = None,
                  history_values: dict | None = None, history_errors: dict | None = None):
    return (
        render_template(
            "findings/form.html",
            report=report,
            finding=finding,
            display_id=repo.finding_display_id(report, finding, repo.get_settings(get_db())) if finding else None,
            values=values,
            errors=errors,
            targets=repo.list_targets(get_db(), report["id"]),
            selected_targets=set(selected_targets),
            severities=SEVERITIES,
            statuses=FINDING_STATUSES,
            cwe_choices=cwe_choices(),
            cvss_defs=METRIC_DEFINITIONS,
            evidence=finding["evidence"] if finding else [],
            evidence_values=evidence_values or {},
            evidence_errors=evidence_errors or {},
            attachments=finding["attachments"] if finding else [],
            attachment_values=attachment_values or {},
            attachment_errors=attachment_errors or {},
            confidence_levels=CONFIDENCE_LEVELS,
            target_kinds=TARGET_KINDS,
            history=[{**h, "text": history_text(h)} for h in finding["history"]] if finding else [],
            history_values=history_values or {"date": date.today().isoformat()},
            history_errors=history_errors or {},
            retest_results=RETEST_RESULTS,
            templates=repo.list_templates(get_db()) if finding is None else [],
            ai_enabled=repo.get_ai_settings(get_db())["enabled"],
            ai_fields=AI_FIELD_LABELS,
        ),
        status,
    )


def _parse_finding_form(report: dict, finding_id: int | None = None) -> tuple[dict, dict, list[int]]:
    raw_ids = request.form.getlist("target_ids")
    data, errors = validate_finding(request.form, target_ids_raw=raw_ids)
    if "target_ids" not in errors and repo.foreign_target_ids(
        get_db(), report["id"], data.get("target_ids", [])
    ):
        errors["target_ids"] = "Selected targets must belong to this report."
    if "external_id" not in errors and repo.external_id_taken(
        get_db(), report["id"], data.get("external_id", ""), finding_id
    ):
        errors["external_id"] = "Another finding in this report already uses this ID."
    selected = [int(i) for i in raw_ids if i.isdigit()]
    return data, errors, selected


@bp.route("/reports/<int:report_id>/findings/new", methods=["GET", "POST"])
def finding_new(report_id: int):
    report = _report_or_404(report_id)
    if request.method == "GET":
        values = {"status": "open", "cvss_version": "3.1"}
        template_id = request.args.get("template", "")
        if template_id.isdigit():
            template = repo.get_template(get_db(), int(template_id))
            if template is None:
                abort(404)
            values = repo.template_as_finding_values(template)
        return _finding_form(report, None, values, {}, [])
    data, errors, selected = _parse_finding_form(report)
    if errors:
        return _finding_form(report, None, request.form, errors, selected, 422)
    finding_id = repo.create_finding(get_db(), report_id, data)
    flash("Finding created.", "success")
    return redirect(url_for("web.finding_edit", finding_id=finding_id))


@bp.route("/findings/<int:finding_id>/edit", methods=["GET", "POST"])
def finding_edit(finding_id: int):
    finding, report = _finding_or_404(finding_id)
    if request.method == "GET":
        return _finding_form(report, finding, finding, {}, finding["target_ids"])
    data, errors, selected = _parse_finding_form(report, finding_id)
    if errors:
        return _finding_form(report, finding, request.form, errors, selected, 422)
    repo.update_finding(get_db(), finding, data)
    if data.get("retest_result") and data["retest_result"] != finding.get("retest_result"):
        lang = report["language"] if report["language"] in RETEST_LABELS else "en"
        note = f"{REPORT_LABELS[lang]['retest']}: {RETEST_LABELS[lang][data['retest_result']]}"
        repo.create_history_entry(get_db(), finding, {
            "date": data.get("retest_date") or date.today().isoformat(), "author": "", "kind": "note",
            "status_from": "", "status_to": "", "description": note[:300]})
    flash("Finding saved.", "success")
    if request.form.get("save_and_back"):
        return redirect(url_for("web.report_detail", report_id=report["id"], _anchor="findings"))
    return redirect(url_for("web.finding_edit", finding_id=finding_id))


@bp.post("/findings/<int:finding_id>/delete")
def finding_delete(finding_id: int):
    finding, report = _finding_or_404(finding_id)
    repo.delete_finding(get_db(), finding)
    flash("Finding deleted.", "success")
    return redirect(url_for("web.report_detail", report_id=report["id"], _anchor="findings"))


@bp.post("/findings/<int:finding_id>/move")
def finding_move(finding_id: int):
    finding, report = _finding_or_404(finding_id)
    direction = request.form.get("direction")
    if direction not in ("up", "down"):
        abort(400)
    repo.move_finding(get_db(), finding, direction)
    return redirect(url_for("web.report_detail", report_id=report["id"], _anchor="findings"))


@bp.post("/reports/<int:report_id>/findings/renumber")
def findings_renumber(report_id: int):
    _report_or_404(report_id)
    repo.renumber_by_severity(get_db(), report_id)
    flash("Findings renumbered by severity.", "success")
    return redirect(url_for("web.report_detail", report_id=report_id, _anchor="findings"))


# --------------------------------------------------------------- evidence --

@bp.post("/findings/<int:finding_id>/evidence")
def evidence_new(finding_id: int):
    finding, report = _finding_or_404(finding_id)
    data, errors = validate_evidence({**request.form.to_dict(), "source": "manual"})
    if errors:
        return _finding_form(report, finding, finding, {}, finding["target_ids"], 422,
                             evidence_values=request.form, evidence_errors=errors)
    repo.create_evidence(get_db(), finding, data)
    flash("HTTP evidence added.", "success")
    return redirect(url_for("web.finding_edit", finding_id=finding_id, _anchor="evidence"))


@bp.post("/evidence/<int:evidence_id>/delete")
def evidence_delete(evidence_id: int):
    evidence = repo.get_evidence(get_db(), evidence_id)
    if evidence is None:
        abort(404)
    repo.delete_evidence(get_db(), evidence)
    flash("HTTP evidence deleted.", "success")
    return redirect(url_for("web.finding_edit", finding_id=evidence["finding_id"], _anchor="evidence"))


# ------------------------------------------------------------- screenshots --

@bp.post("/findings/<int:finding_id>/attachments")
def attachment_new(finding_id: int):
    finding, report = _finding_or_404(finding_id)
    upload = request.files.get("file")
    data = upload.read(IMAGE_MAX_BYTES + 1) if upload and upload.filename else None
    clean, errors = validate_attachment(request.form.get("caption", ""), data)
    if not errors and repo.count_attachments(get_db(), finding_id) >= IMAGE_MAX_PER_FINDING:
        errors["file"] = f"A finding can have at most {IMAGE_MAX_PER_FINDING} screenshots."
    if errors:
        return _finding_form(report, finding, finding, {}, finding["target_ids"], 422,
                             attachment_values=request.form, attachment_errors=errors)
    repo.create_attachment(get_db(), finding, clean)
    flash("Screenshot added.", "success")
    return redirect(url_for("web.finding_edit", finding_id=finding_id, _anchor="screenshots"))


def _attachment_or_404(attachment_id: int, with_data: bool = False) -> dict:
    attachment = repo.get_attachment(get_db(), attachment_id, with_data=with_data)
    if attachment is None:
        abort(404)
    return attachment


@bp.get("/attachments/<int:attachment_id>")
def attachment_file(attachment_id: int):
    attachment = _attachment_or_404(attachment_id, with_data=True)
    response = Response(attachment["data"], mimetype=attachment["mime"])
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response.headers["Content-Disposition"] = "inline"
    response.headers["Cache-Control"] = "private, max-age=3600"
    response.headers["ETag"] = attachment["sha256"]
    return response


@bp.post("/attachments/<int:attachment_id>/caption")
def attachment_caption(attachment_id: int):
    attachment = _attachment_or_404(attachment_id)
    clean, errors = validate_attachment(request.form.get("caption", ""), b"\x89PNG\r\n\x1a\n")
    if errors.get("caption"):
        flash(errors["caption"], "error")
    else:
        repo.update_attachment_caption(get_db(), attachment, clean["caption"])
        flash("Caption saved.", "success")
    return redirect(url_for("web.finding_edit", finding_id=attachment["finding_id"], _anchor="screenshots"))


@bp.post("/attachments/<int:attachment_id>/delete")
def attachment_delete(attachment_id: int):
    attachment = _attachment_or_404(attachment_id)
    repo.delete_attachment(get_db(), attachment)
    flash("Screenshot deleted.", "success")
    return redirect(url_for("web.finding_edit", finding_id=attachment["finding_id"], _anchor="screenshots"))


# --------------------------------------------------------- report versions --

@bp.post("/reports/<int:report_id>/versions")
def report_version_new(report_id: int):
    _report_or_404(report_id)
    data, errors = validate_report_version(request.form)
    if errors:
        repo.ensure_sections(get_db(), report_id)
        ctx = export.build_context(get_db(), report_id, inline_images=False)
        return render_template("reports/detail.html", version_values=request.form, version_errors=errors,
                               section_kinds=SECTION_KIND_LABELS, addable_kinds=ADDABLE_KINDS,
                               retest_mode=_retest_mode(ctx), note_count=repo.count_notes(get_db(), report_id),
                               **ctx), 422
    repo.create_report_version(get_db(), report_id, data)
    flash("Version added to the history.", "success")
    return redirect(url_for("web.report_detail", report_id=report_id, _anchor="versions"))


@bp.post("/report-versions/<int:version_id>/edit")
def report_version_edit(version_id: int):
    version = repo.get_report_version(get_db(), version_id)
    if version is None:
        abort(404)
    data, errors = validate_report_version(request.form)
    if errors:
        flash("Version not saved: " + " ".join(errors.values()), "error")
    else:
        repo.update_report_version(get_db(), version, data)
        flash("Version updated.", "success")
    return redirect(url_for("web.report_detail", report_id=version["report_id"], _anchor="versions"))


# -------------------------------------------------------- report structure --

SECTION_KIND_LABELS = {
    "executive_summary": "Executive summary (report field)", "scope": "Scope + targets (report field)",
    "methodology": "Methodology (report field)", "summary": "Severity chart + table of findings",
    "findings_table": "Table of findings", "charts": "Charts (severity, per target, CVSS vs severity)",
    "findings": "Findings (details)", "retest_summary": "Retest summary (results per finding)",
    "text": "Text section",
}
ADDABLE_KINDS = repo.REMOVABLE_KINDS


def _section_or_404(section_id: int) -> dict:
    section = repo.get_section(get_db(), section_id)
    if section is None:
        abort(404)
    return section


def _back_to_structure(report_id: int):
    return redirect(url_for("web.report_detail", report_id=report_id, _anchor="structure"))


@bp.post("/reports/<int:report_id>/sections")
def section_new(report_id: int):
    _report_or_404(report_id)
    kind = request.form.get("kind", "text")
    if kind not in ADDABLE_KINDS:
        abort(400)
    data, errors = validate_section({**request.form.to_dict(), "kind": kind, "level": request.form.get("level", "1"),
                                     "new_page": "1" if kind != "text" else request.form.get("new_page", "0")})
    if errors:
        flash("Section not added: " + " ".join(errors.values()), "error")
    else:
        repo.create_section(get_db(), report_id, data)
        flash("Section added at the end of the report.", "success")
    return _back_to_structure(report_id)


@bp.post("/sections/<int:section_id>/edit")
def section_edit(section_id: int):
    section = _section_or_404(section_id)
    data, errors = validate_section(_section_form(section))
    if errors:
        flash("Section not saved: " + " ".join(errors.values()), "error")
    else:
        repo.update_section(get_db(), section, data)
        flash("Section saved.", "success")
    return _back_to_structure(section["report_id"])


def _section_form(section: dict):
    """The posted form with the section's own kind (the kind of a section never changes)."""
    form = request.form.copy()
    form["kind"] = section["kind"]
    return form


@bp.post("/sections/<int:section_id>/move")
def section_move(section_id: int):
    section = _section_or_404(section_id)
    direction = request.form.get("direction")
    if direction not in ("up", "down"):
        abort(400)
    repo.move_section(get_db(), section, direction)
    return _back_to_structure(section["report_id"])


@bp.post("/sections/<int:section_id>/delete")
def section_delete(section_id: int):
    section = _section_or_404(section_id)
    if section["kind"] not in repo.REMOVABLE_KINDS:
        abort(400, description="Built-in sections can be switched off, not deleted.")
    repo.delete_section(get_db(), section)
    flash("Section deleted.", "success")
    return _back_to_structure(section["report_id"])


@bp.post("/reports/<int:report_id>/cwe-groups")
def cwe_group_save(report_id: int):
    _report_or_404(report_id)
    data, errors = validate_cwe_note(request.form)
    if errors:
        flash("Group not saved: " + " ".join(errors.values()), "error")
    else:
        repo.save_cwe_note(get_db(), report_id, data["cwe"], data)
        flash("CWE group saved.", "success")
    return redirect(url_for("web.report_detail", report_id=report_id, _anchor="cwe-groups"))


@bp.post("/reports/<int:report_id>/cwe-groups/move")
def cwe_group_move(report_id: int):
    _report_or_404(report_id)
    direction = request.form.get("direction")
    cwe = request.form.get("cwe", "")
    if direction not in ("up", "down") or (cwe and validate_cwe_note({"cwe": cwe})[1]):
        abort(400)
    repo.move_cwe_group(get_db(), report_id, cwe, direction, repo.list_findings(get_db(), report_id))
    return redirect(url_for("web.report_detail", report_id=report_id, _anchor="cwe-groups"))


# --------------------------------------------------------- finding history --

@bp.post("/findings/<int:finding_id>/history")
def history_new(finding_id: int):
    finding, report = _finding_or_404(finding_id)
    data, errors = validate_history_entry({**request.form.to_dict(), "kind": "note"})
    if errors:
        return _finding_form(report, finding, finding, {}, finding["target_ids"], 422,
                             history_values=request.form, history_errors=errors)
    repo.create_history_entry(get_db(), finding, data)
    flash("History entry added.", "success")
    return redirect(url_for("web.finding_edit", finding_id=finding_id, _anchor="history"))


def _history_or_404(entry_id: int) -> dict:
    entry = repo.get_history_entry(get_db(), entry_id)
    if entry is None:
        abort(404)
    return entry


@bp.post("/history/<int:entry_id>/edit")
def history_edit(entry_id: int):
    entry = _history_or_404(entry_id)
    data, errors = validate_history_entry({**request.form.to_dict(), "kind": entry["kind"],
                                           "status_from": entry["status_from"], "status_to": entry["status_to"]})
    if errors:
        flash("History entry not saved: " + " ".join(errors.values()), "error")
    else:
        repo.update_history_entry(get_db(), entry, data)
        flash("History entry updated.", "success")
    return redirect(url_for("web.finding_edit", finding_id=entry["finding_id"], _anchor="history"))


@bp.post("/history/<int:entry_id>/delete")
def history_delete(entry_id: int):
    entry = _history_or_404(entry_id)
    repo.delete_history_entry(get_db(), entry)
    flash("History entry deleted.", "success")
    return redirect(url_for("web.finding_edit", finding_id=entry["finding_id"], _anchor="history"))


@bp.post("/report-versions/<int:version_id>/delete")
def report_version_delete(version_id: int):
    version = repo.get_report_version(get_db(), version_id)
    if version is None:
        abort(404)
    repo.delete_report_version(get_db(), version)
    flash("Version removed from the history.", "success")
    return redirect(url_for("web.report_detail", report_id=version["report_id"], _anchor="versions"))


# ---------------------------------------------------------------- export --

@bp.get("/reports/<int:report_id>/preview")
def report_preview(report_id: int):
    """The real PDF (LaTeX template), shown inline in the browser's PDF viewer."""
    return report_export(report_id, "pdf", inline=True)


@bp.get("/reports/<int:report_id>/export/<fmt>")
def report_export(report_id: int, fmt: str, inline: bool = False):
    if fmt not in ("html", "md", "json", "pdf", "tex"):
        abort(404)
    try:
        rendered = export.render_download(get_db(), report_id, fmt)
    except latex.LatexError as exc:
        current_app.logger.warning("PDF export of report %s failed: %s", report_id, exc)
        return render_template("export/pdf_error.html", report=_report_or_404(report_id), error=str(exc),
                               log=exc.log), 500
    if rendered is None:
        abort(404)
    body, mimetype, filename = rendered
    response = Response(body, mimetype=mimetype)
    disposition = "inline" if inline else "attachment"
    response.headers["Content-Disposition"] = f'{disposition}; filename="{filename}"'
    if fmt == "pdf":
        # the browser's own PDF viewer renders it; the HTML page policy would block that viewer
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'self'"
    if fmt == "html":
        # exported file is opened from disk; this header only matters if opened via the app
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'"
        )
    return response


@bp.route("/import", methods=["GET", "POST"])
def report_import():
    if request.method == "GET":
        return render_template("import.html", errors=[])
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return render_template("import.html", errors=["Choose a .json export file."]), 422
    try:
        payload = json.loads(upload.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return render_template("import.html", errors=["File is not valid UTF-8 JSON."]), 422
    try:
        report_id = export.import_json(get_db(), payload)
    except export.ImportError_ as exc:
        return render_template("import.html", errors=exc.errors), 422
    flash("Report imported.", "success")
    return redirect(url_for("web.report_detail", report_id=report_id))


# --------------------------------------------------------------- settings --

@bp.get("/settings")
def settings():
    return _settings_page({k: str(v) for k, v in repo.get_settings(get_db()).items()}, {})


def _id_examples(id_format: str, start: int, prefix: str) -> list[str]:
    if ids.template_error(id_format):
        return []
    return [ids.render(id_format, prefix, start + i, None) for i in range(3)]


def _settings_page(values: dict, errors: dict, status: int = 200, *,
                   ai_values: dict | None = None, ai_errors: dict | None = None):
    current = repo.get_settings(get_db())
    return (
        render_template(
            "settings.html",
            api_token=current_app.config["API_TOKEN"],
            data_dir=current_app.config["DATA_DIR"],
            api_base=request.host_url.rstrip("/") + "/api/v1",
            values=values,
            errors=errors,
            id_examples=_id_examples(current["id_format"], current["id_start"], current["default_prefix"]),
            custom_latex=repo.get_latex_template(get_db()) is not None,
            brand=repo.get_brand(get_db()),
            label_rows=_label_rows(),
            label_overrides=repo.get_label_overrides(get_db()),
            latex_engine=latex.find_engine(),
            ai_values=ai_values if ai_values is not None else repo.get_ai_settings(get_db()),
            ai_errors=ai_errors or {},
        ),
        status,
    )


@bp.post("/settings/finding-ids")
def settings_finding_ids():
    data, errors = validate_settings(request.form)
    if errors:
        return _settings_page(request.form, errors, 422)
    repo.save_settings(get_db(), data)
    flash("Finding ID settings saved. Existing reports show the new format right away.", "success")
    return redirect(url_for("web.settings", _anchor="finding-ids"))


@bp.get("/settings/latex-template/<which>")
def settings_latex_download(which: str):
    if which == "default":
        source = latex.default_template()
    elif which == "current":
        source = repo.get_latex_template(get_db()) or latex.default_template()
    else:
        abort(404)
    response = Response(source, mimetype="text/x-tex")
    response.headers["Content-Disposition"] = f'attachment; filename="ptreport-{which}-template.tex"'
    return response


@bp.post("/settings/latex-template")
def settings_latex_upload():
    upload = request.files.get("file")
    raw = upload.read(latex.MAX_TEMPLATE_BYTES + 1) if upload and upload.filename else b""
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        source = None
    error = "Choose a .tex file (UTF-8)." if not source else latex.template_problem(source, latex.sample_context())
    if error:
        flash(f"Template not saved: {error}", "error")
        return redirect(url_for("web.settings", _anchor="pdf-template"))
    repo.set_latex_template(get_db(), source)
    flash("Custom LaTeX template saved. PDF exports use it from now on.", "success")
    return redirect(url_for("web.settings", _anchor="pdf-template"))


@bp.post("/settings/latex-template/reset")
def settings_latex_reset():
    repo.set_latex_template(get_db(), None)
    flash("Back to the default LaTeX template.", "success")
    return redirect(url_for("web.settings", _anchor="pdf-template"))


def label_keys() -> list[tuple[str, str]]:
    """(override key, English default) for every label a user can rename."""
    keys = [(f"sev.{k}", v) for k, v in SEVERITY_LABELS["en"].items()]
    keys += [(f"status.{k}", v) for k, v in STATUS_LABELS["en"].items()]
    keys += [(f"conf.{k}", v) for k, v in CONFIDENCE_LABELS["en"].items()]
    keys += list(REPORT_LABELS["en"].items())
    return keys


def _label_rows() -> list[tuple[str, str, str]]:
    pl = labels_for("pl")

    def pl_default(key: str) -> str:
        group, _, name = key.partition(".")
        return pl[group][name] if name and group in ("sev", "status", "conf") else pl["L"].get(key, "")

    return [(key, en, pl_default(key)) for key, en in label_keys()]


# ------------------------------------------------------------- CWE library --

@bp.get("/cwe-library")
def cwe_library():
    q = request.args.get("q", "").strip()[:100]
    own = repo.list_cwe_library(get_db())
    results = cwe_search(q) if q else []
    return render_template("cwe_library.html", q=q, results=results, own=own,
                           own_rows=[(cwe, cwe_name(cwe)) for cwe in own],
                           use_mitre=repo.use_mitre_text(get_db()), version=cwe_catalogue_version(),
                           total=len(cwe_choices()))


@bp.route("/cwe-library/<int:number>", methods=["GET", "POST"])
def cwe_library_entry(number: int):
    cwe = f"CWE-{number}"
    reference = cwe_reference(cwe)
    if request.method == "POST":
        data, errors = validate_cwe_note({"cwe": cwe, "description": request.form.get("description", ""),
                                          "mitigation": request.form.get("mitigation", "")})
        if errors:
            flash("Not saved: " + " ".join(errors.values()), "error")
        else:
            repo.save_cwe_library(get_db(), cwe, data["description"], data["mitigation"])
            flash(f"{cwe} saved in the CWE library.", "success")
            return redirect(url_for("web.cwe_library_entry", number=number))
    own = repo.get_cwe_library(get_db(), cwe) or {"description": "", "mitigation": ""}
    return render_template("cwe_entry.html", cwe=cwe, number=number, reference=reference, own=own)


@bp.post("/cwe-library/settings")
def cwe_library_settings():
    values = request.form.getlist("use_mitre")
    repo.save_settings(get_db(), {"cwe_use_mitre": "1" if "1" in values else "0"})
    flash("CWE library settings saved.", "success")
    return redirect(url_for("web.cwe_library"))


@bp.post("/settings/labels")
def settings_labels():
    keys = dict(label_keys())
    overrides: dict[str, dict[str, str]] = {"en": {}, "pl": {}}
    for field, value in request.form.items():
        lang, _, key = field.partition(":")
        if lang not in overrides or key not in keys:
            continue
        value = value.strip()
        if len(value) > 80 or "\n" in value or "\r" in value:
            flash(f"Label {key} ({lang}) must be one line of at most 80 characters.", "error")
            return redirect(url_for("web.settings", _anchor="labels"))
        if value:
            overrides[lang][key] = value
    repo.set_label_overrides(get_db(), overrides)
    flash("Report labels saved.", "success")
    return redirect(url_for("web.settings", _anchor="labels"))


@bp.post("/settings/branding")
def settings_branding():
    color, error = validate_brand_color(request.form.get("brand_color", ""))
    if error:
        flash(error, "error")
        return redirect(url_for("web.settings", _anchor="branding"))
    repo.set_brand_color(get_db(), color)
    upload = request.files.get("logo")
    if upload and upload.filename:
        clean, errors = validate_attachment("", upload.read(IMAGE_MAX_BYTES + 1))
        if errors:
            flash("Logo not saved: " + errors["file"], "error")
            return redirect(url_for("web.settings", _anchor="branding"))
        repo.set_brand_logo(get_db(), clean["mime"], clean["data"])
    flash("Branding saved.", "success")
    return redirect(url_for("web.settings", _anchor="branding"))


@bp.post("/settings/branding/logo/delete")
def settings_branding_logo_delete():
    repo.set_brand_logo(get_db(), None, None)
    flash("Logo removed.", "success")
    return redirect(url_for("web.settings", _anchor="branding"))


@bp.get("/brand.css")
def brand_css():
    """The brand colour as a stylesheet, so pages under the strict CSP need no inline styles."""
    color = repo.get_brand(get_db())["color"]
    response = Response(f":root {{ --brand: #{color}; }}\n", mimetype="text/css")
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/settings/branding/logo")
def settings_branding_logo():
    logo = repo.get_brand(get_db())["logo"]
    if logo is None:
        abort(404)
    response = Response(logo["data"], mimetype=logo["mime"])
    response.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    return response


@bp.post("/settings/api-token")
def settings_regenerate_token():
    regenerate_api_token(current_app)
    flash("New API token generated. Update it in the Burp extension.", "success")
    return redirect(url_for("web.settings"))


# ------------------------------------------------------- writing assistant --

AI_FIELD_LABELS = {"description": "Description", "impact": "Impact", "technical_details": "Technical details",
                   "remediation": "Remediation"}
AI_MAX_BODY = 256 * 1024


def _ai_json(message: str, status: int):
    return jsonify(error=message), status


def _ai_bucket():
    bucket = current_app.extensions.get("ai_bucket")
    if bucket is None:
        bucket = ai.TokenBucket(current_app.config.get("AI_RATE_CAPACITY", 6),
                                current_app.config.get("AI_RATE_PER_SECOND", 1 / 10))
        current_app.extensions["ai_bucket"] = bucket
    return bucket


def _ai_payload() -> dict | None:
    if (request.content_length or 0) > AI_MAX_BODY:
        return None
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


@bp.post("/settings/ai")
def settings_ai():
    data, errors = validate_ai_settings(request.form)
    if errors:
        values = {"enabled": request.form.get("enabled") == "1", "url": request.form.get("url", ""),
                  "model": request.form.get("model", "")}
        return _settings_page({k: str(v) for k, v in repo.get_settings(get_db()).items()}, {}, 422,
                              ai_values=values, ai_errors=errors)
    repo.set_ai_settings(get_db(), data)
    flash("AI assistant " + ("enabled." if data["enabled"] else "settings saved (assistant is off)."), "success")
    return redirect(url_for("web.settings", _anchor="ai-assistant"))


def _ai_target_from_request() -> tuple:
    data = _ai_payload()
    if data is None:
        return None, _ai_json("Send a JSON object with url and model.", 400)
    url = data.get("url")
    model = data.get("model", "")
    if not isinstance(url, str) or not isinstance(model, str):
        return None, _ai_json("url and model must be text.", 400)
    url = ai.normalise_url(url)
    problem = ai.url_problem(url)
    if problem:
        return None, _ai_json(problem, 400)
    model = model.strip()
    if model and ai.model_problem(model):
        return None, _ai_json(ai.model_problem(model), 400)
    return url, model


@bp.post("/settings/ai/models")
def settings_ai_models():
    url, model = _ai_target_from_request()
    if url is None:
        return model
    try:
        models = ai.list_models(url)
    except ai.AiError as exc:
        return _ai_json(exc.message, exc.status)
    return jsonify(models=models)


@bp.post("/settings/ai/test")
def settings_ai_test():
    url, model = _ai_target_from_request()
    if url is None:
        return model
    try:
        message = ai.test_connection(url, model)
    except ai.AiError as exc:
        return _ai_json(exc.message, exc.status)
    return jsonify(message=message)


@bp.post("/ai/assist")
def ai_assist():
    settings = repo.get_ai_settings(get_db())
    if not settings["enabled"]:
        return _ai_json("The AI assistant is turned off. Enable it in Settings.", 404)
    data = _ai_payload()
    if data is None:
        return _ai_json("Request too large or not a JSON object.", 413 if (request.content_length or 0) > AI_MAX_BODY
                        else 400)
    report_id = data.get("report_id")
    if not isinstance(report_id, int) or isinstance(report_id, bool):
        return _ai_json("report_id is required.", 400)
    report = repo.get_report(get_db(), report_id)
    if report is None:
        return _ai_json("Report not found.", 404)
    field = data.get("field")
    action = data.get("action")
    if field not in ai.FIELDS:
        return _ai_json("Unknown field.", 400)
    if action not in ai.ACTIONS:
        return _ai_json("Unknown action.", 400)
    texts: dict[str, str] = {}
    for name in ("title", "cwe", "severity", *ai.CONTEXT_FIELDS):
        value = data.get(name, "")
        if not isinstance(value, str):
            return _ai_json(f"{name} must be text.", 400)
        limit = ai.MAX_TITLE_CHARS if name == "title" else 20 if name in ("cwe", "severity") else ai.MAX_FIELD_CHARS
        if len(value) > limit:
            if name in ai.CONTEXT_FIELDS and not (name == field and action != "draft"):
                value = value[:limit]  # other fields are only context: a long one is cut, not refused
            else:
                label = AI_FIELD_LABELS.get(name, name.capitalize())
                return _ai_json(f"{label} is too long for the assistant (at most {limit} characters).", 413)
        texts[name] = value.replace("\x00", "").strip()
    if action == "draft" and not texts["title"]:
        return _ai_json("Write the vulnerability title first: the draft is based on it.", 422)
    if action != "draft" and not texts[field]:
        return _ai_json(f"{AI_FIELD_LABELS[field]} is empty; there is nothing to work on.", 422)
    if not _ai_bucket().take():
        return _ai_json("Too many assistant requests. Wait a few seconds and try again.", 429)

    lang = report["language"] if report["language"] in ai.SYSTEM_PROMPT else "en"
    cwe = texts["cwe"].upper()
    if cwe and not cwe.startswith("CWE-"):
        cwe = "CWE-" + cwe
    severity = SEVERITY_LABELS[lang].get(texts["severity"], "") if texts["severity"] else ""
    req = ai.AssistRequest(field=field, action=action, report_language=lang, title=texts["title"],
                           cwe=cwe if cwe_name(cwe) else "", cwe_name=cwe_name(cwe) if cwe else "",
                           severity=severity, fields={k: texts[k] for k in ai.CONTEXT_FIELDS})
    current_app.logger.info("AI assist: action=%s field=%s model=%s", action, field, settings["model"])
    try:
        text = ai.chat(settings["url"], settings["model"], ai.build_messages(req),
                       timeout=current_app.config.get("AI_TIMEOUT", ai.TIMEOUT_SECONDS))
    except ai.AiError as exc:
        return _ai_json(exc.message, exc.status)
    return jsonify(text=text, field=field, action=action)


# ------------------------------------------------------------------- cvss --

@bp.get("/cvss/score")
def cvss_score():
    vector = request.args.get("vector", "")
    try:
        return jsonify(score_vector(vector).as_dict())
    except CvssInvalid as exc:
        return jsonify(valid=False, error=str(exc)), 200


# ------------------------------------------------------- finding templates --

def _template_or_404(template_id: int) -> dict:
    template = repo.get_template(get_db(), template_id)
    if template is None:
        abort(404)
    return template


@bp.get("/templates")
def templates_list():
    query = request.args.get("q", "").strip()[:100]
    language = request.args.get("language", "")
    language = language if language in LANGUAGES else ""
    reports = repo.list_reports(get_db())
    return render_template("templates/list.html", templates=repo.list_templates(get_db(), query, language),
                           query=query, language=language, languages=LANGUAGES, reports=reports,
                           section="templates")


def _template_form(template: dict | None, values: dict, errors: dict, status: int = 200):
    return (
        render_template("templates/form.html", template=template, values=values, errors=errors,
                        languages=LANGUAGES, severities=SEVERITIES, cwe_choices=cwe_choices(),
                        cvss_defs=METRIC_DEFINITIONS, finding=None, section="templates"),
        status,
    )


@bp.route("/templates/new", methods=["GET", "POST"])
def template_new():
    if request.method == "GET":
        return _template_form(None, {"cvss_version": "3.1",
                                     "language": repo.get_settings(get_db())["default_language"]}, {})
    data, errors = validate_template(request.form)
    if errors:
        return _template_form(None, request.form, errors, 422)
    repo.create_template(get_db(), data)
    flash("Template created.", "success")
    return redirect(url_for("web.templates_list"))


@bp.route("/templates/<int:template_id>/edit", methods=["GET", "POST"])
def template_edit(template_id: int):
    template = _template_or_404(template_id)
    if request.method == "GET":
        return _template_form(template, template, {})
    data, errors = validate_template(request.form)
    if errors:
        return _template_form(template, request.form, errors, 422)
    repo.update_template(get_db(), template, data)
    flash("Template saved.", "success")
    return redirect(url_for("web.templates_list"))


@bp.post("/templates/<int:template_id>/delete")
def template_delete(template_id: int):
    repo.delete_template(get_db(), _template_or_404(template_id))
    flash("Template deleted.", "success")
    return redirect(url_for("web.templates_list"))


@bp.post("/findings/<int:finding_id>/save-as-template")
def finding_save_as_template(finding_id: int):
    finding, report = _finding_or_404(finding_id)
    values = {f: finding[f] or "" for f in TEMPLATE_FIELDS}
    values["language"] = report["language"]
    data, errors = validate_template(values)
    if errors:
        flash("This finding cannot be saved as a template: " + "; ".join(errors.values()), "error")
    else:
        repo.create_template(get_db(), data)
        flash("Saved to the template library.", "success")
    return redirect(url_for("web.finding_edit", finding_id=finding_id))


@bp.get("/templates/export")
def templates_export():
    rows = [{c: t[c] for c in repo.TEMPLATE_COLUMNS} for t in repo.list_templates(get_db())]
    body = json.dumps({"format": "ptreport-templates", "version": 1, "templates": rows}, ensure_ascii=False, indent=1)
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": 'attachment; filename="ptreport-templates.json"'})


@bp.post("/templates/import")
def templates_import():
    upload = request.files.get("file")
    try:
        doc = json.loads(upload.read().decode("utf-8")) if upload else None
    except (UnicodeDecodeError, ValueError):
        doc = None
    items = doc.get("templates") if isinstance(doc, dict) else None
    if not isinstance(items, list) or not items or len(items) > repo.MAX_TEMPLATES_IMPORT \
            or not all(isinstance(i, dict) for i in items):
        flash("Choose a template library JSON file exported from ptreport.", "error")
        return redirect(url_for("web.templates_list"), 303)
    cleaned, problems = [], []
    for n, item in enumerate(items, start=1):
        clean, errors = validate_template(item)
        if errors:
            problems.append(f"#{n}: " + "; ".join(errors.values()))
        cleaned.append(clean)
    if problems:
        flash("Nothing imported. " + " | ".join(problems[:5]), "error")
        return redirect(url_for("web.templates_list"), 303)
    with transaction(get_db()):
        for clean in cleaned:
            repo.create_template(get_db(), clean)
    flash(f"Imported {len(cleaned)} template(s).", "success")
    return redirect(url_for("web.templates_list"))


# ------------------------------------------------------------------ retest --

@bp.post("/reports/<int:report_id>/retest")
def report_retest(report_id: int):
    _report_or_404(report_id)
    new_id = repo.clone_report(get_db(), report_id, retest=True)
    flash("Retest report created. Set the retest result on each finding.", "success")
    return redirect(url_for("web.report_detail", report_id=new_id))


@bp.post("/reports/<int:report_id>/duplicate")
def report_duplicate(report_id: int):
    _report_or_404(report_id)
    new_id = repo.clone_report(get_db(), report_id, retest=False)
    flash("Report duplicated.", "success")
    return redirect(url_for("web.report_detail", report_id=new_id))


# ---------------------------------------------------------- scanner import --

SCANNER_LABELS = importers.LABELS


def _scan_form(report: dict, errors: list[str], status: int = 200):
    return render_template("reports/scan_import.html", report=report, errors=errors, formats=importers.FORMATS,
                           format_labels=SCANNER_LABELS), status


@bp.route("/reports/<int:report_id>/scan-import", methods=["GET", "POST"])
def scan_import(report_id: int):
    report = _report_or_404(report_id)
    if request.method == "GET":
        return _scan_form(report, [])
    upload = request.files.get("file")
    data = upload.read(importers.MAX_BYTES + 1) if upload else b""
    if not data:
        return _scan_form(report, ["Choose a scanner report file."], 422)
    if len(data) > importers.MAX_BYTES:
        return _scan_form(report, [f"The file is larger than {importers.MAX_BYTES // (1024 * 1024)} MB."], 422)
    fmt = request.form.get("format", "")
    if fmt and fmt not in importers.FORMATS:
        return _scan_form(report, ["Unknown format."], 422)
    try:
        parsed = importers.parse(data, fmt or None, include_info=request.form.get("include_info") == "1")
    except importers.ImportError_ as exc:
        return _scan_form(report, [str(exc)], 422)
    cleaned = importers.clean(parsed)
    if not cleaned["targets"] and not cleaned["findings"]:
        return _scan_form(report, ["Nothing to import: the file has no hosts or issues"
                                   + (" (informational issues were left out)" if fmt != "nmap" else "") + "."]
                          + cleaned["warnings"][:10], 422)
    filename = (upload.filename or "")[:200]
    import_id = repo.stage_scan_import(get_db(), report_id, cleaned["format"], filename, cleaned)
    return redirect(url_for("web.scan_import_review", import_id=import_id))


def _staged_or_404(import_id: int) -> tuple[dict, dict]:
    staged = repo.get_scan_import(get_db(), import_id)
    if staged is None:
        abort(404)
    return staged, _report_or_404(staged["report_id"])


@bp.get("/scan-imports/<int:import_id>")
def scan_import_review(import_id: int):
    staged, report = _staged_or_404(import_id)
    existing = {repo.target_match_key(t) for t in repo.list_targets(get_db(), report["id"])}
    names = {t["key"]: t["name"] for t in staged["parsed"]["targets"]}
    return render_template("reports/scan_review.html", report=report, staged=staged, parsed=staged["parsed"],
                           format_label=SCANNER_LABELS.get(staged["format"], staged["format"]),
                           existing={t["key"] for t in staged["parsed"]["targets"]
                                     if repo.target_match_key(t) in existing},
                           target_names=names, severities=SEVERITIES)


@bp.post("/scan-imports/<int:import_id>")
def scan_import_apply(import_id: int):
    staged, report = _staged_or_404(import_id)
    if request.form.get("discard"):
        repo.delete_scan_import(get_db(), import_id)
        flash("Scanner import discarded.", "success")
        return redirect(url_for("web.report_detail", report_id=report["id"]))
    target_keys = set(request.form.getlist("target"))
    finding_keys = set(request.form.getlist("finding"))
    if not target_keys and not finding_keys:
        flash("Select at least one target or finding to import.", "error")
        return redirect(url_for("web.scan_import_review", import_id=import_id))
    created, reused, n_findings = repo.apply_scan_import(get_db(), staged, target_keys, finding_keys)
    flash(f"Imported {n_findings} finding(s) and {created} new target(s)"
          + (f"; {reused} target(s) already in the report were reused" if reused else "") + ".", "success")
    return redirect(url_for("web.report_detail", report_id=report["id"], _anchor="findings"))


# ------------------------------------------------------------------- notes --

def _note_or_404(note_id: int) -> tuple[dict, dict]:
    note = repo.get_note(get_db(), note_id)
    if note is None:
        abort(404)
    return note, _report_or_404(note["report_id"])


_EXCERPT_NOISE = re.compile(r"^\s*(?:#{1,3}\s+|[-*•]\s+|`{3,}.*$|\|?(?:\s*:?-{3,}:?\s*\|)+\s*$)")


def _note_excerpt(body: str, limit: int = 140) -> str:
    """First words of a note without its mark-up, for the list."""
    words = []
    for line in body.splitlines():
        line = _EXCERPT_NOISE.sub("", line)
        line = line.replace("**", "").replace("`", "").strip(" |")
        line = re.sub(r"\s*\|\s*", " · ", line)
        if line:
            words.append(line)
        if sum(len(w) for w in words) > limit:
            break
    text = " ".join(words)
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def _notes_page(report: dict, current: dict | None, values: dict, errors: dict, status: int = 200):
    query = request.args.get("q", "").strip()[:100]
    notes = repo.list_notes(get_db(), report["id"], query)
    for n in notes:
        n["excerpt"] = _note_excerpt(n["body"])
    return render_template("reports/notes.html", report=report, notes=notes,
                           total=repo.count_notes(get_db(), report["id"]), current=current, values=values,
                           errors=errors, query=query), status


@bp.get("/reports/<int:report_id>/notes")
def notes(report_id: int):
    report = _report_or_404(report_id)
    note_id = request.args.get("note", "")
    current = None
    if note_id.isdigit():
        current = repo.get_note(get_db(), int(note_id))
        if current is None or current["report_id"] != report_id:
            abort(404)
    elif note_id != "new":
        first = repo.list_notes(get_db(), report_id)
        current = first[0] if first else None
    return _notes_page(report, current, current or {}, {})


@bp.post("/reports/<int:report_id>/notes")
def note_new(report_id: int):
    report = _report_or_404(report_id)
    data, errors = validate_note(request.form)
    if errors:
        return _notes_page(report, None, request.form, errors, 422)
    note_id = repo.create_note(get_db(), report_id, data)
    flash("Note created.", "success")
    return redirect(url_for("web.notes", report_id=report_id, note=note_id))


@bp.post("/notes/<int:note_id>/edit")
def note_edit(note_id: int):
    note, report = _note_or_404(note_id)
    data, errors = validate_note(request.form)
    if errors:
        return _notes_page(report, note, request.form, errors, 422)
    repo.update_note(get_db(), note, data)
    flash("Note saved.", "success")
    return redirect(url_for("web.notes", report_id=report["id"], note=note_id))


@bp.post("/notes/<int:note_id>/delete")
def note_delete(note_id: int):
    note, report = _note_or_404(note_id)
    repo.delete_note(get_db(), note)
    flash("Note deleted.", "success")
    return redirect(url_for("web.notes", report_id=report["id"]))


# ------------------------------------------------------------ burp extension --

BURP_JAR = "data/ptreport-burp.jar"


@bp.get("/downloads/ptreport-burp.jar")
def burp_extension_download():
    try:
        with current_app.open_resource(BURP_JAR) as fh:
            data = fh.read()
    except FileNotFoundError:
        abort(404, description="The Burp extension is not bundled with this build. Run burp-extension/build.sh.")
    return Response(data, mimetype="application/java-archive",
                    headers={"Content-Disposition": 'attachment; filename="ptreport-burp.jar"',
                             "Cache-Control": "no-store"})
