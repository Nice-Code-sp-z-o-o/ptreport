"""JSON API v1 (bearer-token protected). Primary consumer: the Burp extension."""

from __future__ import annotations

import base64
import binascii

from flask import Blueprint, abort, current_app, jsonify, request, url_for

from ptreport import __version__, repo
from ptreport.cwe import catalogue_version as cwe_catalogue_version
from ptreport.cwe import cwe_choices
from ptreport.cwe import search as cwe_search
from ptreport.db import get_db
from ptreport.security import require_api_token
from ptreport.validation import (
    IMAGE_MAX_PER_FINDING,
    validate_attachment,
    validate_evidence,
    validate_finding,
    validate_note,
    validate_target,
)

bp = Blueprint("api", __name__, url_prefix="/api/v1")
bp.before_request(require_api_token)


def _json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description="Request body must be a JSON object.")
    return data


def _unprocessable(errors: dict):
    return jsonify(error="validation_failed", errors=errors), 422


def _report(report_id: int) -> dict:
    report = repo.get_report(get_db(), report_id)
    if report is None:
        abort(404, description="Report not found.")
    return report


def _finding_out(report: dict, f: dict) -> dict:
    out = {k: v for k, v in f.items() if k not in ("evidence", "targets", "attachments", "severity_manual")}
    out["display_id"] = repo.finding_display_id(report, f, repo.get_settings(get_db()))
    out["url"] = url_for("web.finding_edit", finding_id=f["id"], _external=True)
    if "targets" in f:
        out["target_ids"] = [t["id"] for t in f["targets"]]
    out["evidence_count"] = len(f.get("evidence", []))
    out["screenshot_count"] = len(f.get("attachments", []))
    return out


@bp.get("/ping")
def ping():
    return jsonify(app="ptreport", version=__version__, api="v1")


@bp.get("/reports")
def reports():
    rows = repo.list_reports(get_db())
    return jsonify(reports=[
        {k: r[k] for k in ("id", "title", "client_name", "finding_prefix", "updated_at",
                            "finding_count", "target_count")}
        for r in rows
    ])


@bp.get("/reports/<int:report_id>")
def report(report_id: int):
    r = _report(report_id)
    return jsonify(report=r)


@bp.get("/reports/<int:report_id>/targets")
def targets(report_id: int):
    _report(report_id)
    return jsonify(targets=repo.list_targets(get_db(), report_id))


@bp.post("/reports/<int:report_id>/targets")
def target_create(report_id: int):
    _report(report_id)
    data, errors = validate_target(_json_body())
    if errors:
        return _unprocessable(errors)
    target_id = repo.create_target(get_db(), report_id, data)
    return jsonify(target=repo.get_target(get_db(), target_id)), 201


@bp.get("/reports/<int:report_id>/findings")
def findings(report_id: int):
    r = _report(report_id)
    return jsonify(findings=[_finding_out(r, f) for f in repo.list_findings(get_db(), report_id)])


@bp.post("/reports/<int:report_id>/findings")
def finding_create(report_id: int):
    r = _report(report_id)
    body = _json_body()
    data, errors = validate_finding(body)
    if "target_ids" not in errors and repo.foreign_target_ids(get_db(), report_id, data.get("target_ids", [])):
        errors["target_ids"] = "Targets must belong to this report."
    if "external_id" not in errors and repo.external_id_taken(get_db(), report_id, data.get("external_id", "")):
        errors["external_id"] = "Another finding in this report already uses this ID."
    ev_in = body.get("evidence") or []
    if not isinstance(ev_in, list):
        errors["evidence"] = "Evidence must be a list."
        ev_in = []
    evidence = []
    for i, e in enumerate(ev_in):
        if not isinstance(e, dict):
            errors[f"evidence[{i}]"] = "Must be an object."
            continue
        ev_clean, ev_errors = validate_evidence({**e, "source": e.get("source") or "burp"})
        for field, msg in ev_errors.items():
            errors[f"evidence[{i}].{field}"] = msg
        evidence.append(ev_clean)
    if errors:
        return _unprocessable(errors)
    conn = get_db()
    finding_id = repo.create_finding(conn, report_id, data)
    finding = repo.get_finding(conn, finding_id)
    for ev in evidence:
        repo.create_evidence(conn, finding, ev)
    finding = repo.get_finding(conn, finding_id)
    current_app.logger.info("API: finding %s created in report %s", finding_id, report_id)
    return jsonify(finding=_finding_out(r, finding)), 201


@bp.get("/findings/<int:finding_id>")
def finding(finding_id: int):
    f = repo.get_finding(get_db(), finding_id)
    if f is None:
        abort(404, description="Finding not found.")
    r = _report(f["report_id"])
    out = _finding_out(r, f)
    out["evidence"] = f["evidence"]
    return jsonify(finding=out)


@bp.post("/findings/<int:finding_id>/evidence")
def evidence_create(finding_id: int):
    f = repo.get_finding(get_db(), finding_id)
    if f is None:
        abort(404, description="Finding not found.")
    body = _json_body()
    data, errors = validate_evidence({**body, "source": body.get("source") or "burp"})
    if errors:
        return _unprocessable(errors)
    evidence_id = repo.create_evidence(get_db(), f, data)
    return jsonify(evidence=repo.get_evidence(get_db(), evidence_id)), 201


@bp.post("/findings/<int:finding_id>/attachments")
def attachment_create(finding_id: int):
    """Add a screenshot: {"caption": "...", "data_base64": "<PNG/JPEG/GIF/WebP>"}."""
    f = repo.get_finding(get_db(), finding_id)
    if f is None:
        abort(404, description="Finding not found.")
    body = _json_body()
    raw = None
    if isinstance(body.get("data_base64"), str):
        try:
            raw = base64.b64decode(body["data_base64"], validate=True)
        except (binascii.Error, ValueError):
            return _unprocessable({"data_base64": "Not valid base64."})
    data, errors = validate_attachment(body.get("caption", ""), raw)
    if not errors and repo.count_attachments(get_db(), finding_id) >= IMAGE_MAX_PER_FINDING:
        errors["file"] = f"A finding can have at most {IMAGE_MAX_PER_FINDING} screenshots."
    if errors:
        return _unprocessable(errors)
    attachment_id = repo.create_attachment(get_db(), f, data)
    return jsonify(attachment=repo.get_attachment(get_db(), attachment_id)), 201


@bp.get("/templates")
def templates():
    """Finding template library; ?language=en|pl and ?q=<text> filter it."""
    language = request.args.get("language", "")
    rows = repo.list_templates(get_db(), request.args.get("q", "").strip()[:100],
                               language if language in ("en", "pl") else "")
    return jsonify(templates=rows)


@bp.get("/reports/<int:report_id>/notes")
def notes(report_id: int):
    _report(report_id)
    return jsonify(notes=repo.list_notes(get_db(), report_id, request.args.get("q", "").strip()[:100]))


@bp.post("/reports/<int:report_id>/notes")
def note_create(report_id: int):
    """Add a working note: {"title": "...", "body": "...", "pinned": false}."""
    _report(report_id)
    data, errors = validate_note(_json_body())
    if errors:
        return _unprocessable(errors)
    note_id = repo.create_note(get_db(), report_id, data)
    return jsonify(note=repo.get_note(get_db(), note_id)), 201


@bp.get("/cwe")
def cwe_list():
    """The bundled MITRE CWE catalogue ({"id": "CWE-79", "name": "..."}); ?q= searches number, name, description."""
    query = request.args.get("q", "").strip()[:100]
    rows = cwe_search(query) if query else cwe_choices()
    return jsonify(version=cwe_catalogue_version(), cwe=[{"id": i, "name": n} for i, n in rows])
