"""JSON API v1 (bearer-token protected). Primary consumer: the Burp extension."""

from __future__ import annotations

import base64
import binascii

from flask import Blueprint, Response, abort, current_app, g, jsonify, request, url_for

from ptreport import __version__, ai, proposals, repo, scope
from ptreport.cwe import catalogue_version as cwe_catalogue_version
from ptreport.cwe import cwe_choices
from ptreport.cwe import search as cwe_search
from ptreport.db import get_db, transaction
from ptreport.security import FULL_ACCESS, require_api_token
from ptreport.validation import (
    IMAGE_MAX_PER_FINDING,
    validate_uploads,
    validate_attachment,
    validate_code_evidence,
    validate_evidence,
    validate_finding,
    validate_note,
    validate_target,
)

bp = Blueprint("api", __name__, url_prefix="/api/v1")
bp.before_request(require_api_token)

# What an integration token (Settings -> Integrations) may call. Everything else needs the main API token.
ENDPOINT_SCOPES = {
    "api.ping": "",
    "api.reports": "read", "api.report": "read", "api.targets": "read", "api.findings": "read",
    "api.finding": "read", "api.templates": "read", "api.cwe_list": "read", "api.scope_out": "read",
    "api.proposals_list": "read",
    "api.proposals_create": "propose",
}
PROPOSAL_RATE_CAPACITY = 400   # proposals per token in a burst
PROPOSAL_RATE_PER_SECOND = 2


@bp.before_request
def _check_scope():
    scopes = getattr(g, "api_scopes", None)
    if scopes is None or scopes == FULL_ACCESS:
        return None
    needed = ENDPOINT_SCOPES.get(request.endpoint or "")
    if needed is None or (needed and needed not in scopes):
        current_app.logger.warning("Integration token %s denied for %s", g.api_token_id, request.endpoint)
        return jsonify(error="forbidden", message="This integration token does not have the scope for this "
                                                  "endpoint." + (f" Needed: {needed}." if needed else "")), 403
    return None


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
    out = {k: v for k, v in f.items()
           if k not in ("evidence", "targets", "attachments", "files", "code_evidence", "severity_manual")}
    out["display_id"] = repo.finding_display_id(report, f, repo.get_settings(get_db()))
    out["url"] = url_for("web.finding_edit", finding_id=f["id"], _external=True)
    if "targets" in f:
        out["target_ids"] = [t["id"] for t in f["targets"]]
    out["evidence_count"] = len(f.get("evidence", []))
    out["screenshot_count"] = len(f.get("attachments", []))
    out["file_count"] = len(f.get("files", []))
    out["code_evidence_count"] = len(f.get("code_evidence", []))
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


@bp.get("/reports/<int:report_id>/scope")
def scope_out(report_id: int):
    """The engagement scope for agents: JSON (default) or a Markdown brief with ?format=md."""
    _report(report_id)
    doc = scope.scope_document(get_db(), report_id)
    fmt = request.args.get("format", "json")
    if fmt in ("md", "markdown"):
        return Response(scope.to_markdown(doc), mimetype="text/markdown")
    if fmt != "json":
        return _unprocessable({"format": "Format must be json or md."})
    return jsonify(scope=doc)


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
    out["code_evidence"] = f["code_evidence"]
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


@bp.post("/findings/<int:finding_id>/code-evidence")
def code_evidence_create(finding_id: int):
    """Add code evidence: {"title", "location", "language": c|cpp|asm|pseudo|java|python|text, "code", "note"}."""
    f = _finding(finding_id)
    data, errors = validate_code_evidence(_json_body())
    if errors:
        return _unprocessable(errors)
    code_id = repo.create_code_evidence(get_db(), f, data)
    return jsonify(code_evidence=repo.get_code_evidence(get_db(), code_id)), 201


def _finding(finding_id: int) -> dict:
    f = repo.get_finding(get_db(), finding_id)
    if f is None:
        abort(404, description="Finding not found.")
    return f


def _file_out(x: dict) -> dict:
    return {**x, "download_url": url_for("web.file_download", file_id=x["id"], _external=True)}


@bp.get("/findings/<int:finding_id>/files")
def files(finding_id: int):
    """Evidence files of a finding (metadata only: name, size, MIME type, SHA-256, description)."""
    f = _finding(finding_id)
    return jsonify(files=[_file_out(x) for x in f["files"]])


@bp.post("/findings/<int:finding_id>/files")
def file_create(finding_id: int):
    """Upload evidence files: multipart/form-data with one or more "file" parts and an optional "description".
    Same validation and limits as the web UI; the SHA-256 is computed by the server."""
    f = _finding(finding_id)
    if not request.mimetype.startswith("multipart/form-data"):
        abort(415, description="Send the files as multipart/form-data.")
    cleaned, errors = validate_uploads(request.files.getlist("file") + request.files.getlist("files"),
                                       request.form.get("description", ""), repo.file_usage(get_db(), finding_id))
    if errors:
        return _unprocessable(errors)
    with transaction(get_db()):
        new_ids = [repo.create_file(get_db(), f, clean) for clean in cleaned]
    return jsonify(files=[_file_out(repo.get_file(get_db(), i)) for i in new_ids]), 201


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


# ------------------------------------------------------------ AI proposals --

def _proposal_bucket(key: str) -> ai.TokenBucket:
    buckets = current_app.extensions.setdefault("proposal_buckets", {})
    if key not in buckets:
        buckets[key] = ai.TokenBucket(current_app.config.get("PROPOSAL_RATE_CAPACITY", PROPOSAL_RATE_CAPACITY),
                                      current_app.config.get("PROPOSAL_RATE_PER_SECOND", PROPOSAL_RATE_PER_SECOND))
    return buckets[key]


@bp.get("/reports/<int:report_id>/proposals")
def proposals_list(report_id: int):
    """Proposals of a report (?status=pending|accepted|rejected|merged); file contents are left out."""
    _report(report_id)
    status = request.args.get("status", "")
    if status and status not in proposals.STATUSES:
        return _unprocessable({"status": f"Status must be one of: {', '.join(proposals.STATUSES)}."})
    rows = repo.list_proposals(get_db(), report_id, status)
    return jsonify(proposals=[proposals.public(p) for p in rows])


@bp.post("/reports/<int:report_id>/proposals")
def proposals_create(report_id: int):
    """Queue AI proposals for human review: one proposal object, a list (max 200), or the
    ``ptreport-proposals`` envelope. Nothing reaches the report before someone accepts it in the AI queue."""
    _report(report_id)
    body = request.get_json(silent=True)
    if not isinstance(body, (dict, list)):
        abort(400, description="Request body must be JSON (a proposal object or a list).")
    try:
        items = proposals.normalise_items(body)
    except proposals.ProposalError as exc:
        return _unprocessable(exc.errors)
    if len(items) > proposals.MAX_PER_REQUEST:
        return _unprocessable({"proposals": f"At most {proposals.MAX_PER_REQUEST} proposals at once."})
    if not _proposal_bucket(str(g.api_token_id or "main")).take(max(1, len(items))):
        return jsonify(error="rate_limited", message="Too many proposals; slow down and try again."), 429
    try:
        ids = proposals.submit(get_db(), report_id, items, token_id=g.api_token_id)
    except proposals.ProposalError as exc:
        return _unprocessable(exc.errors)
    current_app.logger.info("API: %d AI proposal(s) queued for report %s (token %s)", len(ids), report_id,
                            g.api_token_id or "main")
    created = [proposals.public(repo.get_proposal(get_db(), i)) for i in ids]
    return jsonify(proposals=created, review_url=url_for("web.ai_queue", report_id=report_id, _external=True)), 201
