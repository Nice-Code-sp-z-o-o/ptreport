"""The AI intake queue: what agents send waits here until a human accepts it.

Agents (the MCP server, the ``/api/v1/reports/<id>/proposals`` endpoint, SARIF / ptai capsule / proposal JSON
imports) never write findings, evidence or retest results directly. They create *proposals*. A proposal is
validated with the same validators as manual input when it is created **and again when it is accepted**; an
accept, merge or reject is one transaction (all or nothing per proposal).

Proposal kinds (``ptreport proposal JSON v1``, documented in ``docs/integrations.md``):

* ``finding`` - a new finding with optional targets, HTTP evidence, code evidence and files;
* ``evidence`` / ``code`` / ``file`` - an HTTP request/response, a code snippet or a file for an existing finding;
* ``retest`` - an explicit retest result (fixed / partially fixed / not fixed / not tested) for a finding;
* ``target`` - a new target.

This module does not need a Flask app context, so the CLI and the MCP server share it with the web UI.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import json
import re
import sqlite3
from datetime import date
from typing import Any
from urllib.parse import urlsplit

from ptreport import repo
from ptreport.cvss_service import CvssInvalid, rating_for_score, score_vector
from ptreport.db import transaction
from ptreport.rendering import REPORT_LABELS, RETEST_LABELS
from ptreport.validation import (
    LONG,
    RETEST_RESULTS,
    SEVERITIES,
    Validator,
    check_file_quota,
    guess_file_type,
    validate_code_evidence,
    validate_evidence,
    validate_file,
    validate_finding,
    validate_target,
)

SCHEMA_FORMAT = "ptreport-proposals"
SCHEMA_VERSION = 1
KINDS = ("finding", "evidence", "code", "file", "retest", "target")
KIND_LABELS = {"finding": "Findings", "evidence": "HTTP evidence", "code": "Code evidence", "file": "Files",
               "retest": "Retest results", "target": "Targets"}
VERDICTS = ("verified", "candidate", "")
STATUSES = ("pending", "accepted", "rejected", "merged")
# verified -> the oracle confirmed it; candidate -> an unconfirmed lead (the app has no "candidate" confidence)
VERDICT_CONFIDENCE = {"verified": "certain", "candidate": "unknown"}
MAX_PER_REQUEST = 200
MAX_ITEMS = 50                      # targets / evidence / code snippets inside one finding proposal
MAX_FILES = 10                      # files inside one proposal
MAX_PAYLOAD_BYTES = 40 * 1024 * 1024   # one stored proposal (JSON, files as base64)
DUPLICATE_RATIO = 0.8
FINDING_TEXT_FIELDS = ("description", "impact", "technical_details", "poc", "remediation", "refs")
SEVERITY_ALIASES = {"informational": "info", "information": "info", "none": "info", "moderate": "medium",
                    "important": "high"}
_SOURCE_LIMITS = {"tool": 100, "version": 50, "run_id": 100, "model": 100}


class ProposalError(ValueError):
    """A proposal that cannot be created or applied; ``errors`` maps field -> message (safe to show)."""

    def __init__(self, errors: dict[str, str] | str):
        self.errors = {"proposal": errors} if isinstance(errors, str) else dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in self.errors.items()))


# ------------------------------------------------------------------ helpers --

def _prefixed(prefix: str, errors: dict) -> dict:
    return {f"{prefix}.{k}" if prefix else k: v for k, v in errors.items()}


def host_key(address: str) -> str:
    """Comparable host of an address: 'https://Shop.example:8443/x' -> 'shop.example:8443', '10.0.0.5' as is."""
    text = (address or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        try:
            parts = urlsplit(text)
            host = parts.hostname or ""
            port = parts.port
        except ValueError:
            return ""
        default = {"http": 80, "https": 443}.get(parts.scheme)
        return f"{host}:{port}" if port and port != default else host
    return text.split("/", 1)[0]


def target_from_address(address: str) -> dict:
    """A target for a bare address an agent sent: a URL becomes a web target named after its host."""
    address = (address or "").strip()
    if re.match(r"^https?://", address, re.IGNORECASE):
        try:
            parts = urlsplit(address)
            netloc = parts.netloc.rsplit("@", 1)[-1]
            origin = f"{parts.scheme.lower()}://{netloc}"
        except ValueError:
            return {"name": address[:200], "kind": "web", "address": address}
        return {"name": (netloc or address)[:200], "kind": "web", "address": origin}
    return {"name": address[:200], "kind": "host", "address": address}


def _code_file(location: str) -> str:
    """The file part of a code location ('src/auth.c:120 check_pw' -> 'auth.c')."""
    first = (location or "").strip().split()[0] if (location or "").strip() else ""
    first = re.sub(r"(:\d+(-\d+)?)+$", "", first)
    return first.replace("\\", "/").rsplit("/", 1)[-1].lower()


def origin_text(record: dict) -> str:
    """Provenance shown as the AI badge's tooltip: 'ptai 1.6.2 · run 7f3a · verified · model x'."""
    tool = " ".join(p for p in (record.get("source_tool") or "AI agent", record.get("source_version")) if p)
    parts = [tool]
    if record.get("run_id"):
        parts.append(f"run {record['run_id']}")
    if record.get("verdict"):
        parts.append(record["verdict"])
    if record.get("model"):
        parts.append(f"model {record['model']}")
    return " · ".join(parts)[:300]


def _source_label(record: dict) -> str:
    tool = record.get("source_tool") or "AI agent"
    return f"{tool} ({record['run_id']})" if record.get("run_id") else tool


# --------------------------------------------------------------- validation --

def _clean_source(raw: Any, defaults: dict | None) -> tuple[dict, dict]:
    defaults = defaults or {}
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        return {}, {"source": "Source must be an object (tool, version, run_id, model)."}
    merged = {k: raw.get(k) if raw.get(k) not in (None, "") else defaults.get(k, "") for k in _SOURCE_LIMITS}
    v = Validator({k: (str(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else x)
                   for k, x in merged.items()})
    for key, limit in _SOURCE_LIMITS.items():
        v.text(key, max_len=limit, label=f"Source {key.replace('_', ' ')}")
    return v.clean, _prefixed("source", v.errors)


def _clean_list(value: Any, name: str, limit: int) -> tuple[list, dict]:
    if value in (None, ""):
        return [], {}
    if not isinstance(value, list):
        return [], {name: "Must be a list."}
    if len(value) > limit:
        return [], {name: f"At most {limit} items."}
    return value, {}


def _clean_evidence_items(items: Any, name: str = "evidence") -> tuple[list[dict], dict]:
    items, errors = _clean_list(items, name, MAX_ITEMS)
    out = []
    for i, e in enumerate(items):
        if not isinstance(e, dict):
            errors[f"{name}[{i}]"] = "Must be an object."
            continue
        clean, errs = validate_evidence({**e, "source": "ai"})
        errors.update(_prefixed(f"{name}[{i}]", errs))
        out.append(clean)
    return out, errors


def _clean_code_items(items: Any, name: str = "code_evidence") -> tuple[list[dict], dict]:
    items, errors = _clean_list(items, name, MAX_ITEMS)
    out = []
    for i, c in enumerate(items):
        if not isinstance(c, dict):
            errors[f"{name}[{i}]"] = "Must be an object."
            continue
        clean, errs = validate_code_evidence(c)
        errors.update(_prefixed(f"{name}[{i}]", errs))
        out.append(clean)
    return out, errors


def _clean_file(item: Any) -> tuple[dict, dict]:
    """A file sent as base64: the evidence-file limits apply and the SHA-256 is computed here."""
    if not isinstance(item, dict) or not isinstance(item.get("data_base64"), str):
        return {}, {"data_base64": "A file needs filename and data_base64."}
    if len(item["data_base64"]) > (25 * 1024 * 1024) * 4 // 3 + 8:
        return {}, {"data_base64": "Files must be at most 25 MB."}
    try:
        raw = base64.b64decode(item["data_base64"], validate=True)
    except (binascii.Error, ValueError):
        return {}, {"data_base64": "Not valid base64."}
    clean, errors = validate_file(item.get("filename"), item.get("description", ""), raw)
    if errors:
        return {}, errors
    if item.get("sha256") not in (None, "") and str(item["sha256"]).lower() != clean["sha256"]:
        return {}, {"sha256": "SHA-256 does not match the file content."}
    return {"filename": clean["filename"], "description": clean.get("description", ""), "size": clean["size"],
            "sha256": clean["sha256"], "data_base64": item["data_base64"]}, {}


def _clean_files(items: Any) -> tuple[list[dict], dict]:
    items, errors = _clean_list(items, "files", MAX_FILES)
    out = []
    for i, x in enumerate(items):
        clean, errs = _clean_file(x)
        errors.update(_prefixed(f"files[{i}]", errs))
        if clean:
            out.append(clean)
    if not errors:
        quota = check_file_quota(0, 0, [x["size"] for x in out])
        if quota:
            errors["files"] = quota
    return out, errors


def _clean_targets(items: Any) -> tuple[list[dict], dict]:
    items, errors = _clean_list(items, "targets", MAX_ITEMS)
    out = []
    for i, t in enumerate(items):
        if isinstance(t, str):
            t = target_from_address(t)
        if not isinstance(t, dict):
            errors[f"targets[{i}]"] = "Must be an address or an object (name, kind, address)."
            continue
        if not t.get("name") and isinstance(t.get("address"), str):
            t = {**target_from_address(t["address"]), **{k: v for k, v in t.items() if v not in (None, "")}}
        clean, errs = validate_target(t)
        errors.update(_prefixed(f"targets[{i}]", errs))
        out.append(clean)
    return out, errors


def _clean_finding(data: dict, verdict: str) -> tuple[dict, dict]:
    raw = dict(data)
    severity = raw.get("severity")
    if isinstance(severity, str):
        raw["severity"] = SEVERITY_ALIASES.get(severity.strip().lower(), severity.strip().lower())
    vector = raw.get("cvss_vector")
    if isinstance(vector, str) and vector.strip() and not raw.get("cvss_version"):
        try:
            raw["cvss_version"] = score_vector(vector.strip()).version
        except CvssInvalid as exc:
            return {}, {"cvss_vector": str(exc)}
    if raw.get("severity") in (None, "") and raw.get("cvss_version") and isinstance(vector, str):
        try:  # no severity given: the CVSS rating is the suggestion (the reviewer can change it)
            result = score_vector(vector.strip(), expected_version=raw["cvss_version"])
            rating = rating_for_score(result.score, result.version)
            raw["severity"] = rating if rating in SEVERITIES else "info"
        except CvssInvalid:
            pass
    if isinstance(raw.get("cwe"), int) and not isinstance(raw.get("cwe"), bool):
        raw["cwe"] = str(raw["cwe"])
    if isinstance(raw.get("refs"), list) and all(isinstance(r, str) for r in raw["refs"]):
        raw["refs"] = "\n".join(raw["refs"])
    raw["confidence"] = VERDICT_CONFIDENCE.get(verdict) or raw.get("confidence") or ""
    clean, errors = validate_finding({**raw, "status": "open", "external_id": "", "retest_result": "",
                                      "retest_date": None, "retest_notes": ""}, target_ids_raw=[])
    out = {k: clean.get(k, "") for k in ("title", "severity", "cvss_version", "cvss_vector", "cwe", "confidence",
                                          *FINDING_TEXT_FIELDS)}
    errors = {k: v for k, v in errors.items() if k != "target_ids"}
    targets, errs = _clean_targets(raw.get("targets"))
    errors.update(errs)
    evidence, errs = _clean_evidence_items(raw.get("evidence"))
    errors.update(errs)
    code, errs = _clean_code_items(raw.get("code_evidence"))
    errors.update(errs)
    files, errs = _clean_files(raw.get("files"))
    errors.update(errs)
    out.update(targets=targets, evidence=evidence, code_evidence=code, files=files)
    match = raw.get("match")
    if isinstance(match, dict):  # importer hints for duplicate / retest matching, never written to a finding
        rule, files = match.get("rule_id"), match.get("files")
        out["match"] = {"rule_id": rule[:200] if isinstance(rule, str) else "",
                        "files": [f[:300] for f in files[:20] if isinstance(f, str)] if isinstance(files, list)
                        else []}
    return out, errors


def _clean_retest(data: dict) -> tuple[dict, dict]:
    v = Validator(data)
    if data.get("result") in (None, ""):
        v.errors["result"] = f"Result is required ({', '.join(RETEST_RESULTS)})."
    else:
        v.choice("result", RETEST_RESULTS, "not_tested", label="Retest result")
    v.iso_date("date", label="Retest date")
    v.text("notes", max_len=LONG, multiline=True, label="Retest notes")
    out = {"result": v.clean.get("result", ""), "date": v.clean.get("date"), "notes": v.clean.get("notes", "")}
    errors = dict(v.errors)
    out["evidence"], errs = _clean_evidence_items(data.get("evidence"))
    errors.update(errs)
    out["code_evidence"], errs = _clean_code_items(data.get("code_evidence"))
    errors.update(errs)
    return out, errors


def clean_data(kind: str, data: Any, verdict: str = "") -> tuple[dict, dict]:
    """Validate the kind-specific part of a proposal. Used on creation and again before it is applied."""
    if not isinstance(data, dict):
        return {}, {"data": "Must be an object."}
    if kind == "finding":
        return _clean_finding(data, verdict)
    if kind == "evidence":
        return validate_evidence({**data, "source": "ai"})
    if kind == "code":
        return validate_code_evidence(data)
    if kind == "file":
        return _clean_file(data)
    if kind == "retest":
        return _clean_retest(data)
    if kind == "target":
        if not data.get("name") and isinstance(data.get("address"), str):
            data = {**target_from_address(data["address"]), **{k: v for k, v in data.items() if v not in (None, "")}}
        return validate_target(data)
    return {}, {"kind": f"Unknown kind; use one of: {', '.join(KINDS)}."}


def _finding_id(raw: Any) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip().isdigit():
        return int(raw.strip())
    return None


def validate_proposal(conn: sqlite3.Connection, report_id: int, raw: Any,
                      defaults: dict | None = None) -> tuple[dict, dict]:
    """One proposal (JSON object) -> (record ready for :func:`repo.create_proposal`, errors)."""
    if not isinstance(raw, dict):
        return {}, {"proposal": "Each proposal must be a JSON object."}
    errors: dict[str, str] = {}
    kind = raw.get("kind")
    if kind not in KINDS:
        return {}, {"kind": f"Kind must be one of: {', '.join(KINDS)}."}
    verdict = raw.get("verdict") if raw.get("verdict") is not None else ""
    if verdict not in VERDICTS:
        errors["verdict"] = "Verdict must be 'verified', 'candidate' or empty."
        verdict = ""
    source, errs = _clean_source(raw.get("source"), defaults)
    errors.update(errs)
    body = raw.get("data")
    if body is None:  # flat form: the kind's fields next to kind/source/verdict
        body = {k: v for k, v in raw.items() if k not in ("kind", "source", "verdict", "finding_id", "format",
                                                          "version")}
    data, errs = clean_data(kind, body, verdict)
    errors.update(_prefixed("data", errs) if errs else {})
    target_finding_id = None
    if kind in ("evidence", "code", "file", "retest"):
        target_finding_id = _finding_id(raw.get("finding_id"))
        if target_finding_id is None:
            errors["finding_id"] = "finding_id (the id of a finding in this report) is required for this kind."
        else:
            row = repo.get_finding(conn, target_finding_id)
            if row is None or row["report_id"] != report_id:
                errors["finding_id"] = "No such finding in this report."
    if errors:
        return {}, errors
    if len(json.dumps(data, ensure_ascii=False)) > MAX_PAYLOAD_BYTES:
        return {}, {"data": f"The proposal is larger than {MAX_PAYLOAD_BYTES // (1024 * 1024)} MB."}
    record = {"kind": kind, "target_finding_id": target_finding_id, "data": data, "verdict": verdict,
              "source_tool": source.get("tool", ""), "source_version": source.get("version", ""),
              "run_id": source.get("run_id", ""), "model": source.get("model", "")}
    return record, {}


# ------------------------------------------------------- duplicates, retest --

def _finding_hosts(f: dict) -> set[str]:
    return {k for t in f.get("targets", []) for k in (host_key(t.get("address", "")) or
                                                       (t.get("name") or "").strip().lower(),) if k}


def _proposal_hosts(data: dict) -> set[str]:
    return {k for t in data.get("targets", []) for k in (host_key(t.get("address", "")) or
                                                          (t.get("name") or "").strip().lower(),) if k}


def _code_files(items: list[dict], hints: dict | None = None) -> set[str]:
    locations = [c.get("location", "") for c in items] + list((hints or {}).get("files", []))
    return {f for f in (_code_file(loc) for loc in locations) if f}


def title_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, (a or "").strip().lower(), (b or "").strip().lower()).ratio()


def duplicate_of(data: dict, findings: list[dict]) -> tuple[dict, str] | None:
    """The existing finding a finding proposal most likely duplicates, and why (same CWE + overlapping target or
    code location; or a title similarity of at least 0.8)."""
    hosts, files = _proposal_hosts(data), _code_files(data.get("code_evidence", []), data.get("match"))
    for f in findings:
        if data.get("cwe") and f.get("cwe") == data["cwe"]:
            if hosts & _finding_hosts(f):
                return f, f"same {data['cwe']} on the same target"
            if files and files & _code_files(f.get("code_evidence", [])):
                return f, f"same {data['cwe']} in the same file"
    best, best_ratio = None, 0.0
    for f in findings:
        ratio = title_ratio(data.get("title", ""), f.get("title", ""))
        if ratio >= DUPLICATE_RATIO and ratio > best_ratio:
            best, best_ratio = f, ratio
    if best is not None:
        return best, f"similar title ({round(best_ratio * 100)}%)"
    return None


def retest_match(data: dict, findings: list[dict]) -> dict | None:
    """The finding of a retest report a re-scan result refers to: same CWE (or, without a CWE, a similar title)
    and an overlapping target or code location. Stricter than :func:`duplicate_of` on purpose."""
    hosts, files = _proposal_hosts(data), _code_files(data.get("code_evidence", []), data.get("match"))
    for f in findings:
        same_rule = (data.get("cwe") and f.get("cwe") == data["cwe"]) or (
            (not data.get("cwe") or not f.get("cwe")) and title_ratio(data.get("title", ""), f["title"]) >= 0.9)
        if not same_rule:
            continue
        if (hosts and hosts & _finding_hosts(f)) or (files and files & _code_files(f.get("code_evidence", []))):
            return f
    return None


def as_retest(record: dict, finding: dict) -> dict:
    """A finding result from a re-scan of a retest report, offered as "still present -> not fixed"."""
    data = record["data"]
    note = f"Still present according to {_source_label(record)}"
    note += f" ({record['verdict']})." if record.get("verdict") else "."
    if data.get("technical_details"):
        note += "\n\n" + data["technical_details"][:4000]
    return {**record, "kind": "retest", "target_finding_id": finding["id"],
            "data": {"result": "not_fixed", "date": date.today().isoformat(), "notes": note[:LONG],
                     "evidence": data.get("evidence", []), "code_evidence": data.get("code_evidence", [])}}


# ---------------------------------------------------------------- creation --

def submit(conn: sqlite3.Connection, report_id: int, items: list, *, defaults: dict | None = None,
           token_id: int | None = None, retest_matching: bool = False) -> list[int]:
    """Validate every proposal, then store them all in one transaction (nothing is stored when one is invalid).

    ``retest_matching``: in a retest report, finding proposals that match an existing finding become retest
    proposals ("still present -> not fixed"). Raises :class:`ProposalError` with errors keyed ``[i].field``."""
    if not isinstance(items, list) or not items:
        raise ProposalError("Send one proposal object or a non-empty list of them.")
    if len(items) > MAX_PER_REQUEST:
        raise ProposalError(f"At most {MAX_PER_REQUEST} proposals at once.")
    records, errors = [], {}
    for i, raw in enumerate(items):
        record, errs = validate_proposal(conn, report_id, raw, defaults)
        errors.update(_prefixed(f"[{i}]", errs))
        records.append(record)
    if errors:
        raise ProposalError(dict(list(errors.items())[:100]))
    findings = repo.list_findings(conn, report_id)
    report = repo.get_report(conn, report_id)
    ids = []
    with transaction(conn):
        for record in records:
            if record["kind"] == "finding":
                match = retest_match(record["data"], findings) if retest_matching and report.get("retest_of") \
                    else None
                if match is not None:
                    record = as_retest(record, match)
                else:
                    dup = duplicate_of(record["data"], findings)
                    record["duplicate_of_finding_id"] = dup[0]["id"] if dup else None
            record["token_id"] = token_id
            ids.append(repo.create_proposal(conn, report_id, record))
        repo.touch_report(conn, report_id)
    return ids


def normalise_items(body: Any) -> list:
    """Request/file body -> list of proposals. Accepts one proposal, a list, or the envelope
    ``{"format": "ptreport-proposals", "version": 1, "source": {...}, "proposals": [...]}``."""
    if isinstance(body, dict) and "proposals" in body:
        if body.get("format") not in (None, SCHEMA_FORMAT):
            raise ProposalError({"format": f"Expected format '{SCHEMA_FORMAT}'."})
        if body.get("version") not in (None, SCHEMA_VERSION):
            raise ProposalError({"version": f"Unsupported version {body.get('version')!r} (expected 1)."})
        items = body["proposals"]
        if not isinstance(items, list):
            raise ProposalError({"proposals": "Must be a list."})
        source = body.get("source")
        if isinstance(source, dict):
            items = [{**p, "source": {**source, **(p.get("source") or {})}} if isinstance(p, dict)
                     and isinstance(p.get("source") or {}, dict) else p for p in items]
        return items
    if isinstance(body, dict):
        return [body]
    if isinstance(body, list):
        return body
    raise ProposalError("Send one proposal object or a list of them.")


# ---------------------------------------------------------------- decisions --

def _history(conn: sqlite3.Connection, finding: dict, text: str) -> None:
    repo.create_history_entry(conn, finding, {"date": date.today().isoformat(), "author": "", "kind": "note",
                                              "status_from": "", "status_to": "", "description": text[:300]})


def _attach(conn: sqlite3.Connection, finding: dict, evidence: list[dict], code: list[dict],
            files: list[dict]) -> None:
    for e in evidence:
        repo.create_evidence(conn, finding, {**e, "source": "ai"})
    for c in code:
        repo.create_code_evidence(conn, finding, c)
    if files:
        quota = check_file_quota(*repo.file_usage(conn, finding["id"]), [x["size"] for x in files])
        if quota:
            raise ProposalError({"files": quota})
        for x in files:
            repo.create_file(conn, finding, {"filename": x["filename"], "description": x["description"],
                                             "mime": guess_file_type(x["filename"]),
                                             "data": base64.b64decode(x["data_base64"])})


def _link_targets(conn: sqlite3.Connection, report_id: int, targets: list[dict]) -> list[int]:
    existing = {repo.target_match_key(t): t["id"] for t in repo.list_targets(conn, report_id)}
    ids = []
    for t in targets:
        key = repo.target_match_key(t)
        if key not in existing:
            existing[key] = repo.create_target(conn, report_id, t)
        ids.append(existing[key])
    return sorted(set(ids))


def _finding_in_report(conn: sqlite3.Connection, report_id: int, finding_id: int | None) -> dict:
    finding = repo.get_finding(conn, finding_id) if finding_id else None
    if finding is None or finding["report_id"] != report_id:
        raise ProposalError({"finding_id": "The finding does not exist in this report (any more)."})
    return finding


def accept(conn: sqlite3.Connection, proposal: dict, merge_into: int | None = None) -> dict:
    """Apply a pending proposal; ``merge_into`` adds a finding proposal's evidence to an existing finding (or
    attaches evidence/code/file proposals to a finding other than the one they named).

    Returns ``{"status": "accepted"|"merged", "finding_id": ..., "target_id": ...}``."""
    if proposal["status"] != "pending":
        raise ProposalError("This proposal was already decided.")
    kind, report_id = proposal["kind"], proposal["report_id"]
    data, errors = clean_data(kind, proposal["data"], proposal["verdict"])
    if errors:
        raise ProposalError(errors)
    report = repo.get_report(conn, report_id)
    lang = report["language"] if report["language"] in RETEST_LABELS else "en"
    source = _source_label(proposal)
    out: dict[str, Any] = {"finding_id": None, "target_id": None}
    with transaction(conn):
        if kind == "finding" and merge_into is None:
            values = {k: data[k] for k in ("title", "severity", "cvss_version", "cvss_vector", "cwe", "confidence",
                                            *FINDING_TEXT_FIELDS)}
            clean, errs = validate_finding({**values, "status": "open"}, target_ids_raw=[])
            if errs:
                raise ProposalError(errs)
            clean.update(status="open", external_id="", retest_result="", retest_date=None, retest_notes="",
                         origin=origin_text(proposal), target_ids=_link_targets(conn, report_id, data["targets"]))
            finding_id = repo.create_finding(conn, report_id, clean)
            finding = {"id": finding_id, "report_id": report_id}
            _attach(conn, finding, data["evidence"], data["code_evidence"], data["files"])
            _history(conn, finding, f"Added from {source} – AI proposal accepted")
            status, out["finding_id"] = "accepted", finding_id
        elif kind == "finding":
            finding = _finding_in_report(conn, report_id, merge_into)
            linked = _link_targets(conn, report_id, data["targets"])
            conn.executemany("INSERT OR IGNORE INTO finding_targets (finding_id, target_id) VALUES (?, ?)",
                             [(finding["id"], t) for t in linked])
            _attach(conn, finding, data["evidence"], data["code_evidence"], data["files"])
            _history(conn, finding, f"Merged AI proposal from {source}: {data['title']}")
            status, out["finding_id"] = "merged", finding["id"]
        elif kind in ("evidence", "code", "file"):
            target = merge_into or proposal["target_finding_id"]
            finding = _finding_in_report(conn, report_id, target)
            _attach(conn, finding, [data] if kind == "evidence" else [], [data] if kind == "code" else [],
                    [data] if kind == "file" else [])
            what = {"evidence": "HTTP evidence", "code": "Code evidence", "file": "File"}[kind]
            _history(conn, finding, f"{what} added from {source} – AI proposal accepted")
            status = "accepted" if target == proposal["target_finding_id"] else "merged"
            out["finding_id"] = finding["id"]
        elif kind == "retest":
            finding = _finding_in_report(conn, report_id, merge_into or proposal["target_finding_id"])
            when = data["date"] or date.today().isoformat()
            repo.set_finding_retest(conn, finding, data["result"], when, data["notes"])
            _attach(conn, finding, data["evidence"], data["code_evidence"], [])
            label = f"{REPORT_LABELS[lang]['retest']}: {RETEST_LABELS[lang][data['result']]}"
            repo.create_history_entry(conn, finding, {
                "date": when, "author": "", "kind": "note", "status_from": "", "status_to": "",
                "description": f"{label} – from {source} – AI proposal accepted"[:300]})
            status, out["finding_id"] = "accepted", finding["id"]
        else:  # target
            out["target_id"] = _link_targets(conn, report_id, [data])[0]
            status = "accepted"
        if not repo.decide_proposal(conn, proposal["id"], status):
            raise ProposalError("This proposal was already decided.")
    out["status"] = status
    return out


def reject(conn: sqlite3.Connection, proposal: dict) -> None:
    with transaction(conn):
        if not repo.decide_proposal(conn, proposal["id"], "rejected"):
            raise ProposalError("This proposal was already decided.")


# ------------------------------------------------------------------ output --

def public(proposal: dict) -> dict:
    """A proposal for API / MCP output: file contents are replaced by their size and SHA-256."""
    def strip(files: list[dict]) -> list[dict]:
        return [{k: v for k, v in x.items() if k != "data_base64"} for x in files]

    data = dict(proposal["data"])
    if proposal["kind"] == "file":
        data.pop("data_base64", None)
    if "files" in data:
        data["files"] = strip(data["files"])
    keys = ("id", "report_id", "kind", "target_finding_id", "source_tool", "source_version", "run_id", "model",
            "verdict", "status", "duplicate_of_finding_id", "created_at", "decided_at")
    return {**{k: proposal.get(k) for k in keys}, "data": data}


def _excerpt(text: str, limit: int = 280) -> str:
    text = re.sub(r"\s+", " ", (text or "").replace("```", " ")).strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def preview(proposal: dict, findings: list[dict]) -> dict:
    """What the review page shows for a proposal: a readable summary and a duplicate hint."""
    data, kind = proposal["data"], proposal["kind"]
    by_id = {f["id"]: f for f in findings}
    out: dict[str, Any] = {"target_finding": by_id.get(proposal["target_finding_id"]), "duplicate": None,
                           "duplicate_reason": "", "cvss_score": None}
    if kind == "finding":
        out["title"] = data.get("title", "")
        if data.get("cvss_vector"):
            try:
                out["cvss_score"] = score_vector(data["cvss_vector"], expected_version=data["cvss_version"]).score
            except CvssInvalid:
                pass
        dup = duplicate_of(data, findings)
        if dup:
            out["duplicate"], out["duplicate_reason"] = dup
        out["excerpt"] = _excerpt(data.get("description") or data.get("technical_details", ""))
    elif kind == "evidence":
        out["title"] = data.get("title") or data.get("request", "").split("\n", 1)[0][:120]
        out["excerpt"] = data.get("request", "").split("\n", 1)[0][:200]
    elif kind == "code":
        out["title"] = data.get("title") or data.get("location") or "Code snippet"
        out["excerpt"] = _excerpt(data.get("code", ""), 200)
    elif kind == "file":
        out["title"] = data.get("filename", "")
        out["excerpt"] = data.get("description", "")
    elif kind == "retest":
        f = out["target_finding"]
        out["title"] = f["title"] if f else "Retest result"
        out["excerpt"] = _excerpt(data.get("notes", ""))
    else:
        out["title"] = data.get("name", "")
        out["excerpt"] = data.get("address", "")
    return out
