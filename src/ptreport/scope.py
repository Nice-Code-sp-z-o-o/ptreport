"""The engagement scope of a report as a document an agent can start from (JSON or a Markdown brief).

Used by the MCP tool ``get_scope``, ``ptreport scope`` and ``GET /api/v1/reports/<id>/scope``. A report has one
scope text; an "Out of scope" heading (or a line such as "Out of scope:") inside it starts the out-of-scope part.
"""

from __future__ import annotations

import re
import sqlite3

from ptreport import repo
from ptreport.rendering import TARGET_KIND_LABELS

SCOPE_FORMAT = "ptreport-scope"
SCOPE_VERSION = 1
LANGUAGE_NAMES = {"en": "English", "pl": "Polish"}
_OUT_OF_SCOPE = re.compile(
    r"^\s*(?:#{1,3}\s*)?(?:\*\*)?\s*(?:out[ -]of[ -]scope|not in scope|exclusions?|excluded|poza zakresem|"
    r"wyłączenia|wyłączone z zakresu|wyłączone z testów)\s*(?:\*\*)?\s*:?\s*(?:\*\*)?\s*$",
    re.IGNORECASE,
)
_HEADING = re.compile(r"^\s*#{1,3}\s+\S")


def split_scope(text: str) -> tuple[str, str]:
    """(in scope, out of scope) from a report's scope text."""
    lines = (text or "").split("\n")
    for i, line in enumerate(lines):
        if _OUT_OF_SCOPE.match(line):
            rest, after = [], []
            for j, other in enumerate(lines[i + 1:], start=i + 1):
                if _HEADING.match(other) and not _OUT_OF_SCOPE.match(other):
                    after = lines[j:]
                    break
                rest.append(other)
            inside = "\n".join(lines[:i] + after).strip()
            return inside, "\n".join(rest).strip()
    return (text or "").strip(), ""


def scope_document(conn: sqlite3.Connection, report_id: int) -> dict | None:
    report = repo.get_report(conn, report_id)
    if report is None:
        return None
    in_scope, out_of_scope = split_scope(report["scope"])
    return {
        "format": SCOPE_FORMAT,
        "version": SCOPE_VERSION,
        "report": {"id": report["id"], "title": report["title"], "language": report["language"],
                   "classification": report["classification"], "retest_of": report.get("retest_of")},
        "client": report["client_name"],
        "dates": {"start": report["start_date"], "end": report["end_date"], "report_date": report["report_date"]},
        "contacts": {"assessor": report["assessor"], "prepared_by": report["vendor_name"],
                     "contact": report["vendor_contact"]},
        "targets": [{"id": t["id"], "name": t["name"], "kind": t["kind"], "address": t["address"],
                     "description": t["description"]} for t in repo.list_targets(conn, report_id)],
        "scope": in_scope,
        "out_of_scope": out_of_scope,
        "methodology": report["methodology"],
    }


def _cell(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").replace("|", "\\|")).strip() or "–"


def _block(text: str) -> str:
    """Report text inside a "## Section" of the brief: its own headings move one level down."""
    return re.sub(r"(?m)^(#{1,3})(\s)", r"#\1\2", text.strip())


def to_markdown(doc: dict) -> str:
    """A short engagement brief (e.g. the input for Decepticon's RoE / ConOps / OPPLAN, or any agent)."""
    r, d, c = doc["report"], doc["dates"], doc["contacts"]
    out = [f"# Engagement brief: {r['title']}", ""]
    window = " – ".join(x for x in (d["start"], d["end"]) if x) or "not set"
    facts = [("Client", doc["client"]), ("Testing window", window),
             ("Report language", LANGUAGE_NAMES.get(r["language"], r["language"])),
             ("Classification", r["classification"]),
             ("Type", "retest of report #" + str(r["retest_of"]) if r["retest_of"] else "assessment")]
    out += [f"- **{k}:** {v}" for k, v in facts if v] + [""]
    contacts = [("Assessor(s)", c["assessor"]), ("Prepared by", c["prepared_by"]), ("Contact", c["contact"])]
    if any(v for _, v in contacts):
        out += ["## Contacts", ""] + [f"- **{k}:** {v}" for k, v in contacts if v] + [""]
    out += ["## Targets", ""]
    if doc["targets"]:
        labels = TARGET_KIND_LABELS["en"]
        out += ["| Name | Type | Address | Notes |", "|---|---|---|---|"]
        out += [f"| {_cell(t['name'])} | {labels.get(t['kind'], t['kind'])} | {_cell(t['address'])} | "
                f"{_cell(t['description'])[:200]} |" for t in doc["targets"]]
    else:
        out.append("No targets are listed yet.")
    out += ["", "## In scope", "", _block(doc["scope"]) or "Only the targets listed above.", "",
            "## Out of scope", "",
            _block(doc["out_of_scope"]) or "Nothing stated explicitly: everything not listed under Targets is out "
                                           "of scope.", ""]
    if doc["methodology"]:
        out += ["## Methodology", "", _block(doc["methodology"]), ""]
    out += ["## Rules for agents", "",
            "- Stay within the targets and the testing window above; ask the operator before anything else.",
            "- Send results to ptreport as proposals (MCP tools `propose_*`, or "
            f"`POST /api/v1/reports/{r['id']}/proposals`). A person reviews every proposal before it reaches the "
            "report.",
            "- Include the requests and responses (or code locations) that prove each finding, and say whether it "
            "was verified.", ""]
    return "\n".join(out)
