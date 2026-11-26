"""Data access functions shared by the web UI, JSON API and import/export.

All SQL lives here and uses bound parameters exclusively. Callers are expected
to pass data that has already been through ``ptreport.validation``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import date
import sqlite3
from typing import Any

from ptreport import ids
from ptreport.db import transaction
from ptreport.validation import DEFAULT_BRAND_COLOR, SEVERITY_RANK

REPORT_FIELDS = (
    "title", "client_name", "assessor", "start_date", "end_date", "language",
    "finding_prefix", "executive_summary", "scope", "methodology", "id_format",
    "vendor_name", "vendor_contact", "report_version", "report_date",
    "show_version_history", "show_finding_history", "classification", "group_by_cwe",
)
TARGET_FIELDS = ("name", "kind", "address", "description")
FINDING_FIELDS = (
    "title", "severity", "status", "cvss_version", "cvss_vector", "cvss_score", "cwe",
    "description", "impact", "technical_details", "poc", "remediation", "refs",
    "external_id", "confidence", "retest_result", "retest_date", "retest_notes",
)
EVIDENCE_FIELDS = ("title", "request", "response", "source")
ATTACHMENT_META = ("id, finding_id, position, caption, mime, sha256, length(data) AS size, created_at, "
                   "original_data IS NOT NULL AS edited, edited_at")


def _row(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def _placeholders(n: int) -> str:
    return ",".join("?" * n)


# ----------------------------------------------------------------- reports --

def list_reports(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT r.*,
               (SELECT COUNT(*) FROM findings f WHERE f.report_id = r.id) AS finding_count,
               (SELECT COUNT(*) FROM targets t WHERE t.report_id = r.id) AS target_count
        FROM reports r
        ORDER BY r.updated_at DESC, r.id DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def get_report(conn: sqlite3.Connection, report_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone())


def create_report(conn: sqlite3.Connection, data: dict) -> int:
    values = [data.get(f) for f in REPORT_FIELDS]
    with transaction(conn):
        cur = conn.execute(
            f"INSERT INTO reports ({', '.join(REPORT_FIELDS)}) VALUES ({_placeholders(len(REPORT_FIELDS))})",
            values,
        )
        report_id = int(cur.lastrowid)
        ensure_sections(conn, report_id)
    return report_id


def update_report(conn: sqlite3.Connection, report_id: int, data: dict) -> None:
    assignments = ", ".join(f"{f} = ?" for f in REPORT_FIELDS)
    conn.execute(
        f"UPDATE reports SET {assignments}, updated_at = datetime('now') WHERE id = ?",
        [data.get(f) for f in REPORT_FIELDS] + [report_id],
    )


def touch_report(conn: sqlite3.Connection, report_id: int) -> None:
    conn.execute("UPDATE reports SET updated_at = datetime('now') WHERE id = ?", (report_id,))


def delete_report(conn: sqlite3.Connection, report_id: int) -> None:
    conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))


# ----------------------------------------------------------------- targets --

def list_targets(conn: sqlite3.Connection, report_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM targets WHERE report_id = ? ORDER BY name COLLATE NOCASE, id", (report_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_target(conn: sqlite3.Connection, target_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone())


def create_target(conn: sqlite3.Connection, report_id: int, data: dict) -> int:
    cur = conn.execute(
        f"INSERT INTO targets (report_id, {', '.join(TARGET_FIELDS)}) "
        f"VALUES (?, {_placeholders(len(TARGET_FIELDS))})",
        [report_id] + [data.get(f) for f in TARGET_FIELDS],
    )
    touch_report(conn, report_id)
    return int(cur.lastrowid)


def update_target(conn: sqlite3.Connection, target: dict, data: dict) -> None:
    assignments = ", ".join(f"{f} = ?" for f in TARGET_FIELDS)
    conn.execute(
        f"UPDATE targets SET {assignments} WHERE id = ?",
        [data.get(f) for f in TARGET_FIELDS] + [target["id"]],
    )
    touch_report(conn, target["report_id"])


def delete_target(conn: sqlite3.Connection, target: dict) -> None:
    conn.execute("DELETE FROM targets WHERE id = ?", (target["id"],))
    touch_report(conn, target["report_id"])


def foreign_target_ids(conn: sqlite3.Connection, report_id: int, target_ids: list[int]) -> list[int]:
    """Return the ids from ``target_ids`` that do NOT belong to ``report_id``."""
    if not target_ids:
        return []
    rows = conn.execute(
        f"SELECT id FROM targets WHERE report_id = ? AND id IN ({_placeholders(len(target_ids))})",
        [report_id] + list(target_ids),
    ).fetchall()
    owned = {r["id"] for r in rows}
    return [t for t in target_ids if t not in owned]


# ---------------------------------------------------------------- findings --

def list_findings(conn: sqlite3.Connection, report_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM findings WHERE report_id = ? ORDER BY position, id", (report_id,)
    ).fetchall()
    findings = [dict(r) for r in rows]
    if not findings:
        return findings
    by_id = {f["id"]: f for f in findings}
    for f in findings:
        f["targets"] = []
        f["evidence"] = []
        f["attachments"] = []
        f["history"] = []
    finding_ids = list(by_id)
    for row in conn.execute(
        f"""
        SELECT ft.finding_id, t.* FROM finding_targets ft
        JOIN targets t ON t.id = ft.target_id
        WHERE ft.finding_id IN ({_placeholders(len(finding_ids))})
        ORDER BY t.name COLLATE NOCASE, t.id
        """,
        finding_ids,
    ):
        target = dict(row)
        by_id[target.pop("finding_id")]["targets"].append(target)
    for row in conn.execute(
        f"SELECT * FROM http_evidence WHERE finding_id IN ({_placeholders(len(finding_ids))}) "
        "ORDER BY position, id",
        finding_ids,
    ):
        by_id[row["finding_id"]]["evidence"].append(dict(row))
    for row in conn.execute(
        f"SELECT {ATTACHMENT_META} FROM attachments WHERE finding_id IN ({_placeholders(len(finding_ids))}) "
        "ORDER BY position, id",
        finding_ids,
    ):
        by_id[row["finding_id"]]["attachments"].append(dict(row))
    for row in conn.execute(
        f"SELECT * FROM finding_history WHERE finding_id IN ({_placeholders(len(finding_ids))}) "
        "ORDER BY COALESCE(date, ''), id",
        finding_ids,
    ):
        by_id[row["finding_id"]]["history"].append(dict(row))
    return findings


def get_finding(conn: sqlite3.Connection, finding_id: int) -> dict | None:
    finding = _row(conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone())
    if finding is None:
        return None
    finding["target_ids"] = [
        r["target_id"]
        for r in conn.execute(
            "SELECT target_id FROM finding_targets WHERE finding_id = ?", (finding_id,)
        )
    ]
    finding["evidence"] = list_evidence(conn, finding_id)
    finding["attachments"] = list_attachments(conn, finding_id)
    finding["history"] = list_history(conn, finding_id)
    return finding


def _set_finding_targets(conn: sqlite3.Connection, finding_id: int, target_ids: list[int]) -> None:
    conn.execute("DELETE FROM finding_targets WHERE finding_id = ?", (finding_id,))
    conn.executemany(
        "INSERT INTO finding_targets (finding_id, target_id) VALUES (?, ?)",
        [(finding_id, t) for t in target_ids],
    )


def create_finding(conn: sqlite3.Connection, report_id: int, data: dict) -> int:
    with transaction(conn):
        position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) + 1 FROM findings WHERE report_id = ?", (report_id,)
        ).fetchone()[0]
        cur = conn.execute(
            f"INSERT INTO findings (report_id, position, {', '.join(FINDING_FIELDS)}) "
            f"VALUES (?, ?, {_placeholders(len(FINDING_FIELDS))})",
            [report_id, position] + [data.get(f, "") for f in FINDING_FIELDS],
        )
        finding_id = int(cur.lastrowid)
        _set_finding_targets(conn, finding_id, data.get("target_ids", []))
        touch_report(conn, report_id)
    return finding_id


def update_finding(conn: sqlite3.Connection, finding: dict, data: dict, author: str = "") -> None:
    assignments = ", ".join(f"{f} = ?" for f in FINDING_FIELDS)
    with transaction(conn):
        old_status, new_status = finding.get("status"), data.get("status")
        if old_status and new_status and old_status != new_status:
            create_history_entry(conn, finding, {
                "date": date.today().isoformat(), "author": author, "kind": "status",
                "status_from": old_status, "status_to": new_status, "description": "",
            })
        conn.execute(
            f"UPDATE findings SET {assignments}, updated_at = datetime('now') WHERE id = ?",
            [data.get(f, "") for f in FINDING_FIELDS] + [finding["id"]],
        )
        _set_finding_targets(conn, finding["id"], data.get("target_ids", []))
        touch_report(conn, finding["report_id"])


def _compact_positions(conn: sqlite3.Connection, report_id: int, ordered_ids: list[int]) -> None:
    conn.executemany(
        "UPDATE findings SET position = ? WHERE id = ? AND report_id = ?",
        [(i, fid, report_id) for i, fid in enumerate(ordered_ids, start=1)],
    )


def _ordered_finding_ids(conn: sqlite3.Connection, report_id: int) -> list[int]:
    return [
        r["id"]
        for r in conn.execute(
            "SELECT id FROM findings WHERE report_id = ? ORDER BY position, id", (report_id,)
        )
    ]


def delete_finding(conn: sqlite3.Connection, finding: dict) -> None:
    with transaction(conn):
        conn.execute("DELETE FROM findings WHERE id = ?", (finding["id"],))
        _compact_positions(conn, finding["report_id"], _ordered_finding_ids(conn, finding["report_id"]))
        touch_report(conn, finding["report_id"])


def move_finding(conn: sqlite3.Connection, finding: dict, direction: str) -> None:
    with transaction(conn):
        ids = _ordered_finding_ids(conn, finding["report_id"])
        i = ids.index(finding["id"])
        j = i - 1 if direction == "up" else i + 1
        if 0 <= j < len(ids):
            ids[i], ids[j] = ids[j], ids[i]
        _compact_positions(conn, finding["report_id"], ids)
        touch_report(conn, finding["report_id"])


def renumber_by_severity(conn: sqlite3.Connection, report_id: int) -> None:
    """Order findings: severity (critical first), then CVSS score desc, then current order."""
    with transaction(conn):
        rows = conn.execute(
            "SELECT id, severity, cvss_score, position FROM findings WHERE report_id = ?",
            (report_id,),
        ).fetchall()
        ordered = sorted(
            rows,
            key=lambda r: (
                SEVERITY_RANK.get(r["severity"], len(SEVERITY_RANK)),
                -(r["cvss_score"] if r["cvss_score"] is not None else -1),
                r["position"],
                r["id"],
            ),
        )
        _compact_positions(conn, report_id, [r["id"] for r in ordered])
        touch_report(conn, report_id)


def get_settings(conn: sqlite3.Connection) -> dict:
    stored = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}
    start = stored.get("id_start", "")
    return {
        "id_format": stored.get("id_format") or ids.DEFAULT_TEMPLATE,
        "id_start": int(start) if start.isdigit() else ids.DEFAULT_START,
        "default_prefix": stored.get("default_prefix") or ids.DEFAULT_PREFIX,
        "default_language": stored.get("default_language") or "en",
    }


def get_brand(conn: sqlite3.Connection) -> dict:
    """Brand colour (RRGGBB) and logo ({mime, data} or None) used by the exports."""
    stored = {r["key"]: r["value"] for r in conn.execute(
        "SELECT key, value FROM settings WHERE key IN ('brand_color', 'brand_logo', 'brand_logo_mime')")}
    logo = None
    if stored.get("brand_logo") and stored.get("brand_logo_mime"):
        logo = {"mime": stored["brand_logo_mime"], "data": base64.b64decode(stored["brand_logo"])}
    return {"color": stored.get("brand_color") or DEFAULT_BRAND_COLOR, "logo": logo}


def set_brand_color(conn: sqlite3.Connection, color: str | None) -> None:
    if color is None:
        conn.execute("DELETE FROM settings WHERE key = 'brand_color'")
    else:
        save_settings(conn, {"brand_color": color})


def set_brand_logo(conn: sqlite3.Connection, mime: str | None, data: bytes | None) -> None:
    if not data:
        conn.execute("DELETE FROM settings WHERE key IN ('brand_logo', 'brand_logo_mime')")
    else:
        save_settings(conn, {"brand_logo": base64.b64encode(data).decode("ascii"), "brand_logo_mime": mime})


def get_label_overrides(conn: sqlite3.Connection) -> dict:
    """{"en": {key: text}, "pl": {...}} - the user's own wording for report labels."""
    row = conn.execute("SELECT value FROM settings WHERE key = 'labels'").fetchone()
    try:
        data = json.loads(row["value"]) if row else {}
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def set_label_overrides(conn: sqlite3.Connection, overrides: dict) -> None:
    save_settings(conn, {"labels": json.dumps(overrides, ensure_ascii=False)})


def get_latex_template(conn: sqlite3.Connection) -> str | None:
    """The custom LaTeX template, or None when the built-in default is used."""
    row = conn.execute("SELECT value FROM settings WHERE key = 'latex_template'").fetchone()
    return row["value"] if row and row["value"] else None


def set_latex_template(conn: sqlite3.Connection, source: str | None) -> None:
    if source is None:
        conn.execute("DELETE FROM settings WHERE key = 'latex_template'")
    else:
        save_settings(conn, {"latex_template": source})


def save_settings(conn: sqlite3.Connection, values: dict) -> None:
    with transaction(conn):
        conn.executemany(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [(k, str(v)) for k, v in values.items()],
        )


def finding_display_id(report: dict, finding: dict, settings: dict | None = None) -> str:
    """The finding's own ID when set (e.g. LT-0002); otherwise the report's or the global ID format."""
    if finding.get("external_id"):
        return finding["external_id"]
    settings = settings or {"id_format": ids.DEFAULT_TEMPLATE, "id_start": ids.DEFAULT_START}
    template = report.get("id_format") or settings["id_format"]
    number = finding["position"] - 1 + settings["id_start"]
    return ids.render(template, report["finding_prefix"], number, ids.report_year(report))


def external_id_taken(conn: sqlite3.Connection, report_id: int, external_id: str,
                      exclude_finding_id: int | None = None) -> bool:
    if not external_id:
        return False
    row = conn.execute(
        "SELECT id FROM findings WHERE report_id = ? AND external_id = ? COLLATE NOCASE AND id IS NOT ?",
        (report_id, external_id, exclude_finding_id),
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------- evidence --

def list_evidence(conn: sqlite3.Connection, finding_id: int) -> list[dict]:
    return [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM http_evidence WHERE finding_id = ? ORDER BY position, id", (finding_id,)
        )
    ]


def get_evidence(conn: sqlite3.Connection, evidence_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM http_evidence WHERE id = ?", (evidence_id,)).fetchone())


def create_evidence(conn: sqlite3.Connection, finding: dict, data: dict) -> int:
    with transaction(conn):
        position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) + 1 FROM http_evidence WHERE finding_id = ?",
            (finding["id"],),
        ).fetchone()[0]
        cur = conn.execute(
            f"INSERT INTO http_evidence (finding_id, position, {', '.join(EVIDENCE_FIELDS)}) "
            f"VALUES (?, ?, {_placeholders(len(EVIDENCE_FIELDS))})",
            [finding["id"], position] + [data.get(f, "") for f in EVIDENCE_FIELDS],
        )
        conn.execute("UPDATE findings SET updated_at = datetime('now') WHERE id = ?", (finding["id"],))
        touch_report(conn, finding["report_id"])
    return int(cur.lastrowid)


def delete_evidence(conn: sqlite3.Connection, evidence: dict) -> None:
    conn.execute("DELETE FROM http_evidence WHERE id = ?", (evidence["id"],))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_RANK}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


# ------------------------------------------------------------- attachments --

def list_attachments(conn: sqlite3.Connection, finding_id: int) -> list[dict]:
    return [
        dict(r)
        for r in conn.execute(
            f"SELECT {ATTACHMENT_META} FROM attachments WHERE finding_id = ? ORDER BY position, id", (finding_id,)
        )
    ]


def get_attachment(conn: sqlite3.Connection, attachment_id: int, with_data: bool = False) -> dict | None:
    columns = ATTACHMENT_META + (", data, original_mime, original_data, original_sha256" if with_data else "")
    return _row(conn.execute(f"SELECT {columns} FROM attachments WHERE id = ?", (attachment_id,)).fetchone())


def attachment_data(conn: sqlite3.Connection, attachment_ids: list[int]) -> dict[int, tuple[str, bytes]]:
    if not attachment_ids:
        return {}
    rows = conn.execute(
        f"SELECT id, mime, data FROM attachments WHERE id IN ({_placeholders(len(attachment_ids))})",
        list(attachment_ids),
    )
    return {r["id"]: (r["mime"], r["data"]) for r in rows}


def count_attachments(conn: sqlite3.Connection, finding_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM attachments WHERE finding_id = ?", (finding_id,)).fetchone()[0]


def create_attachment(conn: sqlite3.Connection, finding: dict, data: dict) -> int:
    with transaction(conn):
        position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) + 1 FROM attachments WHERE finding_id = ?", (finding["id"],)
        ).fetchone()[0]
        original = data.get("original_data")
        cur = conn.execute(
            "INSERT INTO attachments (finding_id, position, caption, mime, data, sha256, original_mime, original_data,"
            " original_sha256, edited_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding["id"], position, data.get("caption", ""), data["mime"], data["data"],
             hashlib.sha256(data["data"]).hexdigest(),
             data.get("original_mime") if original else None, original,
             hashlib.sha256(original).hexdigest() if original else None,
             (data.get("edited_at") or _sql_now(conn)) if original else None),
        )
        conn.execute("UPDATE findings SET updated_at = datetime('now') WHERE id = ?", (finding["id"],))
        touch_report(conn, finding["report_id"])
    return int(cur.lastrowid)


def _sql_now(conn: sqlite3.Connection) -> str:
    return conn.execute("SELECT datetime('now')").fetchone()[0]


def attachment_originals(conn: sqlite3.Connection, attachment_ids: list[int]) -> dict[int, tuple[str, bytes]]:
    """Untouched originals of edited screenshots (attachments that were never edited are left out)."""
    if not attachment_ids:
        return {}
    rows = conn.execute(
        f"SELECT id, original_mime, original_data FROM attachments WHERE original_data IS NOT NULL "
        f"AND id IN ({_placeholders(len(attachment_ids))})",
        list(attachment_ids),
    )
    return {r["id"]: (r["original_mime"], r["original_data"]) for r in rows}


def save_edited_attachment(conn: sqlite3.Connection, attachment: dict, mime: str, data: bytes) -> None:
    """Replace a screenshot's image with an edited version.

    The first edit moves the current image into the ``original_*`` columns; later edits only replace the
    edited image, so the original is always the image as it was uploaded."""
    with transaction(conn):
        conn.execute(
            """UPDATE attachments SET
                 original_mime   = COALESCE(original_mime, mime),
                 original_sha256 = CASE WHEN original_data IS NULL THEN sha256 ELSE original_sha256 END,
                 original_data   = COALESCE(original_data, data),
                 mime = ?, data = ?, sha256 = ?, edited_at = datetime('now')
               WHERE id = ?""",
            (mime, data, hashlib.sha256(data).hexdigest(), attachment["id"]),
        )
        _touch_attachment_finding(conn, attachment["finding_id"])


def restore_attachment_original(conn: sqlite3.Connection, attachment: dict) -> bool:
    """Bring back the original image and drop the edited one. False when the screenshot was never edited."""
    with transaction(conn):
        cur = conn.execute(
            """UPDATE attachments SET mime = original_mime, data = original_data, sha256 = original_sha256,
                 original_mime = NULL, original_data = NULL, original_sha256 = NULL, edited_at = NULL
               WHERE id = ? AND original_data IS NOT NULL""",
            (attachment["id"],),
        )
        if cur.rowcount:
            _touch_attachment_finding(conn, attachment["finding_id"])
    return bool(cur.rowcount)


def _touch_attachment_finding(conn: sqlite3.Connection, finding_id: int) -> None:
    conn.execute("UPDATE findings SET updated_at = datetime('now') WHERE id = ?", (finding_id,))
    row = conn.execute("SELECT report_id FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if row:
        touch_report(conn, row["report_id"])


def update_attachment_caption(conn: sqlite3.Connection, attachment: dict, caption: str) -> None:
    conn.execute("UPDATE attachments SET caption = ? WHERE id = ?", (caption, attachment["id"]))


def delete_attachment(conn: sqlite3.Connection, attachment: dict) -> None:
    conn.execute("DELETE FROM attachments WHERE id = ?", (attachment["id"],))


# ---------------------------------------------------------- report versions --

def list_report_versions(conn: sqlite3.Connection, report_id: int) -> list[dict]:
    return [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM report_versions WHERE report_id = ? ORDER BY COALESCE(date, ''), id", (report_id,)
        )
    ]


def get_report_version(conn: sqlite3.Connection, version_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM report_versions WHERE id = ?", (version_id,)).fetchone())


def create_report_version(conn: sqlite3.Connection, report_id: int, data: dict) -> int:
    cur = conn.execute(
        "INSERT INTO report_versions (report_id, version, date, author, description) VALUES (?, ?, ?, ?, ?)",
        (report_id, data["version"], data.get("date"), data.get("author", ""), data.get("description", "")),
    )
    touch_report(conn, report_id)
    return int(cur.lastrowid)


def update_report_version(conn: sqlite3.Connection, version: dict, data: dict) -> None:
    conn.execute(
        "UPDATE report_versions SET version = ?, date = ?, author = ?, description = ? WHERE id = ?",
        (data["version"], data.get("date"), data.get("author", ""), data.get("description", ""), version["id"]),
    )
    touch_report(conn, version["report_id"])


def delete_report_version(conn: sqlite3.Connection, version: dict) -> None:
    conn.execute("DELETE FROM report_versions WHERE id = ?", (version["id"],))
    touch_report(conn, version["report_id"])


# ---------------------------------------------------------- finding history --

HISTORY_FIELDS = ("date", "author", "kind", "status_from", "status_to", "description")


def list_history(conn: sqlite3.Connection, finding_id: int) -> list[dict]:
    return [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM finding_history WHERE finding_id = ? ORDER BY COALESCE(date, ''), id", (finding_id,)
        )
    ]


def get_history_entry(conn: sqlite3.Connection, entry_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM finding_history WHERE id = ?", (entry_id,)).fetchone())


def create_history_entry(conn: sqlite3.Connection, finding: dict, data: dict) -> int:
    cur = conn.execute(
        f"INSERT INTO finding_history (finding_id, {', '.join(HISTORY_FIELDS)}) "
        f"VALUES (?, {_placeholders(len(HISTORY_FIELDS))})",
        [finding["id"]] + [data.get(f) if f == "date" else data.get(f, "") for f in HISTORY_FIELDS],
    )
    touch_report(conn, finding["report_id"])
    return int(cur.lastrowid)


def update_history_entry(conn: sqlite3.Connection, entry: dict, data: dict) -> None:
    conn.execute(
        "UPDATE finding_history SET date = ?, author = ?, description = ? WHERE id = ?",
        (data.get("date"), data.get("author", ""), data.get("description", ""), entry["id"]),
    )


def delete_history_entry(conn: sqlite3.Connection, entry: dict) -> None:
    conn.execute("DELETE FROM finding_history WHERE id = ?", (entry["id"],))


# -------------------------------------------------------- report structure --

SECTION_FIELDS = ("kind", "title", "level", "numbered", "new_page", "enabled", "body")
# kind, level, numbered, new_page - what a report looks like until its structure is edited.
DEFAULT_STRUCTURE = (
    ("executive_summary", 1, 1, 0),
    ("scope", 1, 1, 0),
    ("methodology", 1, 1, 0),
    ("summary", 1, 1, 1),
    ("findings", 1, 1, 1),
)
REMOVABLE_KINDS = ("text", "charts", "findings_table", "summary", "retest_summary")


def list_sections(conn: sqlite3.Connection, report_id: int) -> list[dict]:
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM report_sections WHERE report_id = ? ORDER BY position, id", (report_id,))]
    if rows:
        return rows
    return [
        {"id": None, "report_id": report_id, "position": i, "kind": kind, "title": "", "level": level,
         "numbered": numbered, "new_page": new_page, "enabled": 1, "body": ""}
        for i, (kind, level, numbered, new_page) in enumerate(DEFAULT_STRUCTURE, start=1)
    ]


def ensure_sections(conn: sqlite3.Connection, report_id: int) -> list[dict]:
    """Persist the default structure the first time a report's structure is edited."""
    sections = list_sections(conn, report_id)
    if sections and sections[0]["id"] is None:
        with transaction(conn):
            for sec in sections:
                _insert_section(conn, report_id, sec["position"], sec)
        sections = list_sections(conn, report_id)
    return sections


def _insert_section(conn: sqlite3.Connection, report_id: int, position: int, data: dict) -> int:
    cur = conn.execute(
        f"INSERT INTO report_sections (report_id, position, {', '.join(SECTION_FIELDS)}) "
        f"VALUES (?, ?, {_placeholders(len(SECTION_FIELDS))})",
        [report_id, position] + [data.get(f, "" if f in ("kind", "title", "body") else 1) for f in SECTION_FIELDS],
    )
    return int(cur.lastrowid)


def get_section(conn: sqlite3.Connection, section_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM report_sections WHERE id = ?", (section_id,)).fetchone())


def create_section(conn: sqlite3.Connection, report_id: int, data: dict) -> int:
    ensure_sections(conn, report_id)
    with transaction(conn):
        position = conn.execute(
            "SELECT COALESCE(MAX(position), 0) + 1 FROM report_sections WHERE report_id = ?", (report_id,)
        ).fetchone()[0]
        section_id = _insert_section(conn, report_id, position, data)
        touch_report(conn, report_id)
    return section_id


def replace_sections(conn: sqlite3.Connection, report_id: int, sections: list[dict]) -> None:
    """Used by the JSON import: store a whole structure at once."""
    with transaction(conn):
        conn.execute("DELETE FROM report_sections WHERE report_id = ?", (report_id,))
        for i, sec in enumerate(sections, start=1):
            _insert_section(conn, report_id, i, sec)


def update_section(conn: sqlite3.Connection, section: dict, data: dict) -> None:
    assignments = ", ".join(f"{f} = ?" for f in SECTION_FIELDS if f != "kind")
    conn.execute(
        f"UPDATE report_sections SET {assignments} WHERE id = ?",
        [data.get(f) for f in SECTION_FIELDS if f != "kind"] + [section["id"]],
    )
    touch_report(conn, section["report_id"])


def move_section(conn: sqlite3.Connection, section: dict, direction: str) -> None:
    with transaction(conn):
        ids = [r["id"] for r in conn.execute(
            "SELECT id FROM report_sections WHERE report_id = ? ORDER BY position, id", (section["report_id"],))]
        i = ids.index(section["id"])
        j = i - 1 if direction == "up" else i + 1
        if 0 <= j < len(ids):
            ids[i], ids[j] = ids[j], ids[i]
        conn.executemany("UPDATE report_sections SET position = ? WHERE id = ?",
                         [(n, sid) for n, sid in enumerate(ids, start=1)])
        touch_report(conn, section["report_id"])


def delete_section(conn: sqlite3.Connection, section: dict) -> None:
    conn.execute("DELETE FROM report_sections WHERE id = ?", (section["id"],))
    touch_report(conn, section["report_id"])


# ------------------------------------------------------------- CWE groups --

CWE_NOTE_FIELDS = ("title", "description", "mitigation")


def list_cwe_notes(conn: sqlite3.Connection, report_id: int) -> dict[str, dict]:
    return {r["cwe"]: dict(r) for r in conn.execute(
        "SELECT * FROM report_cwe_notes WHERE report_id = ? ORDER BY position, id", (report_id,))}


def save_cwe_note(conn: sqlite3.Connection, report_id: int, cwe: str, data: dict,
                  position: int | None = None) -> None:
    existing = conn.execute("SELECT id, position FROM report_cwe_notes WHERE report_id = ? AND cwe = ?",
                            (report_id, cwe)).fetchone()
    if existing:
        conn.execute("UPDATE report_cwe_notes SET title = ?, description = ?, mitigation = ?, position = ? "
                     "WHERE id = ?", [data.get(f, "") for f in CWE_NOTE_FIELDS]
                     + [existing["position"] if position is None else position, existing["id"]])
    else:
        conn.execute("INSERT INTO report_cwe_notes (report_id, cwe, position, title, description, mitigation) "
                     "VALUES (?, ?, ?, ?, ?, ?)",
                     [report_id, cwe, position or 0] + [data.get(f, "") for f in CWE_NOTE_FIELDS])
    touch_report(conn, report_id)


def finding_groups(findings: list[dict], notes: dict[str, dict]) -> list[dict]:
    """Findings grouped by CWE. Order: the group's saved position, then the first finding's position.
    Findings without a CWE form one group with cwe == ''."""
    groups: dict[str, dict] = {}
    for f in findings:
        cwe = f.get("cwe") or ""
        if cwe not in groups:
            note = notes.get(cwe, {})
            groups[cwe] = {"cwe": cwe, "title": note.get("title", ""), "description": note.get("description", ""),
                           "mitigation": note.get("mitigation", ""), "position": note.get("position", 0),
                           "first": len(groups), "findings": []}
        groups[cwe]["findings"].append(f)
    ordered = sorted(groups.values(), key=lambda g: (g["position"] or 10_000, g["cwe"] == "", g["first"]))
    return ordered


def move_cwe_group(conn: sqlite3.Connection, report_id: int, cwe: str, direction: str,
                   findings: list[dict]) -> None:
    """Reorder groups: positions are written for every group so the order becomes explicit."""
    notes = list_cwe_notes(conn, report_id)
    order = [g["cwe"] for g in finding_groups(findings, notes)]
    if cwe not in order:
        return
    i = order.index(cwe)
    j = i - 1 if direction == "up" else i + 1
    if 0 <= j < len(order):
        order[i], order[j] = order[j], order[i]
    with transaction(conn):
        for n, key in enumerate(order, start=1):
            save_cwe_note(conn, report_id, key, notes.get(key, {}), position=n)


# ------------------------------------------------------------- CWE library --

def get_cwe_library(conn: sqlite3.Connection, cwe: str) -> dict | None:
    return _row(conn.execute("SELECT * FROM cwe_library WHERE cwe = ?", (cwe,)).fetchone())


def list_cwe_library(conn: sqlite3.Connection) -> dict[str, dict]:
    return {r["cwe"]: dict(r) for r in conn.execute("SELECT * FROM cwe_library ORDER BY cwe")}


def save_cwe_library(conn: sqlite3.Connection, cwe: str, description: str, mitigation: str) -> None:
    if not description and not mitigation:
        conn.execute("DELETE FROM cwe_library WHERE cwe = ?", (cwe,))
        return
    conn.execute(
        "INSERT INTO cwe_library (cwe, description, mitigation) VALUES (?, ?, ?) "
        "ON CONFLICT(cwe) DO UPDATE SET description = excluded.description, mitigation = excluded.mitigation, "
        "updated_at = datetime('now')",
        (cwe, description, mitigation),
    )


def use_mitre_text(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT value FROM settings WHERE key = 'cwe_use_mitre'").fetchone()
    return row is None or row["value"] != "0"


def cwe_texts(conn: sqlite3.Connection, cwe: str) -> dict:
    """Description and mitigation for a CWE from the user's library, else MITRE's (unless switched off)."""
    from ptreport.cwe import cwe_reference

    own = get_cwe_library(conn, cwe) or {}
    mitre = cwe_reference(cwe) if use_mitre_text(conn) else {"description": "", "mitigation": ""}
    return {
        "description": own.get("description") or mitre["description"],
        "mitigation": own.get("mitigation") or mitre["mitigation"],
    }


# -------------------------------------------------------- finding templates --

TEMPLATE_COLUMNS = (
    "language", "title", "severity", "cvss_version", "cvss_vector", "cwe", "description", "impact",
    "technical_details", "poc", "remediation", "refs", "tags",
)


def list_templates(conn: sqlite3.Connection, query: str = "", language: str = "") -> list[dict]:
    sql = "SELECT * FROM finding_templates WHERE 1 = 1"
    params: list = []
    if language:
        sql += " AND language = ?"
        params.append(language)
    if query:
        sql += " AND (title LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\' OR cwe LIKE ? ESCAPE '\\')"
        like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params += [like, like, like]
    sql += " ORDER BY title COLLATE NOCASE, language"
    return [dict(r) for r in conn.execute(sql, params)]


def get_template(conn: sqlite3.Connection, template_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM finding_templates WHERE id = ?", (template_id,)).fetchone())


def create_template(conn: sqlite3.Connection, data: dict) -> int:
    cur = conn.execute(
        f"INSERT INTO finding_templates ({', '.join(TEMPLATE_COLUMNS)}) VALUES ({_placeholders(len(TEMPLATE_COLUMNS))})",
        [data.get(c, "") for c in TEMPLATE_COLUMNS],
    )
    return int(cur.lastrowid)


def update_template(conn: sqlite3.Connection, template: dict, data: dict) -> None:
    assignments = ", ".join(f"{c} = ?" for c in TEMPLATE_COLUMNS)
    conn.execute(f"UPDATE finding_templates SET {assignments}, updated_at = datetime('now') WHERE id = ?",
                 [data.get(c, "") for c in TEMPLATE_COLUMNS] + [template["id"]])


def delete_template(conn: sqlite3.Connection, template: dict) -> None:
    conn.execute("DELETE FROM finding_templates WHERE id = ?", (template["id"],))


def template_as_finding_values(template: dict) -> dict:
    """Form values for a new finding started from a template (the CVSS score is recomputed on save)."""
    return {c: template[c] for c in TEMPLATE_COLUMNS if c not in ("language", "tags")} | {"status": "open"}


# ------------------------------------------------------------------ retests --

def clone_report(conn: sqlite3.Connection, report_id: int, retest: bool) -> int:
    """Copy a report with targets, findings (incl. evidence and screenshots), structure and CWE notes.

    A retest copy links to the original (retest_of / original_finding_id), starts with a retest summary
    section and clears the findings' retest fields; a plain copy is an independent duplicate."""
    report = get_report(conn, report_id)
    with transaction(conn):
        data = {f: report[f] for f in REPORT_FIELDS}
        prefix = "Retest: " if retest else "Copy of "
        data["title"] = (prefix + report["title"])[:300]
        new_id = create_report(conn, data)
        if retest:
            conn.execute("UPDATE reports SET retest_of = ? WHERE id = ?", (report_id, new_id))
        target_map = {}
        for t in list_targets(conn, report_id):
            target_map[t["id"]] = create_target(conn, new_id, {f: t[f] for f in TARGET_FIELDS})
        for f in list_findings(conn, report_id):
            values = {k: f[k] for k in FINDING_FIELDS}
            values["target_ids"] = [target_map[t["id"]] for t in f["targets"] if t["id"] in target_map]
            if retest:
                values.update(retest_result="", retest_date=None, retest_notes="")
            fid = create_finding(conn, new_id, values)
            conn.execute("UPDATE findings SET position = ?, original_finding_id = ? WHERE id = ?",
                         (f["position"], f["id"] if retest else None, fid))
            new_finding = {"id": fid, "report_id": new_id}
            for e in f["evidence"]:
                create_evidence(conn, new_finding, {k: e[k] for k in EVIDENCE_FIELDS})
            att_ids = [a["id"] for a in f["attachments"]]
            blobs = attachment_data(conn, att_ids)
            originals = attachment_originals(conn, att_ids)
            for a in f["attachments"]:
                mime, blob = blobs[a["id"]]
                copy = {"caption": a["caption"], "mime": mime, "data": blob}
                if a["id"] in originals:
                    copy["original_mime"], copy["original_data"] = originals[a["id"]]
                    copy["edited_at"] = a["edited_at"]
                create_attachment(conn, new_finding, copy)
        sections = [{k: s[k] for k in SECTION_FIELDS} for s in list_sections(conn, report_id)]
        if retest and not any(s["kind"] == "retest_summary" for s in sections):
            sections.insert(0, {"kind": "retest_summary", "title": "", "level": 1, "numbered": 1, "new_page": 0,
                                "enabled": 1, "body": ""})
        replace_sections(conn, new_id, sections)
        for cwe, note in list_cwe_notes(conn, report_id).items():
            save_cwe_note(conn, new_id, cwe, note, position=note["position"])
        conn.execute("UPDATE reports SET group_by_cwe = ? WHERE id = ?", (report["group_by_cwe"], new_id))
        for note in reversed(list_notes(conn, report_id)):
            create_note(conn, new_id, note)
    return new_id


MAX_TEMPLATES_IMPORT = 2000


def seed_templates(conn: sqlite3.Connection) -> int:
    """Install the bundled starter templates (EN + PL) once; later deletions are respected."""
    if conn.execute("SELECT 1 FROM settings WHERE key = 'templates_seeded'").fetchone():
        return 0
    from importlib import resources

    from ptreport.validation import validate_template

    raw = json.loads(resources.files("ptreport").joinpath("data/finding_templates.json").read_text("utf-8"))
    created = 0
    with transaction(conn):
        for item in raw:
            clean, errors = validate_template(item)
            if not errors:
                create_template(conn, clean)
                created += 1
        save_settings(conn, {"templates_seeded": "1"})
    return created


# ----------------------------------------------------------- scanner import --

def stage_scan_import(conn: sqlite3.Connection, report_id: int, fmt: str, filename: str, parsed: dict) -> int:
    """Keep a parsed scanner file until the user has chosen what to import (stale ones are dropped)."""
    with transaction(conn):
        conn.execute("DELETE FROM scan_imports WHERE created_at < datetime('now', '-1 day')")
        cur = conn.execute("INSERT INTO scan_imports (report_id, format, filename, payload) VALUES (?, ?, ?, ?)",
                           (report_id, fmt, filename, json.dumps(parsed, ensure_ascii=False)))
    return int(cur.lastrowid)


def get_scan_import(conn: sqlite3.Connection, import_id: int) -> dict | None:
    row = _row(conn.execute("SELECT * FROM scan_imports WHERE id = ?", (import_id,)).fetchone())
    if row:
        row["parsed"] = json.loads(row.pop("payload"))
    return row


def delete_scan_import(conn: sqlite3.Connection, import_id: int) -> None:
    conn.execute("DELETE FROM scan_imports WHERE id = ?", (import_id,))


def target_match_key(t: dict) -> tuple[str, str]:
    address = (t.get("address") or "").strip().lower()
    return ("a", address) if address else ("n", (t.get("name") or "").strip().lower())


def apply_scan_import(conn: sqlite3.Connection, staged: dict, target_keys: set[str],
                      finding_keys: set[str]) -> tuple[int, int, int]:
    """Create the chosen targets and findings (with evidence) in the report.

    Targets already in the report (same address, or same name when there is no address) are reused.
    A chosen finding brings its targets along even when they were not ticked. Returns
    (targets created, targets reused, findings created)."""
    report_id, parsed = staged["report_id"], staged["parsed"]
    findings = [f for f in parsed["findings"] if f["key"] in finding_keys]
    needed = set(target_keys) | {k for f in findings for k in f["target_keys"]}
    existing = {target_match_key(t): t["id"] for t in list_targets(conn, report_id)}
    created = reused = 0
    key_to_id: dict[str, int] = {}
    label = {"burp": "Burp Suite", "nessus": "Nessus", "nmap": "Nmap", "zap": "OWASP ZAP",
             "openvas": "OpenVAS"}.get(staged["format"], staged["format"])
    with transaction(conn):
        for t in parsed["targets"]:
            if t["key"] not in needed:
                continue
            match = existing.get(target_match_key(t))
            if match:
                key_to_id[t["key"]] = match
                reused += 1
            else:
                new_id = create_target(conn, report_id, {f: t.get(f, "") for f in TARGET_FIELDS})
                existing[target_match_key(t)] = key_to_id[t["key"]] = new_id
                created += 1
        for f in findings:
            values = {k: f.get(k, "") for k in FINDING_FIELDS}
            values.update(status="open", external_id="", retest_result="", retest_date=None, retest_notes="")
            values["target_ids"] = sorted({key_to_id[k] for k in f["target_keys"] if k in key_to_id})
            fid = create_finding(conn, report_id, values)
            finding = {"id": fid, "report_id": report_id}
            for e in f.get("evidence", []):
                create_evidence(conn, finding, {"title": e.get("title", ""), "request": e["request"],
                                                "response": e.get("response", ""), "source": "import"})
            create_history_entry(conn, finding, {
                "date": date.today().isoformat(), "author": "", "kind": "note", "status_from": "", "status_to": "",
                "description": f"Imported from {label}" + (f" ({staged['filename']})" if staged["filename"] else ""),
            })
        delete_scan_import(conn, staged["id"])
    return created, reused, len(findings)


# ------------------------------------------------------------------- notes --

NOTE_FIELDS = ("title", "body", "pinned")


def list_notes(conn: sqlite3.Connection, report_id: int, query: str = "") -> list[dict]:
    sql = "SELECT * FROM report_notes WHERE report_id = ?"
    params: list = [report_id]
    if query:
        like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        sql += " AND (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\')"
        params += [like, like]
    sql += " ORDER BY pinned DESC, updated_at DESC, id DESC"
    return [dict(r) for r in conn.execute(sql, params)]


def count_notes(conn: sqlite3.Connection, report_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM report_notes WHERE report_id = ?", (report_id,)).fetchone()[0]


def get_note(conn: sqlite3.Connection, note_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM report_notes WHERE id = ?", (note_id,)).fetchone())


def create_note(conn: sqlite3.Connection, report_id: int, data: dict) -> int:
    cur = conn.execute("INSERT INTO report_notes (report_id, title, body, pinned) VALUES (?, ?, ?, ?)",
                       [report_id] + [data.get(f, "" if f != "pinned" else 0) for f in NOTE_FIELDS])
    return int(cur.lastrowid)


def update_note(conn: sqlite3.Connection, note: dict, data: dict) -> None:
    conn.execute("UPDATE report_notes SET title = ?, body = ?, pinned = ?, updated_at = datetime('now') WHERE id = ?",
                 [data.get(f, "" if f != "pinned" else 0) for f in NOTE_FIELDS] + [note["id"]])


def delete_note(conn: sqlite3.Connection, note: dict) -> None:
    conn.execute("DELETE FROM report_notes WHERE id = ?", (note["id"],))
