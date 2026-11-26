"""SQLite access layer: connection handling and schema migrations.

Migrations are applied in order based on ``PRAGMA user_version`` so existing
databases are upgraded in place when a new version of the tool is installed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, current_app, g

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE reports (
        id                INTEGER PRIMARY KEY,
        title             TEXT    NOT NULL,
        client_name       TEXT    NOT NULL DEFAULT '',
        assessor          TEXT    NOT NULL DEFAULT '',
        start_date        TEXT,
        end_date          TEXT,
        language          TEXT    NOT NULL DEFAULT 'en',
        finding_prefix    TEXT    NOT NULL DEFAULT 'VULN',
        executive_summary TEXT    NOT NULL DEFAULT '',
        scope             TEXT    NOT NULL DEFAULT '',
        methodology       TEXT    NOT NULL DEFAULT '',
        created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
        updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE targets (
        id          INTEGER PRIMARY KEY,
        report_id   INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        name        TEXT    NOT NULL,
        kind        TEXT    NOT NULL DEFAULT 'web',
        address     TEXT    NOT NULL DEFAULT '',
        description TEXT    NOT NULL DEFAULT '',
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_targets_report ON targets(report_id);

    CREATE TABLE findings (
        id                INTEGER PRIMARY KEY,
        report_id         INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        position          INTEGER NOT NULL,
        title             TEXT    NOT NULL,
        severity          TEXT    NOT NULL,
        status            TEXT    NOT NULL DEFAULT 'open',
        cvss_version      TEXT    NOT NULL DEFAULT '',
        cvss_vector       TEXT    NOT NULL DEFAULT '',
        cvss_score        REAL,
        cwe               TEXT    NOT NULL DEFAULT '',
        description       TEXT    NOT NULL DEFAULT '',
        impact            TEXT    NOT NULL DEFAULT '',
        technical_details TEXT    NOT NULL DEFAULT '',
        poc               TEXT    NOT NULL DEFAULT '',
        remediation       TEXT    NOT NULL DEFAULT '',
        refs              TEXT    NOT NULL DEFAULT '',
        created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
        updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_findings_report_position ON findings(report_id, position);

    CREATE TABLE finding_targets (
        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        target_id  INTEGER NOT NULL REFERENCES targets(id)  ON DELETE CASCADE,
        PRIMARY KEY (finding_id, target_id)
    );
    CREATE INDEX idx_finding_targets_target ON finding_targets(target_id);

    CREATE TABLE http_evidence (
        id         INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        position   INTEGER NOT NULL,
        title      TEXT    NOT NULL DEFAULT '',
        request    TEXT    NOT NULL DEFAULT '',
        response   TEXT    NOT NULL DEFAULT '',
        source     TEXT    NOT NULL DEFAULT 'manual',
        created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_http_evidence_finding ON http_evidence(finding_id, position);
    """,
    # 2: custom finding id (e.g. LT-0002); severity_manual is unused since severity became always manual
    #    (kept because DROP COLUMN needs SQLite 3.35+)
    """
    ALTER TABLE findings ADD COLUMN external_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN severity_manual INTEGER NOT NULL DEFAULT 0;
    """,
    # 3: application settings (finding ID format) and a per-report ID format override
    """
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    ALTER TABLE reports ADD COLUMN id_format TEXT NOT NULL DEFAULT '';
    """,
    # 4: confidence, report metadata (vendor, version, date, history) and screenshot attachments
    """
    ALTER TABLE findings ADD COLUMN confidence TEXT NOT NULL DEFAULT '';
    ALTER TABLE reports ADD COLUMN vendor_name TEXT NOT NULL DEFAULT '';
    ALTER TABLE reports ADD COLUMN vendor_contact TEXT NOT NULL DEFAULT '';
    ALTER TABLE reports ADD COLUMN report_version TEXT NOT NULL DEFAULT '';
    ALTER TABLE reports ADD COLUMN report_date TEXT;

    CREATE TABLE report_versions (
        id          INTEGER PRIMARY KEY,
        report_id   INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        version     TEXT    NOT NULL,
        date        TEXT,
        description TEXT    NOT NULL DEFAULT '',
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_report_versions_report ON report_versions(report_id);

    CREATE TABLE attachments (
        id         INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        position   INTEGER NOT NULL,
        caption    TEXT    NOT NULL DEFAULT '',
        mime       TEXT    NOT NULL,
        data       BLOB    NOT NULL,
        sha256     TEXT    NOT NULL,
        created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_attachments_finding ON attachments(finding_id, position);
    """,
    # 5: changelogs - author on report versions, per-finding history, export switches
    """
    ALTER TABLE report_versions ADD COLUMN author TEXT NOT NULL DEFAULT '';
    ALTER TABLE reports ADD COLUMN show_version_history INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE reports ADD COLUMN show_finding_history INTEGER NOT NULL DEFAULT 1;

    CREATE TABLE finding_history (
        id          INTEGER PRIMARY KEY,
        finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        date        TEXT,
        author      TEXT    NOT NULL DEFAULT '',
        kind        TEXT    NOT NULL DEFAULT 'note',
        status_from TEXT    NOT NULL DEFAULT '',
        status_to   TEXT    NOT NULL DEFAULT '',
        description TEXT    NOT NULL DEFAULT '',
        created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_finding_history_finding ON finding_history(finding_id);
    """,
    # 6: confidentiality label per report (logo and brand colour live in settings)
    """
    ALTER TABLE reports ADD COLUMN classification TEXT NOT NULL DEFAULT '';
    """,
    # 7: report structure (ordered sections), grouping findings by CWE with per-group notes
    """
    CREATE TABLE report_sections (
        id         INTEGER PRIMARY KEY,
        report_id  INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        position   INTEGER NOT NULL,
        kind       TEXT    NOT NULL,
        title      TEXT    NOT NULL DEFAULT '',
        level      INTEGER NOT NULL DEFAULT 1,
        numbered   INTEGER NOT NULL DEFAULT 1,
        new_page   INTEGER NOT NULL DEFAULT 0,
        enabled    INTEGER NOT NULL DEFAULT 1,
        body       TEXT    NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_report_sections_report ON report_sections(report_id, position);
    ALTER TABLE reports ADD COLUMN group_by_cwe INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE report_cwe_notes (
        id          INTEGER PRIMARY KEY,
        report_id   INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        cwe         TEXT    NOT NULL DEFAULT '',
        position    INTEGER NOT NULL DEFAULT 0,
        title       TEXT    NOT NULL DEFAULT '',
        description TEXT    NOT NULL DEFAULT '',
        mitigation  TEXT    NOT NULL DEFAULT '',
        UNIQUE (report_id, cwe)
    );
    """,
    # 8: global CWE library - the user's own description and mitigation per CWE
    """
    CREATE TABLE cwe_library (
        cwe         TEXT PRIMARY KEY,
        description TEXT NOT NULL DEFAULT '',
        mitigation  TEXT NOT NULL DEFAULT '',
        updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
    """,
    # 9: finding template library; retest reports linked to the original report
    """
    CREATE TABLE finding_templates (
        id                INTEGER PRIMARY KEY,
        language          TEXT    NOT NULL DEFAULT 'en',
        title             TEXT    NOT NULL,
        severity          TEXT    NOT NULL,
        cvss_version      TEXT    NOT NULL DEFAULT '',
        cvss_vector       TEXT    NOT NULL DEFAULT '',
        cwe               TEXT    NOT NULL DEFAULT '',
        description       TEXT    NOT NULL DEFAULT '',
        impact            TEXT    NOT NULL DEFAULT '',
        technical_details TEXT    NOT NULL DEFAULT '',
        poc               TEXT    NOT NULL DEFAULT '',
        remediation       TEXT    NOT NULL DEFAULT '',
        refs              TEXT    NOT NULL DEFAULT '',
        tags              TEXT    NOT NULL DEFAULT '',
        created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
        updated_at        TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_finding_templates_lang ON finding_templates(language, title);
    ALTER TABLE reports ADD COLUMN retest_of INTEGER REFERENCES reports(id) ON DELETE SET NULL;
    ALTER TABLE findings ADD COLUMN retest_result TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN retest_date TEXT;
    ALTER TABLE findings ADD COLUMN retest_notes TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN original_finding_id INTEGER;
    """,
    # 10: scanner imports waiting for the user to pick what to keep
    """
    CREATE TABLE scan_imports (
        id         INTEGER PRIMARY KEY,
        report_id  INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        format     TEXT    NOT NULL,
        filename   TEXT    NOT NULL DEFAULT '',
        payload    TEXT    NOT NULL,
        created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_scan_imports_report ON scan_imports(report_id);
    """,
    # 11: working notes per report (never part of the report itself)
    """
    CREATE TABLE report_notes (
        id         INTEGER PRIMARY KEY,
        report_id  INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        title      TEXT    NOT NULL,
        body       TEXT    NOT NULL DEFAULT '',
        pinned     INTEGER NOT NULL DEFAULT 0,
        created_at TEXT    NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_report_notes_report ON report_notes(report_id, pinned, updated_at);
    """,
    # 12: evidence files of any type per finding (pcap, logs, HAR ...), with a server-side SHA-256
    """
    CREATE TABLE IF NOT EXISTS finding_files (
        id          INTEGER PRIMARY KEY,
        finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        position    INTEGER NOT NULL,
        filename    TEXT    NOT NULL,
        description TEXT    NOT NULL DEFAULT '',
        mime        TEXT    NOT NULL,
        size        INTEGER NOT NULL,
        sha256      TEXT    NOT NULL,
        data        BLOB    NOT NULL,
        uploaded_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_finding_files_finding ON finding_files(finding_id, position);
    """,
    # 13: screenshot editor - the untouched original of an edited screenshot (NULL = never edited)
    """
    ALTER TABLE attachments ADD COLUMN original_mime TEXT;
    ALTER TABLE attachments ADD COLUMN original_data BLOB;
    ALTER TABLE attachments ADD COLUMN original_sha256 TEXT;
    ALTER TABLE attachments ADD COLUMN edited_at TEXT;
    """,
    # 14: evidence files again, for databases that ran the screenshot-editor build first: there 12 was an empty
    # placeholder, so they are at 13 without the table. A no-op where 12 already created it.
    """
    CREATE TABLE IF NOT EXISTS finding_files (
        id          INTEGER PRIMARY KEY,
        finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        position    INTEGER NOT NULL,
        filename    TEXT    NOT NULL,
        description TEXT    NOT NULL DEFAULT '',
        mime        TEXT    NOT NULL,
        size        INTEGER NOT NULL,
        sha256      TEXT    NOT NULL,
        data        BLOB    NOT NULL,
        uploaded_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_finding_files_finding ON finding_files(finding_id, position);
    """,
]


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), isolation_level=None)  # autocommit; explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations. Returns the resulting schema version."""
    conn.execute("PRAGMA journal_mode = WAL")
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current > len(MIGRATIONS):
        raise RuntimeError(
            f"Database schema version {current} is newer than this ptreport "
            f"supports ({len(MIGRATIONS)}). Please upgrade ptreport."
        )
    for version in range(current + 1, len(MIGRATIONS) + 1):
        conn.executescript(
            "BEGIN;\n" + MIGRATIONS[version - 1] + f"\nPRAGMA user_version = {version};\nCOMMIT;"
        )
    return len(MIGRATIONS)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


class transaction:
    """Explicit write transaction on an autocommit connection.

    Re-entrant: when a transaction is already open (e.g. during an import that
    calls several repository functions) the inner block joins the outer one.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.owner = False

    def __enter__(self) -> sqlite3.Connection:
        if not self.conn.in_transaction:
            self.conn.execute("BEGIN IMMEDIATE")
            self.owner = True
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.owner:
            self.conn.execute("ROLLBACK" if exc_type else "COMMIT")


def init_app(app: Flask) -> None:
    conn = connect(app.config["DATABASE"])
    try:
        migrate(conn)
    finally:
        conn.close()
    app.teardown_appcontext(close_db)
