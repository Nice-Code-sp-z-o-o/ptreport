"""Command-line interface: ``cli.main([...])`` against temporary data directories."""

import json
import sqlite3
from pathlib import Path

import pytest

from ptreport import cli, latex

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


@pytest.fixture()
def data_dir(tmp_path):
    return str(tmp_path / "data")


@pytest.fixture()
def run(data_dir, capsys):
    """Run the CLI with the temp data dir; returns (exit code, stdout, stderr)."""
    def _run(*argv, data_dir_arg=True):
        argv = (["--data-dir", data_dir] if data_dir_arg else []) + list(argv)
        code = cli.main(argv)
        out, err = capsys.readouterr()
        return code, out, err
    return _run


@pytest.fixture()
def report_id(run):
    code, out, err = run("report", "create", "--title", "ACME web app", "--client", "ACME",
                         "--assessor", "Jan Kowalski", "--start-date", "2026-11-01", "--end-date", "2026-11-10")
    assert code == 0, err
    return int(out.strip())


def _count(data_dir, table):
    conn = sqlite3.connect(Path(data_dir) / "ptreport.db")
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608 - test constant
    finally:
        conn.close()


# ------------------------------------------------------------------ parsing --

def test_plain_ptreport_is_server_mode():
    args = cli.parse_args([])
    assert args.command is None
    assert (args.host, args.port, args.data_dir, args.no_browser) == ("127.0.0.1", cli.DEFAULT_PORT, None, False)


def test_existing_server_flags_still_parse():
    args = cli.parse_args(["--host", "0.0.0.0", "--port", "6000", "--data-dir", "/srv/pt", "--no-browser",  # noqa: S104
                           "--allow-host", "box.lan", "--show-api-token", "--warm-latex"])
    assert args.command is None
    assert args.port == 6000 and args.data_dir == "/srv/pt" and args.no_browser and args.show_api_token
    assert args.warm_latex and args.allow_host == ["box.lan"]


def test_server_mode_dispatch(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "serve", lambda args: seen.setdefault("args", args) and 0)
    cli.main(["--no-browser", "--port", "5999"])
    assert seen["args"].command is None and seen["args"].port == 5999


def test_show_api_token_still_works(run, data_dir):
    code, out, _ = run("--show-api-token")
    assert code == 0
    assert out.strip() == (Path(data_dir) / "api_token").read_text().strip()


def test_data_dir_after_the_command(run, data_dir, report_id):
    code, out, _ = run("report", "list", "--json", "--data-dir", data_dir, data_dir_arg=False)
    assert code == 0 and json.loads(out)[0]["id"] == report_id


@pytest.mark.parametrize("argv", [
    ["bogus"], ["report"], ["report", "show"], ["report", "show", "abc"], ["report", "show", "0"],
    ["report", "create"], ["report", "create", "--title", "x", "--language", "de"],
    ["export", "1"], ["export", "1", "--format", "docx"], ["import-scan", "1"],
    ["import-scan", "1", "f.xml", "--format", "qualys"],
])
def test_usage_errors_exit_2(run, argv):
    code, _, err = run(*argv)
    assert code == 2
    assert "usage:" in err and "Traceback" not in err


@pytest.mark.parametrize("argv", [
    [], ["report"], ["report", "list"], ["report", "create"], ["report", "show"],
    ["import-scan"], ["export"], ["import-json"],
])
def test_help_for_every_command(capsys, argv):
    assert cli.main([*argv, "--help"]) == 0
    assert "usage: ptreport" in capsys.readouterr().out


# ------------------------------------------------------------------ reports --

def test_report_list_empty(run):
    code, out, _ = run("report", "list")
    assert code == 0 and "No reports yet" in out
    code, out, _ = run("report", "list", "--json")
    assert code == 0 and json.loads(out) == []


def test_report_create_and_list(run, report_id):
    assert report_id == 1
    code, out, _ = run("report", "list")
    assert code == 0
    assert "ACME web app" in out and "2026-11-01 – 2026-11-10" in out
    code, out, _ = run("report", "list", "--json")
    items = json.loads(out)
    assert items[0]["title"] == "ACME web app" and items[0]["client"] == "ACME"
    assert items[0]["language"] == "en" and items[0]["status"] == "assessment"
    assert items[0]["findings"] == {"total": 0, "open": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                                    "info": 0}


def test_report_create_uses_settings_defaults_and_options(run):
    code, out, err = run("report", "create", "--title", "Raport", "--language", "pl", "--prefix", "lt",
                         "--report-version", "1.1", "--classification", "POUFNE")
    assert code == 0, err
    code, out, _ = run("report", "show", out.strip(), "--json")
    shown = json.loads(out)
    assert shown["language"] == "pl" and shown["report_version"] == "1.1"


def test_report_create_validation_errors(run, data_dir):
    code, out, err = run("report", "create", "--title", "  ", "--assessor", "R2D2", "--prefix", "1x",
                         "--start-date", "2026-11-10", "--end-date", "2026-11-01")
    assert code == 1 and out == ""
    assert "--title: Report title is required." in err
    assert "--assessor:" in err and "--prefix:" in err and "--end-date:" in err
    assert "Traceback" not in err
    assert _count(data_dir, "reports") == 0


def test_report_create_rejects_bad_date_and_control_chars(run, data_dir):
    code, _, err = run("report", "create", "--title", "X", "--start-date", "2026-02-30")
    assert code == 1 and "--start-date" in err
    code, _, err = run("report", "create", "--title", "bad\x1b[31mtitle")
    assert code == 1 and "single line" in err
    assert _count(data_dir, "reports") == 0


def test_report_show(run, report_id):
    assert run("import-scan", str(report_id), str(FIXTURES / "burp.xml"), "--yes")[0] == 0
    code, out, _ = run("report", "show", str(report_id))
    assert code == 0
    assert "Report #1: ACME web app" in out and "Jan Kowalski" in out
    assert "Cross-site scripting (reflected)" in out and "VULN-001" in out and "CWE-79" in out
    code, out, _ = run("report", "show", str(report_id), "--json")
    shown = json.loads(out)
    assert shown["findings"]["total"] == len(shown["finding_list"]) == 2
    assert shown["findings"]["high"] == 1 and len(shown["targets"]) == 2


def test_report_show_missing(run):
    code, out, err = run("report", "show", "42")
    assert code == 1 and out == ""
    assert err.startswith("error: report 42 not found") and "Traceback" not in err


def test_terminal_escapes_are_neutralised(run, data_dir, report_id):
    conn = sqlite3.connect(Path(data_dir) / "ptreport.db")
    conn.execute("UPDATE reports SET client_name = ? WHERE id = ?", ("Evil\x1b]0;pwn\x07Corp", report_id))
    conn.commit()
    conn.close()
    for argv in (["report", "list"], ["report", "show", str(report_id)]):
        code, out, _ = run(*argv)
        assert code == 0 and "\x1b" not in out and "\x07" not in out and "Evil?]0;pwn?Corp" in out


# -------------------------------------------------------------- scan import --

def test_import_scan_dry_run_creates_nothing(run, data_dir, report_id):
    code, out, err = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"), "--dry-run")
    assert code == 0, err
    assert "Cross-site scripting (reflected)" in out and "Dry run: nothing was changed." in out
    assert "--include-info" in err  # the informational issue was left out
    assert _count(data_dir, "findings") == 0 and _count(data_dir, "targets") == 0
    assert _count(data_dir, "scan_imports") == 0


def test_import_scan_yes(run, data_dir, report_id):
    code, out, err = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"), "--yes")
    assert code == 0, err
    assert "Imported 2 finding(s) and 2 new target(s)." in out
    assert _count(data_dir, "findings") == 2 and _count(data_dir, "http_evidence") >= 1
    assert _count(data_dir, "scan_imports") == 0
    # second run reuses the targets
    code, out, _ = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"), "--yes", "--format", "burp")
    assert code == 0 and "2 target(s) already in the report were reused" in out
    assert _count(data_dir, "targets") == 2 and _count(data_dir, "findings") == 4


def test_import_scan_include_info(run, data_dir, report_id):
    code, _, _ = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"), "--yes", "--include-info")
    assert code == 0 and _count(data_dir, "findings") == 3


@pytest.mark.parametrize("fixture", ["nessus.nessus", "nmap.xml", "zap.xml", "openvas.xml"])
def test_import_scan_other_formats(run, data_dir, report_id, fixture):
    code, _, err = run("import-scan", str(report_id), str(FIXTURES / fixture), "--yes")
    assert code == 0, err
    assert _count(data_dir, "targets") > 0


def test_import_scan_confirmation_on_tty(run, data_dir, report_id, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    code, _, err = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"))
    assert code == 1 and "nothing was imported" in err
    assert _count(data_dir, "findings") == 0
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    code, out, _ = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"))
    assert code == 0 and _count(data_dir, "findings") == 2


def test_import_scan_without_tty_needs_yes(run, data_dir, report_id, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code, _, err = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"))
    assert code == 2 and "--yes" in err
    assert _count(data_dir, "findings") == 0


def test_import_scan_errors(run, data_dir, report_id, tmp_path):
    code, _, err = run("import-scan", "99", str(FIXTURES / "burp.xml"), "--yes")
    assert code == 1 and "report 99 not found" in err
    code, _, err = run("import-scan", str(report_id), str(tmp_path / "nope.xml"), "--yes")
    assert code == 1 and "no such file" in err
    code, _, err = run("import-scan", str(report_id), str(tmp_path), "--yes")
    assert code == 1 and "not a regular file" in err
    for bad in ("xxe.xml", "billion_laughs.xml", "not_xml.txt", "wrong_root.xml"):
        code, _, err = run("import-scan", str(report_id), str(FIXTURES / bad), "--yes")
        assert code == 1 and err.startswith("error:") and "Traceback" not in err, bad
    code, _, err = run("import-scan", str(report_id), str(FIXTURES / "burp.xml"), "--yes", "--format", "nessus")
    assert code == 1 and "burp" in err
    assert _count(data_dir, "findings") == 0


def test_import_scan_nothing_to_import(run, report_id):
    code, _, err = run("import-scan", str(report_id), str(FIXTURES / "nmap_down.xml"), "--yes")
    assert code == 1 and "nothing to import" in err


# ------------------------------------------------------------------- export --

@pytest.mark.parametrize("fmt,ext,marker", [("md", "md", b"# ACME web app"), ("html", "html", b"<html"),
                                            ("json", "json", b'"format": "ptreport"')])
def test_export_default_name_in_cwd(run, report_id, tmp_path, monkeypatch, fmt, ext, marker):
    monkeypatch.chdir(tmp_path)
    code, out, err = run("export", str(report_id), "--format", fmt)
    assert code == 0, err
    target = tmp_path / f"ACME_web_app.{ext}"
    assert target.exists() and marker in target.read_bytes()
    assert str(target) in out


def test_export_refuses_overwrite_without_force(run, report_id, tmp_path):
    out_file = tmp_path / "r.md"
    out_file.write_text("keep me")
    code, _, err = run("export", str(report_id), "--format", "md", "-o", str(out_file))
    assert code == 1 and "already exists" in err and "--force" in err
    assert out_file.read_text() == "keep me"
    code, _, _ = run("export", str(report_id), "--format", "md", "-o", str(out_file), "--force")
    assert code == 0 and out_file.read_text().startswith("# ACME web app")


def test_export_into_directory_and_stdout(run, report_id, tmp_path):
    code, _, _ = run("export", str(report_id), "--format", "json", "-o", str(tmp_path))
    assert code == 0
    doc = json.loads((tmp_path / "ACME_web_app.json").read_text())
    assert doc["report"]["title"] == "ACME web app"
    code, out, _ = run("export", str(report_id), "--format", "md", "-o", "-")
    assert code == 0 and out.startswith("# ACME web app")


def test_export_errors(run, report_id, tmp_path):
    code, _, err = run("export", "7", "--format", "md", "-o", str(tmp_path / "x.md"))
    assert code == 1 and "report 7 not found" in err
    assert not (tmp_path / "x.md").exists()
    code, _, err = run("export", str(report_id), "--format", "md", "-o", str(tmp_path / "missing" / "x.md"))
    assert code == 1 and "does not exist" in err


def test_export_pdf(run, report_id, tmp_path, monkeypatch):
    monkeypatch.setattr(latex, "compile_pdf", lambda source, files, **kw: b"%PDF-1.7 fake")
    code, _, err = run("export", str(report_id), "--format", "pdf", "-o", str(tmp_path))
    assert code == 0, err
    assert (tmp_path / "ACME_web_app.pdf").read_bytes() == b"%PDF-1.7 fake"


def test_export_pdf_failure_is_reported(run, report_id, tmp_path, monkeypatch):
    def boom(*a, **kw):
        raise latex.LatexError("No LaTeX engine found.", "")
    monkeypatch.setattr(latex, "compile_pdf", boom)
    code, _, err = run("export", str(report_id), "--format", "pdf", "-o", str(tmp_path))
    assert code == 1 and "PDF export failed: No LaTeX engine found." in err and "Traceback" not in err
    assert not (tmp_path / "ACME_web_app.pdf").exists()


def test_export_matches_web_download(run, report_id, tmp_path, data_dir):
    from ptreport.app import create_app

    run("export", str(report_id), "--format", "md", "-o", str(tmp_path / "cli.md"))
    client = create_app({"DATA_DIR": data_dir, "TESTING": True}).test_client()
    web = client.get(f"/reports/{report_id}/export/md")
    assert web.status_code == 200
    assert 'filename="ACME_web_app.md"' in web.headers["Content-Disposition"]
    strip = [line for line in (tmp_path / "cli.md").read_text().splitlines() if "UTC" not in line]
    assert strip == [line for line in web.get_data(as_text=True).splitlines() if "UTC" not in line]


# -------------------------------------------------------------- JSON import --

def test_import_json_roundtrip(run, data_dir, report_id, tmp_path):
    run("import-scan", str(report_id), str(FIXTURES / "burp.xml"), "--yes")
    run("export", str(report_id), "--format", "json", "-o", str(tmp_path / "backup.json"))
    code, out, err = run("import-json", str(tmp_path / "backup.json"))
    assert code == 0, err
    new_id = int(out.strip())
    assert new_id != report_id
    code, out, _ = run("report", "show", str(new_id), "--json")
    shown = json.loads(out)
    assert shown["title"] == "ACME web app" and shown["findings"]["total"] == 2


def test_import_json_errors(run, data_dir, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    code, _, err = run("import-json", str(bad))
    assert code == 1 and "not valid UTF-8 JSON" in err
    bad.write_text(json.dumps({"format": "something-else"}))
    code, _, err = run("import-json", str(bad))
    assert code == 1 and "Not a ptreport export file." in err
    bad.write_text(json.dumps({"format": "ptreport", "version": 1, "report": {"title": ""}}))
    code, _, err = run("import-json", str(bad))
    assert code == 1 and "title" in err.lower() and "nothing was imported" in err
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    code, _, err = run("import-json", str(empty))
    assert code == 1 and "empty" in err
    code, _, err = run("import-json", str(tmp_path / "missing.json"))
    assert code == 1 and "no such file" in err
    assert _count(data_dir, "reports") == 0


def test_concurrent_writer_with_open_server_connection(run, data_dir, report_id):
    """The web app keeps its own connection; CLI writes go through while it is open (WAL)."""
    from ptreport import db

    other = db.connect(Path(data_dir) / "ptreport.db")
    try:
        other.execute("SELECT * FROM reports").fetchall()
        assert other.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        code, _, _ = run("report", "create", "--title", "Second")
        assert code == 0
        assert other.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 2
    finally:
        other.close()
