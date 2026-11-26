"""Command-line entry point.

``ptreport`` with no subcommand starts the local server (the behaviour install.sh and the README rely on).
The subcommands work on the same SQLite database directly through the repository layer, so they are safe
to run while the server is up: the database is in WAL mode, connections wait up to 5 s for a lock
(``db.connect``) and every write runs in one ``BEGIN IMMEDIATE`` transaction.

Exit codes: 0 success, 1 error (missing report, invalid input, failed export...), 2 usage error.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
import sys
import threading
import webbrowser
from contextlib import closing
from pathlib import Path

from werkzeug.serving import make_server

from ptreport import __version__
from ptreport.app import MAX_UPLOAD_BYTES, create_app, default_data_dir
from ptreport.security import LOOPBACK_HOSTS
from ptreport.validation import LANGUAGES, SEVERITIES

DEFAULT_PORT = 5055
EXPORT_FORMATS = ("pdf", "html", "md", "json", "tex")
SCAN_FORMATS = ("auto", "burp", "nessus", "nmap", "zap", "openvas")

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2

# form field -> command-line flag, so validation messages name what the user typed
CREATE_FLAGS = {
    "title": "--title", "client_name": "--client", "assessor": "--assessor", "language": "--language",
    "finding_prefix": "--prefix", "start_date": "--start-date", "end_date": "--end-date",
    "report_date": "--report-date", "report_version": "--report-version", "classification": "--classification",
    "vendor_name": "--vendor", "vendor_contact": "--contact",
}

# C0/C1 control characters (incl. ESC): never let stored text drive the terminal
_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class CliError(Exception):
    """A user-facing error: printed as ``error: <message>`` (no traceback), exit code 1."""

    def __init__(self, message: str, code: int = EXIT_ERROR):
        super().__init__(message)
        self.code = code


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ------------------------------------------------------------------ parser --

def _report_id(value: str) -> int:
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError(f"invalid report id {value!r} (expected a positive number)")
    return int(value)


def _build_parser() -> argparse.ArgumentParser:
    data_dir_help = f"where the SQLite DB and secrets live (default: {default_data_dir()})"
    p = argparse.ArgumentParser(
        prog="ptreport",
        description="Local pentest report generator. Without a command it starts the web app.",
        epilog="Run 'ptreport <command> --help' for the options of a command.",
    )
    p.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default: {DEFAULT_PORT})")
    p.add_argument("--data-dir", default=None, help=data_dir_help)
    p.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                   help="extra Host header value to accept (needed when binding to a non-loopback address)")
    p.add_argument("--no-browser", action="store_true", help="do not open the browser")
    p.add_argument("--show-api-token", action="store_true", help="print the API token and exit")
    p.add_argument("--warm-latex", action="store_true",
                   help="typeset a sample report once so LaTeX packages are cached (used by install.sh)")
    p.add_argument("--version", action="version", version=f"ptreport {__version__}")

    # --data-dir is accepted before or after the command; SUPPRESS keeps the global value when omitted
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir", default=argparse.SUPPRESS, help=data_dir_help)

    sub = p.add_subparsers(dest="command", metavar="<command>", title="commands")

    report = sub.add_parser("report", parents=[common], help="list, create and show reports",
                            description="List, create and show reports.")
    rsub = report.add_subparsers(dest="report_command", metavar="<action>", title="actions")
    rsub.required = True

    r_list = rsub.add_parser("list", parents=[common], help="list all reports",
                             description="List all reports with their finding counts by severity.")
    r_list.add_argument("--json", action="store_true", help="print JSON instead of a table")

    r_create = rsub.add_parser(
        "create", parents=[common], help="create a report and print its id",
        description="Create a report (same rules as the web form) and print the new report id. "
                    "Prefix and language default to the values in Settings.")
    r_create.add_argument("--title", required=True, help="report title (required)")
    r_create.add_argument("--client", help="client name")
    r_create.add_argument("--assessor", help="assessor name(s), comma separated")
    r_create.add_argument("--language", choices=LANGUAGES, help="report language")
    r_create.add_argument("--prefix", help="finding ID prefix, e.g. ACME (1-10 letters/digits)")
    r_create.add_argument("--start-date", metavar="YYYY-MM-DD", help="test start date")
    r_create.add_argument("--end-date", metavar="YYYY-MM-DD", help="test end date")
    r_create.add_argument("--report-date", metavar="YYYY-MM-DD", help="date printed on the report")
    r_create.add_argument("--report-version", metavar="VERSION", help="report version, e.g. 1.0")
    r_create.add_argument("--classification", help="confidentiality label, e.g. CONFIDENTIAL")
    r_create.add_argument("--vendor", help="prepared by (company)")
    r_create.add_argument("--contact", help="vendor contact")

    r_show = rsub.add_parser("show", parents=[common], help="show a report and its findings",
                             description="Show a report summary and its findings table.")
    r_show.add_argument("report_id", type=_report_id, help="report id (see 'ptreport report list')")
    r_show.add_argument("--json", action="store_true", help="print JSON instead of text")

    scan = sub.add_parser(
        "import-scan", parents=[common], help="import a scanner file into a report",
        description="Import targets and findings from a Burp, Nessus, Nmap, ZAP or OpenVAS XML file into a "
                    "report. Everything in the file is imported (like the web review page with all boxes "
                    "ticked); targets already in the report are reused. Informational issues are skipped "
                    "unless --include-info is given.")
    scan.add_argument("report_id", type=_report_id, help="report id")
    scan.add_argument("file", help="scanner output file")
    scan.add_argument("--format", choices=SCAN_FORMATS, default="auto",
                      help="scanner format (default: auto-detect)")
    scan.add_argument("--include-info", action="store_true", help="also import informational issues")
    scan.add_argument("--dry-run", action="store_true", help="only print what would be created")
    scan.add_argument("-y", "--yes", action="store_true",
                      help="do not ask for confirmation (required when stdin is not a terminal)")

    exp = sub.add_parser(
        "export", parents=[common], help="export a report to a file",
        description="Export a report as PDF, HTML, Markdown, JSON (backup) or a LaTeX source zip (tex). "
                    "The default file name is the one the web download uses, in the current directory.")
    exp.add_argument("report_id", type=_report_id, help="report id")
    exp.add_argument("--format", required=True, choices=EXPORT_FORMATS, help="output format")
    exp.add_argument("-o", "--output", metavar="FILE",
                     help="output file, a directory, or '-' for standard output")
    exp.add_argument("--force", action="store_true", help="overwrite an existing file")

    imp = sub.add_parser("import-json", parents=[common], help="import a ptreport JSON export as a new report",
                         description="Import a JSON export (made by ptreport) as a new report and print its id.")
    imp.add_argument("file", help="JSON export file ('-' for standard input)")
    return p


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    return _build_parser().parse_args(argv)


# ----------------------------------------------------------------- helpers --

def _safe(value: object) -> str:
    """Single-line text for terminal output, with control characters neutralised."""
    text = "" if value is None else str(value)
    return _UNSAFE.sub("?", text.replace("\r\n", " ").replace("\n", " ").replace("\t", " "))


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(width - 1, 0)] + "…"


def _table(headers: list[str], rows: list[list[object]], max_widths: dict[int, int] | None = None,
           right: set[int] | None = None) -> str:
    max_widths, right = max_widths or {}, right or set()
    cells = [[_truncate(_safe(c), max_widths.get(i, 10_000)) for i, c in enumerate(row)] for row in rows]
    widths = [max([len(h)] + [len(r[i]) for r in cells]) for i, h in enumerate(headers)]

    def line(values: list[str]) -> str:
        out = [v.rjust(widths[i]) if i in right else v.ljust(widths[i]) for i, v in enumerate(values)]
        return "  ".join(out).rstrip()

    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in cells])


def _err(message: str) -> None:
    print(f"error: {_safe(message)}", file=sys.stderr)


def _warn(message: str) -> None:
    print(f"warning: {_safe(message)}", file=sys.stderr)


def _open(args: argparse.Namespace):
    """App (for config, templates and migrations) plus a fresh DB connection."""
    from ptreport import db

    config = {"DATA_DIR": args.data_dir} if args.data_dir else {}
    app = create_app(config)
    return app, db.connect(app.config["DATABASE"])


def _require_report(conn: sqlite3.Connection, report_id: int) -> dict:
    from ptreport import repo

    report = repo.get_report(conn, report_id)
    if report is None:
        raise CliError(f"report {report_id} not found (see 'ptreport report list')")
    return report


def _read_file(path: str, limit: int, what: str) -> bytes:
    if path == "-":
        data = sys.stdin.buffer.read(limit + 1)
    else:
        p = Path(path).expanduser()
        if not p.exists():
            raise CliError(f"{path}: no such file")
        if not p.is_file():
            raise CliError(f"{path}: not a regular file")
        try:
            with p.open("rb") as fh:
                data = fh.read(limit + 1)
        except OSError as exc:
            raise CliError(f"{path}: {exc.strerror or exc}") from None
    if len(data) > limit:
        raise CliError(f"{what} is larger than {limit // (1024 * 1024)} MB")
    if not data:
        raise CliError(f"{path}: file is empty")
    return data


def _confirm(question: str) -> bool:
    if not sys.stdin.isatty():
        raise CliError("refusing to import without confirmation: stdin is not a terminal, pass --yes",
                       EXIT_USAGE)
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def _dump_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------- commands --

def _report_summary(report: dict, counts: dict | None, target_count: int | None = None) -> dict:
    counts = counts or {"severity": {s: 0 for s in SEVERITIES}, "open": 0}
    severity = {s: counts["severity"].get(s, 0) for s in SEVERITIES}
    out = {
        "id": report["id"],
        "title": report["title"],
        "client": report["client_name"],
        "assessor": report["assessor"],
        "language": report["language"],
        "status": "retest" if report.get("retest_of") else "assessment",
        "retest_of": report.get("retest_of"),
        "start_date": report["start_date"],
        "end_date": report["end_date"],
        "report_date": report.get("report_date"),
        "report_version": report.get("report_version", ""),
        "created_at": report["created_at"],
        "updated_at": report["updated_at"],
        "findings": {"total": sum(severity.values()), "open": counts["open"], **severity},
    }
    if target_count is not None:
        out["targets"] = target_count
    return out


def cmd_report_list(args: argparse.Namespace) -> int:
    from ptreport import repo

    _app, conn = _open(args)
    with closing(conn):
        reports = repo.list_reports(conn)
        counts = repo.finding_counts_by_report(conn)
    items = [_report_summary(r, counts.get(r["id"]), r["target_count"]) for r in reports]
    if args.json:
        _dump_json(items)
        return EXIT_OK
    if not items:
        print("No reports yet. Create one with: ptreport report create --title \"...\"")
        return EXIT_OK
    sev_heads = ["Crit", "High", "Med", "Low", "Info"]
    rows = []
    for r in items:
        period = (r["start_date"] or "") + (f" – {r['end_date']}" if r["end_date"] else "")
        f = r["findings"]
        rows.append([r["id"], r["title"], r["client"], r["language"], r["status"], period,
                     *[f[s] for s in SEVERITIES], f["total"], r["updated_at"]])
    print(_table(["ID", "Title", "Client", "Lang", "Type", "Period", *sev_heads, "Total", "Updated (UTC)"],
                 rows, max_widths={1: 48, 2: 28}, right={0, 6, 7, 8, 9, 10, 11}))
    return EXIT_OK


def cmd_report_create(args: argparse.Namespace) -> int:
    from ptreport import repo
    from ptreport.validation import validate_report

    _app, conn = _open(args)
    with closing(conn):
        defaults = repo.get_settings(conn)
        form = {
            "title": args.title, "client_name": args.client, "assessor": args.assessor,
            "language": args.language or defaults["default_language"],
            "finding_prefix": args.prefix if args.prefix is not None else defaults["default_prefix"],
            "start_date": args.start_date, "end_date": args.end_date, "report_date": args.report_date,
            "report_version": args.report_version, "classification": args.classification,
            "vendor_name": args.vendor, "vendor_contact": args.contact,
        }
        data, errors = validate_report({k: v for k, v in form.items() if v is not None})
        if errors:
            for field, message in errors.items():
                _err(f"{CREATE_FLAGS.get(field, field)}: {message}")
            return EXIT_ERROR
        report_id = repo.create_report(conn, data)
    print(report_id)
    return EXIT_OK


def cmd_report_show(args: argparse.Namespace) -> int:
    from ptreport import repo

    _app, conn = _open(args)
    with closing(conn):
        report = _require_report(conn, args.report_id)
        findings = repo.list_findings(conn, report["id"])
        targets = repo.list_targets(conn, report["id"])
        settings = repo.get_settings(conn)
        counts = repo.finding_counts_by_report(conn).get(report["id"])
        original = repo.get_report(conn, report["retest_of"]) if report.get("retest_of") else None
    summary = _report_summary(report, counts, len(targets))
    rows = []
    for f in findings:
        cvss = f"{f['cvss_score']:.1f}" if f["cvss_score"] is not None and f["cvss_version"] else ""
        rows.append({"id": f["id"], "display_id": repo.finding_display_id(report, f, settings),
                     "title": f["title"], "severity": f["severity"], "status": f["status"],
                     "cvss_version": f["cvss_version"], "cvss_score": f["cvss_score"] if cvss else None,
                     "cwe": f["cwe"], "targets": [t["name"] for t in f["targets"]],
                     "retest_result": f["retest_result"], "_cvss": cvss})
    if args.json:
        summary["targets"] = [{"id": t["id"], "name": t["name"], "kind": t["kind"], "address": t["address"]}
                              for t in targets]
        summary["finding_list"] = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
        _dump_json(summary)
        return EXIT_OK

    f = summary["findings"]
    period = (report["start_date"] or "?") + " – " + (report["end_date"] or "?")
    lines = [
        f"Report #{report['id']}: {_safe(report['title'])}",
        "",
        f"  Client:      {_safe(report['client_name']) or '-'}",
        f"  Assessor:    {_safe(report['assessor']) or '-'}",
        f"  Language:    {report['language']}",
        f"  Period:      {period if report['start_date'] or report['end_date'] else '-'}",
        f"  Report date: {report.get('report_date') or '-'}"
        + (f"   version {_safe(report['report_version'])}" if report.get("report_version") else ""),
    ]
    if original:
        lines.append(f"  Retest of:   #{original['id']} {_safe(original['title'])}")
    lines += [
        f"  Targets:     {len(targets)}",
        f"  Findings:    {f['total']} ({f['open']} open) – "
        + ", ".join(f"{s} {f[s]}" for s in SEVERITIES),
        f"  Updated:     {report['updated_at']} UTC",
        "",
    ]
    print("\n".join(lines))
    if not rows:
        print("No findings yet.")
        return EXIT_OK
    print(_table(["ID", "Severity", "Status", "CVSS", "CWE", "Title", "Targets"],
                 [[r["display_id"], r["severity"], r["status"], r["_cvss"], r["cwe"], r["title"],
                   ", ".join(r["targets"])] for r in rows],
                 max_widths={5: 60, 6: 40}, right={3}))
    return EXIT_OK


def cmd_import_scan(args: argparse.Namespace) -> int:
    from ptreport import importers, repo

    if not (args.dry_run or args.yes or sys.stdin.isatty()):
        raise CliError("stdin is not a terminal, so there is no one to confirm: pass --yes (or --dry-run)",
                       EXIT_USAGE)
    _app, conn = _open(args)
    with closing(conn):
        report = _require_report(conn, args.report_id)
        data = _read_file(args.file, importers.MAX_BYTES, "The scanner file")
        fmt = None if args.format == "auto" else args.format
        try:
            parsed = importers.parse(data, fmt, include_info=args.include_info)
        except importers.ImportError_ as exc:
            raise CliError(str(exc)) from None
        cleaned = importers.clean(parsed)
        if not cleaned["targets"] and not cleaned["findings"]:
            for w in cleaned["warnings"][:10]:
                _warn(w)
            raise CliError("nothing to import: the file has no hosts or issues"
                           + (" (informational issues were left out; try --include-info)"
                              if cleaned["format"] != "nmap" and not args.include_info else ""))
        existing = {repo.target_match_key(t) for t in repo.list_targets(conn, report["id"])}
        reused = sum(1 for t in cleaned["targets"] if repo.target_match_key(t) in existing)
        label = importers.LABELS.get(cleaned["format"], cleaned["format"])

        print(f"{label}: {len(cleaned['findings'])} finding(s), {len(cleaned['targets'])} target(s) "
              f"({len(cleaned['targets']) - reused} new, {reused} already in the report)")
        print(f"Report #{report['id']}: {_safe(report['title'])}\n")
        if cleaned["targets"]:
            print(_table(["Target", "Kind", "Address", "Action"],
                         [[t["name"], t["kind"], t["address"],
                           "reuse existing" if repo.target_match_key(t) in existing else "new"]
                          for t in cleaned["targets"]], max_widths={0: 50, 2: 50}))
            print()
        if cleaned["findings"]:
            order = {s: i for i, s in enumerate(SEVERITIES)}
            print(_table(["Severity", "CVSS", "Title", "Targets", "Evidence"],
                         [[f["severity"], f"{f['cvss_score']:.1f}" if f.get("cvss_score") is not None else "",
                           f["title"], len(f["target_keys"]), len(f["evidence"])]
                          for f in sorted(cleaned["findings"], key=lambda f: order.get(f["severity"], 99))],
                         max_widths={2: 70}, right={1, 3, 4}))
            print()
        for w in cleaned["warnings"]:
            _warn(w.replace("enable 'include informational'", "pass --include-info"))
        if args.dry_run:
            print("Dry run: nothing was changed.")
            return EXIT_OK
        if not args.yes and not _confirm(f"Import into report #{report['id']}?"):
            print("Aborted: nothing was imported.", file=sys.stderr)
            return EXIT_ERROR
        staged = {"id": None, "report_id": report["id"], "format": cleaned["format"],
                  "filename": Path(args.file).name[:200] if args.file != "-" else "", "parsed": cleaned}
        created, reused_n, n_findings = repo.apply_scan_import(
            conn, staged, {t["key"] for t in cleaned["targets"]}, {f["key"] for f in cleaned["findings"]})
    print(f"Imported {n_findings} finding(s) and {created} new target(s)"
          + (f"; {reused_n} target(s) already in the report were reused" if reused_n else "") + ".")
    return EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    from ptreport import export, latex

    app, conn = _open(args)
    with closing(conn), app.app_context():
        _require_report(conn, args.report_id)
        try:
            body, _mime, filename = export.render_download(conn, args.report_id, args.format)
        except latex.LatexError as exc:
            if exc.log:
                print(exc.log, file=sys.stderr)
            raise CliError(f"PDF export failed: {exc}") from None

    if args.output == "-":
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
        return EXIT_OK
    target = Path(args.output).expanduser() if args.output else Path.cwd() / filename
    if target.is_dir():
        target = target / filename
    if not target.parent.is_dir():
        raise CliError(f"{target.parent}: directory does not exist")
    try:
        # "x" refuses to replace an existing file atomically (no check-then-write race)
        with open(target, "wb" if args.force else "xb") as fh:
            fh.write(body)
    except FileExistsError:
        raise CliError(f"{target} already exists (use --force to overwrite)") from None
    except OSError as exc:
        raise CliError(f"{target}: {exc.strerror or exc}") from None
    print(f"Wrote {target} ({len(body):,} bytes)")
    return EXIT_OK


def cmd_import_json(args: argparse.Namespace) -> int:
    from ptreport import export

    data = _read_file(args.file, MAX_UPLOAD_BYTES, "The JSON file")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CliError("file is not valid UTF-8 JSON") from None
    _app, conn = _open(args)
    with closing(conn):
        try:
            report_id = export.import_json(conn, payload)
        except export.ImportError_ as exc:
            for problem in exc.errors[:50]:
                _err(problem)
            if len(exc.errors) > 50:
                _err(f"... and {len(exc.errors) - 50} more problem(s)")
            raise CliError("import failed: nothing was imported") from None
    print(report_id)
    return EXIT_OK


COMMANDS = {
    ("report", "list"): cmd_report_list,
    ("report", "create"): cmd_report_create,
    ("report", "show"): cmd_report_show,
    ("import-scan", None): cmd_import_scan,
    ("export", None): cmd_export,
    ("import-json", None): cmd_import_json,
}


def run_command(args: argparse.Namespace) -> int:
    handler = COMMANDS[(args.command, getattr(args, "report_command", None))]
    try:
        return handler(args)
    except CliError as exc:
        _err(str(exc))
        return exc.code
    except sqlite3.Error as exc:
        _err(f"database: {exc}")
        return EXIT_ERROR
    except RuntimeError as exc:  # e.g. the database schema is newer than this version
        _err(str(exc))
        return EXIT_ERROR
    except OSError as exc:  # data directory not writable, ...
        _err(f"{getattr(exc, 'filename', '') or ''} {exc.strerror or exc}".strip())
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return EXIT_ERROR


# ------------------------------------------------------------------ server --

def serve(args: argparse.Namespace) -> int:
    if not 1 <= args.port <= 65535:
        print("error: --port must be between 1 and 65535", file=sys.stderr)
        return 2

    allowed = set(LOOPBACK_HOSTS) | {h.lower() for h in args.allow_host}
    if args.host not in ("0.0.0.0", "::"):  # noqa: S104 - comparison, not a bind
        allowed.add(args.host.lower())
    config = {"ALLOWED_HOSTS": allowed}
    if args.data_dir:
        config["DATA_DIR"] = args.data_dir
    app = create_app(config)

    if args.warm_latex:
        from ptreport import latex

        try:
            source, files = latex.render(latex.sample_context())
            latex.compile_pdf(source, files)
        except latex.LatexError as exc:
            print(f"error: {exc}\n{exc.log}", file=sys.stderr)
            return 1
        print("LaTeX engine ready:", " ".join(latex.find_engine() or ("none",)))
        return 0

    if args.show_api_token:
        print(app.config["API_TOKEN"])
        return 0

    if not _is_loopback(args.host):
        print(
            "WARNING: ptreport is listening on a non-loopback interface. Anyone who can reach\n"
            "         this port can read and modify your reports. There is no login screen.",
            file=sys.stderr,
        )

    try:
        server = make_server(args.host, args.port, app, threaded=True)
    except OSError as exc:
        print(f"error: cannot listen on {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1

    display_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host  # noqa: S104
    if ":" in display_host:
        display_host = f"[{display_host}]"
    url = f"http://{display_host}:{args.port}/"
    print(f"ptreport {__version__} running at {url}")
    print(f"Data directory: {app.config['DATA_DIR']}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as exc:  # --help / --version (0) or a usage error (2), already printed by argparse
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    if args.command is None:
        return serve(args)
    return run_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
