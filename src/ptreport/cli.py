"""Command-line entry point: ``ptreport`` starts the local server."""

from __future__ import annotations

import argparse
import ipaddress
import sys
import threading
import webbrowser

from werkzeug.serving import make_server

from ptreport import __version__
from ptreport.app import create_app, default_data_dir
from ptreport.security import LOOPBACK_HOSTS

DEFAULT_PORT = 5055


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="ptreport", description="Local pentest report generator.")
    p.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default: {DEFAULT_PORT})")
    p.add_argument("--data-dir", default=None,
                   help=f"where the SQLite DB and secrets live (default: {default_data_dir()})")
    p.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                   help="extra Host header value to accept (needed when binding to a non-loopback address)")
    p.add_argument("--no-browser", action="store_true", help="do not open the browser")
    p.add_argument("--show-api-token", action="store_true", help="print the API token and exit")
    p.add_argument("--warm-latex", action="store_true",
                   help="typeset a sample report once so LaTeX packages are cached (used by install.sh)")
    p.add_argument("--version", action="version", version=f"ptreport {__version__}")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
