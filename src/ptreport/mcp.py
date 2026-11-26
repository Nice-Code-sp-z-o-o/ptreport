"""Model Context Protocol server for ptreport (``ptreport mcp``), stdio transport, no dependencies.

JSON-RPC 2.0 messages, one per line (newline-delimited JSON, as the MCP stdio transport specifies). Only protocol
messages are written to stdout; logs go to stderr. Supported: ``initialize``, ``notifications/initialized``,
``ping``, ``tools/list`` and ``tools/call``.

Read tools return report data (reports, findings, scope, CWE, templates, proposals). Write tools only ever create
**proposals** in the report's AI queue (see :mod:`ptreport.proposals`); a person accepts them in the browser.
``--read-only`` hides the write tools, ``--report ID`` pins every call to one report.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import traceback
from collections.abc import Callable
from typing import Any, TextIO

from ptreport import __version__, proposals, repo, scope
from ptreport.cwe import search as cwe_search
from ptreport.validation import CODE_LANGUAGES, RETEST_RESULTS, SEVERITIES, TARGET_KINDS

# Newest first; a client asking for one of these gets it, anything else gets the newest.
PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MAX_LINE_BYTES = 64 * 1024 * 1024  # a propose_file call carries up to 25 MB as base64

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603

INSTRUCTIONS = (
    "ptreport is the pentest report of record. Start with list_reports / get_scope to learn the engagement "
    "(targets, dates, what is out of scope) and get_report for the findings already written. Send your results "
    "with the propose_* tools: every one becomes a proposal in the report's AI queue, which a person reviews "
    "before anything reaches the report. Include proof (HTTP requests/responses, code locations, files) and set "
    "verdict to 'verified' only when your own verification confirmed the issue. Use propose_retest_result only "
    "for explicit retest results; never report something as fixed just because you did not see it again."
)


class ToolError(Exception):
    """A tool call that failed in a way the model can correct; returned as a result with isError: true."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _log(message: str) -> None:
    print(f"ptreport-mcp: {message}", file=sys.stderr, flush=True)


# -------------------------------------------------------------- schemas --

def _str(description: str, max_length: int | None = None, **extra) -> dict:
    out = {"type": "string", "description": description, **extra}
    if max_length:
        out["maxLength"] = max_length
    return out


SOURCE_SCHEMA = {
    "type": "object", "description": "Who produced this result (shown to the reviewer and kept as the finding's "
                                     "origin). Defaults to the MCP client's name.",
    "properties": {"tool": _str("Tool or agent name, e.g. ptai, decepticon, ghidra-agent", 100),
                   "version": _str("Tool version", 50), "run_id": _str("Run / engagement / session id", 100),
                   "model": _str("Model that produced it", 100)},
    "additionalProperties": False,
}
VERDICT_SCHEMA = {"type": "string", "enum": ["verified", "candidate", ""],
                  "description": "verified = confirmed by your own verification (replayed, oracle); "
                                 "candidate = unconfirmed lead"}
HTTP_SCHEMA = {"type": "object", "properties": {
    "title": _str("Short title", 300), "request": _str("Raw HTTP request", 5_000_000),
    "response": _str("Raw HTTP response (optional)", 5_000_000)}, "required": ["request"]}
CODE_SCHEMA = {"type": "object", "properties": {
    "title": _str("Short title", 300),
    "location": _str("File / function / address, e.g. 'bin/auth:check_pw @ 0x401a2c'", 300),
    "language": {"type": "string", "enum": list(CODE_LANGUAGES)},
    "code": _str("The snippet: decompiled function, disassembly, source excerpt", 200_000),
    "note": _str("What the reviewer should look at", 20_000)}, "required": ["code"]}
TARGET_SCHEMA = {"anyOf": [
    _str("An address: a URL becomes a web target, anything else a host"),
    {"type": "object", "properties": {"name": _str("Name", 200), "kind": {"type": "string", "enum": list(TARGET_KINDS)},
                                      "address": _str("URL / host / IP range / file path", 2048),
                                      "description": _str("Notes")}},
]}


def _schema(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


# -------------------------------------------------------------- server --

class McpServer:
    def __init__(self, conn: sqlite3.Connection, *, report_id: int | None = None, read_only: bool = False):
        self.conn = conn
        self.pinned = report_id
        self.read_only = read_only
        self.client: dict = {}
        self.protocol_version = PROTOCOL_VERSIONS[0]
        self.tools = self._tools()

    # ------------------------------------------------------------ transport --

    def serve(self, stdin, stdout: TextIO) -> None:
        """Read newline-delimited JSON-RPC messages from ``stdin`` (binary) and answer on ``stdout`` (text)."""
        while True:
            line = stdin.readline(MAX_LINE_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
                while True:  # drop the rest of the oversized message
                    chunk = stdin.readline(MAX_LINE_BYTES + 1)
                    if not chunk or chunk.endswith(b"\n"):
                        break
                self._write(stdout, _error(None, INVALID_REQUEST, "Message too large."))
                continue
            response = self.handle_line(line)
            if response is not None:
                self._write(stdout, response)

    @staticmethod
    def _write(stdout: TextIO, message: dict) -> None:
        stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        stdout.flush()

    def handle_line(self, line: bytes | str) -> dict | None:
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError:
                return _error(None, PARSE_ERROR, "Parse error: not UTF-8.")
        if not line.strip():
            return None
        try:
            message = json.loads(line)
        except (ValueError, RecursionError):
            return _error(None, PARSE_ERROR, "Parse error: invalid JSON.")
        return self.handle(message)

    # ------------------------------------------------------------- JSON-RPC --

    def handle(self, message: Any) -> dict | None:
        if isinstance(message, list):
            return _error(None, INVALID_REQUEST, "Batch requests are not supported.")
        if not isinstance(message, dict):
            return _error(None, INVALID_REQUEST, "Invalid request: expected a JSON object.")
        has_id = "id" in message
        msg_id = message.get("id")
        if has_id and (isinstance(msg_id, bool) or not isinstance(msg_id, (str, int))):
            return _error(None, INVALID_REQUEST, "Invalid request: id must be a string or an integer.")
        if message.get("jsonrpc") != "2.0":
            return _error(msg_id if has_id else None, INVALID_REQUEST, "Invalid request: jsonrpc must be \"2.0\".")
        method = message.get("method")
        if method is None and ("result" in message or "error" in message):
            return None  # a response to a request we never send
        if not isinstance(method, str):
            return _error(msg_id if has_id else None, INVALID_REQUEST, "Invalid request: method must be a string.")
        params = message.get("params")
        if params is None:
            params = {}
        if not has_id:  # notification: never answered
            if method == "notifications/initialized":
                _log("client initialized")
            return None
        if not isinstance(params, dict):
            return _error(msg_id, INVALID_PARAMS, "Invalid params: expected an object.")
        try:
            return {"jsonrpc": "2.0", "id": msg_id, "result": self._dispatch(method, params)}
        except RpcError as exc:
            return _error(msg_id, exc.code, str(exc))
        except Exception:  # noqa: BLE001 - never let one call kill the server
            _log("internal error:\n" + traceback.format_exc())
            return _error(msg_id, INTERNAL_ERROR, "Internal error.")

    def _dispatch(self, method: str, params: dict) -> dict:
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [self._describe(t) for t in self.tools.values() if self._visible(t)]}
        if method == "tools/call":
            return self._call(params)
        raise RpcError(METHOD_NOT_FOUND, f"Method not found: {method}")

    def _initialize(self, params: dict) -> dict:
        requested = params.get("protocolVersion")
        self.protocol_version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        info = params.get("clientInfo")
        self.client = {k: str(info.get(k))[:100] for k in ("name", "version") if isinstance(info, dict)
                       and isinstance(info.get(k), str)}
        _log(f"initialize from {self.client.get('name', 'unknown client')}, protocol {self.protocol_version}"
             + (f", pinned to report {self.pinned}" if self.pinned else "") + (", read-only" if self.read_only else ""))
        return {"protocolVersion": self.protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "ptreport", "title": "ptreport", "version": __version__},
                "instructions": INSTRUCTIONS}

    def _visible(self, tool: dict) -> bool:
        return not (self.read_only and tool["write"])

    @staticmethod
    def _describe(tool: dict) -> dict:
        return {"name": tool["name"], "title": tool["title"], "description": tool["description"],
                "inputSchema": tool["schema"],
                "annotations": {"title": tool["title"], "readOnlyHint": not tool["write"], "destructiveHint": False,
                                "idempotentHint": not tool["write"], "openWorldHint": False}}

    def _call(self, params: dict) -> dict:
        name = params.get("name")
        tool = self.tools.get(name) if isinstance(name, str) else None
        if tool is None or not self._visible(tool):
            raise RpcError(INVALID_PARAMS, f"Unknown tool: {name}")
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise RpcError(INVALID_PARAMS, "Invalid params: arguments must be an object.")
        try:
            missing = [k for k in tool["schema"].get("required", []) if args.get(k) in (None, "")]
            if missing:
                raise ToolError(f"Missing required argument(s): {', '.join(missing)}.")
            unknown = sorted(set(args) - set(tool["schema"]["properties"]))
            if unknown:
                raise ToolError(f"Unknown argument(s): {', '.join(unknown)}.")
            result = tool["handler"](args)
        except ToolError as exc:
            payload = {"error": str(exc), **({"errors": exc.details} if exc.details else {})}
            return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
                    "structuredContent": payload, "isError": True}
        except proposals.ProposalError as exc:
            payload = {"error": "The proposal is not valid; nothing was stored.", "errors": exc.errors}
            return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
                    "structuredContent": payload, "isError": True}
        text = result.pop("_text", None) if isinstance(result, dict) else None
        return {"content": [{"type": "text", "text": text or json.dumps(result, ensure_ascii=False, indent=2)}],
                "structuredContent": result, "isError": False}

    # ---------------------------------------------------------------- helpers --

    def _report_id(self, args: dict) -> int:
        raw = args.get("report_id")
        if self.pinned is not None:
            if raw not in (None, "") and raw != self.pinned:
                raise ToolError(f"This server is pinned to report {self.pinned}.")
            return self.pinned
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ToolError("report_id (an integer, see list_reports) is required.")
        if repo.get_report(self.conn, raw) is None:
            raise ToolError(f"Report {raw} not found (see list_reports).")
        return raw

    def _finding(self, args: dict) -> dict:
        raw = args.get("finding_id")
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ToolError("finding_id (an integer, see get_report) is required.")
        finding = repo.get_finding(self.conn, raw)
        if finding is None or (self.pinned is not None and finding["report_id"] != self.pinned):
            raise ToolError(f"Finding {raw} not found" + (f" in report {self.pinned}." if self.pinned else "."))
        if args.get("report_id") not in (None, "") and args["report_id"] != finding["report_id"]:
            raise ToolError(f"Finding {raw} belongs to report {finding['report_id']}.")
        return finding

    def _defaults(self) -> dict:
        name = self.client.get("name") or "MCP client"
        return {"tool": f"{name} (MCP)"[:100], "version": self.client.get("version", "")}

    def _propose(self, report_id: int, item: dict) -> dict:
        ids = proposals.submit(self.conn, report_id, [item], defaults=self._defaults())
        p = repo.get_proposal(self.conn, ids[0])
        out = {"proposal_id": p["id"], "report_id": report_id, "kind": p["kind"], "status": p["status"],
               "message": "Queued for human review in ptreport (report → AI queue). It is not part of the report "
                          "until someone accepts it."}
        if p["duplicate_of_finding_id"]:
            dup = repo.get_finding(self.conn, p["duplicate_of_finding_id"])
            out["possible_duplicate_of"] = {"finding_id": dup["id"], "title": dup["title"]}
        return out

    @staticmethod
    def _item(kind: str, args: dict, fields: tuple[str, ...]) -> dict:
        item = {"kind": kind, "verdict": args.get("verdict") or "", "data": {k: args[k] for k in fields if k in args}}
        if args.get("source") is not None:
            item["source"] = args["source"]
        if "finding_id" in args:
            item["finding_id"] = args["finding_id"]
        return item

    # ------------------------------------------------------------------ tools --

    def _tools(self) -> dict[str, dict]:
        rid = {"report_id": {"type": "integer", "description": "Report id (see list_reports)"
                             + (f"; this server is pinned to report {self.pinned}" if self.pinned else "")}}
        rid_required = [] if self.pinned is not None else ["report_id"]
        fid = {"finding_id": {"type": "integer", "description": "Finding id (see get_report)"}}
        common = {"verdict": VERDICT_SCHEMA, "source": SOURCE_SCHEMA}
        finding_props = {
            **rid,
            "title": _str("Vulnerability title", 300),
            "severity": {"type": "string", "enum": list(SEVERITIES), "description": "Your risk assessment"},
            "cvss_vector": _str("CVSS 4.0 / 3.1 / 3.0 / 2.0 vector, e.g. CVSS:3.1/AV:N/AC:L/...", 512),
            "cwe": _str("CWE id, e.g. CWE-79 (see search_cwe)", 12),
            **{k: _str(label, 200_000) for k, label in (
                ("description", "What is wrong"), ("impact", "What an attacker gains"),
                ("technical_details", "How it works, affected parameters"),
                ("poc", "Reproduction steps / payloads (fenced code blocks allowed)"),
                ("remediation", "How to fix it"), ("refs", "References, one per line"))},
            "targets": {"type": "array", "items": TARGET_SCHEMA, "maxItems": proposals.MAX_ITEMS},
            "evidence": {"type": "array", "items": HTTP_SCHEMA, "maxItems": proposals.MAX_ITEMS},
            "code_evidence": {"type": "array", "items": CODE_SCHEMA, "maxItems": proposals.MAX_ITEMS},
            **common,
        }
        tools = [
            ("list_reports", "List reports", "Reports in ptreport with client, dates and finding counts.",
             _schema({}, []), False, self.t_list_reports),
            ("get_report", "Get a report", "A report's summary, targets and findings (ids, titles, severity, "
             "status, CWE, CVSS, retest result) plus the number of pending proposals.",
             _schema(rid, rid_required), False, self.t_get_report),
            ("get_scope", "Get the engagement scope", "Client, testing window, targets (kind / address), in-scope "
             "and out-of-scope text, methodology, contacts and report language. format=markdown returns a short "
             "engagement brief.", _schema({**rid, "format": {"type": "string", "enum": ["json", "markdown"]}},
                                          rid_required), False, self.t_get_scope),
            ("search_cwe", "Search CWE", "Search the MITRE CWE catalogue by number, name or description.",
             _schema({"query": _str("e.g. 79, xss, deserialization", 100),
                      "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, ["query"]),
             False, self.t_search_cwe),
            ("list_templates", "List finding templates", "Reusable finding write-ups (EN/PL) from ptreport's "
             "template library.", _schema({"query": _str("Search title, tag or CWE", 100),
                                           "language": {"type": "string", "enum": ["en", "pl", ""]}}, []),
             False, self.t_list_templates),
            ("list_proposals", "List proposals", "Proposals in a report's AI queue and what the reviewer decided.",
             _schema({**rid, "status": {"type": "string", "enum": list(proposals.STATUSES) + [""]}}, rid_required),
             False, self.t_list_proposals),
            ("propose_finding", "Propose a finding", "Queue a new finding (with targets, HTTP evidence and code "
             "evidence) for human review. It is not added to the report until accepted.",
             _schema(finding_props, rid_required + ["title"]), True, self.t_propose_finding),
            ("propose_http_evidence", "Propose HTTP evidence", "Queue a raw HTTP request/response as evidence for "
             "an existing finding.", _schema({**rid, **fid, **HTTP_SCHEMA["properties"], **common},
                                             ["finding_id", "request"]), True, self.t_propose_http),
            ("propose_code_evidence", "Propose code evidence", "Queue a code snippet (decompiled function, "
             "disassembly, source excerpt) as evidence for an existing finding.",
             _schema({**rid, **fid, **CODE_SCHEMA["properties"], **common}, ["finding_id", "code"]), True,
             self.t_propose_code),
            ("propose_file", "Propose a file", "Queue a file (base64, at most 25 MB: analysed sample, capture, "
             "log) for an existing finding. ptreport computes its SHA-256.",
             _schema({**rid, **fid, "filename": _str("File name", 180), "description": _str("Description", 300),
                      "data_base64": _str("File content, base64"), **common},
                     ["finding_id", "filename", "data_base64"]), True, self.t_propose_file),
            ("propose_retest_result", "Propose a retest result", "Queue an explicit retest result for a finding: "
             "fixed, partially_fixed, not_fixed or not_tested, with notes and optional evidence. Only report what "
             "you tested; absence of a result is not 'fixed'.",
             _schema({**rid, **fid, "result": {"type": "string", "enum": list(RETEST_RESULTS)},
                      "date": _str("Retest date, YYYY-MM-DD (default today)", 10, format="date"),
                      "notes": _str("What was tested and seen", 200_000),
                      "evidence": finding_props["evidence"], "code_evidence": finding_props["code_evidence"],
                      **common}, ["finding_id", "result"]), True, self.t_propose_retest),
        ]
        return {name: {"name": name, "title": title, "description": desc, "schema": schema, "write": write,
                       "handler": handler} for name, title, desc, schema, write, handler in tools}

    def t_list_reports(self, args: dict) -> dict:
        counts = repo.finding_counts_by_report(self.conn)
        rows = [r for r in repo.list_reports(self.conn) if self.pinned is None or r["id"] == self.pinned]
        return {"reports": [{"id": r["id"], "title": r["title"], "client": r["client_name"],
                             "language": r["language"], "start_date": r["start_date"], "end_date": r["end_date"],
                             "retest_of": r["retest_of"], "findings": r["finding_count"], "targets": r["target_count"],
                             "open_findings": counts.get(r["id"], {}).get("open", 0),
                             "pending_proposals": repo.count_proposals(self.conn, r["id"])} for r in rows]}

    def t_get_report(self, args: dict) -> dict:
        report_id = self._report_id(args)
        report = repo.get_report(self.conn, report_id)
        settings = repo.get_settings(self.conn)
        findings = repo.list_findings(self.conn, report_id)
        return {
            "report": {k: report[k] for k in ("id", "title", "client_name", "assessor", "language", "start_date",
                                              "end_date", "report_date", "classification", "retest_of")},
            "targets": [{k: t[k] for k in ("id", "name", "kind", "address")} for t in
                        repo.list_targets(self.conn, report_id)],
            "findings": [{"id": f["id"], "display_id": repo.finding_display_id(report, f, settings),
                          "title": f["title"], "severity": f["severity"], "status": f["status"], "cwe": f["cwe"],
                          "cvss_version": f["cvss_version"], "cvss_score": f["cvss_score"],
                          "targets": [t["id"] for t in f["targets"]], "retest_result": f["retest_result"],
                          "evidence": len(f["evidence"]), "code_evidence": len(f["code_evidence"]),
                          "files": len(f["files"]), "origin": f["origin"]} for f in findings],
            "pending_proposals": repo.count_proposals(self.conn, report_id),
        }

    def t_get_scope(self, args: dict) -> dict:
        doc = scope.scope_document(self.conn, self._report_id(args))
        if args.get("format") not in (None, "", "json", "markdown"):
            raise ToolError("format must be json or markdown.")
        if args.get("format") == "markdown":
            return {**doc, "_text": scope.to_markdown(doc)}
        return doc

    def t_search_cwe(self, args: dict) -> dict:
        query = args.get("query")
        if not isinstance(query, str):
            raise ToolError("query must be text.")
        limit = args.get("limit", 20)
        limit = limit if isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= 100 else 20
        return {"cwe": [{"id": i, "name": n} for i, n in cwe_search(query[:100], limit)]}

    def t_list_templates(self, args: dict) -> dict:
        query = args.get("query") if isinstance(args.get("query"), str) else ""
        language = args.get("language") if args.get("language") in ("en", "pl") else ""
        rows = repo.list_templates(self.conn, query.strip()[:100], language)[:50]
        keys = ("id", "language", "title", "severity", "cvss_vector", "cwe", "description", "impact",
                "technical_details", "remediation", "refs", "tags")
        return {"templates": [{k: r[k] for k in keys} for r in rows]}

    def t_list_proposals(self, args: dict) -> dict:
        report_id = self._report_id(args)
        status = args.get("status") or ""
        if status not in proposals.STATUSES + ("",):
            raise ToolError(f"status must be one of: {', '.join(proposals.STATUSES)}.")
        return {"proposals": [proposals.public(p) for p in repo.list_proposals(self.conn, report_id, status, 200)]}

    def t_propose_finding(self, args: dict) -> dict:
        report_id = self._report_id(args)
        item = self._item("finding", args, ("title", "severity", "cvss_vector", "cwe", "description", "impact",
                                            "technical_details", "poc", "remediation", "refs", "targets",
                                            "evidence", "code_evidence"))
        return self._propose(report_id, item)

    def t_propose_http(self, args: dict) -> dict:
        finding = self._finding(args)
        return self._propose(finding["report_id"], self._item("evidence", args, ("title", "request", "response")))

    def t_propose_code(self, args: dict) -> dict:
        finding = self._finding(args)
        return self._propose(finding["report_id"],
                             self._item("code", args, ("title", "location", "language", "code", "note")))

    def t_propose_file(self, args: dict) -> dict:
        finding = self._finding(args)
        return self._propose(finding["report_id"],
                             self._item("file", args, ("filename", "description", "data_base64")))

    def t_propose_retest(self, args: dict) -> dict:
        finding = self._finding(args)
        return self._propose(finding["report_id"],
                             self._item("retest", args, ("result", "date", "notes", "evidence", "code_evidence")))


def _error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def run(conn: sqlite3.Connection, *, report_id: int | None = None, read_only: bool = False,
        stdin=None, stdout: TextIO | None = None, on_ready: Callable[[], None] | None = None) -> None:
    server = McpServer(conn, report_id=report_id, read_only=read_only)
    if on_ready:
        on_ready()
    server.serve(stdin or sys.stdin.buffer, stdout or sys.stdout)
