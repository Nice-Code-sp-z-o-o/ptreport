"""MCP server (``ptreport mcp``): JSON-RPC over stdio, tools, read-only and pinned modes."""

import base64
import json
import os
import subprocess  # noqa: S404 - runs this interpreter with fixed arguments
import sys

import pytest

from ptreport import mcp, repo
from ptreport.app import create_app
from ptreport.db import connect
from ptreport.validation import validate_finding, validate_report, validate_target

REQUEST = "GET /search?q=<script> HTTP/1.1\r\nHost: shop.example\r\n\r\n"


@pytest.fixture()
def db(tmp_path):
    app = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "API_TOKEN": "t" * 40})
    conn = connect(app.config["DATABASE"])
    report_id = repo.create_report(conn, validate_report({
        "title": "Shop test", "client_name": "ACME", "finding_prefix": "ACME", "start_date": "2026-11-01",
        "end_date": "2026-11-10", "scope": "The shop.\n\n## Out of scope\n\nThe payment provider.",
        "methodology": "OWASP WSTG"})[0])
    target_id = repo.create_target(conn, report_id, validate_target(
        {"name": "Shop", "kind": "web", "address": "https://shop.example"})[0])
    data = validate_finding({"title": "SQL injection in login", "severity": "high", "cwe": "89",
                             "target_ids": [target_id]})[0]
    finding_id = repo.create_finding(conn, report_id, data)
    yield {"conn": conn, "report_id": report_id, "finding_id": finding_id, "data_dir": str(tmp_path)}
    conn.close()


def _run(args, stdin, **kwargs):
    return subprocess.run(  # noqa: S603 - fixed argv: this Python, -m ptreport
        [sys.executable, "-m", "ptreport", "mcp", *args], input=stdin, capture_output=True, text=True, timeout=60,
        **kwargs)


def _rpc(server, method, params=None, msg_id=1):
    msg = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        msg["params"] = params
    return server.handle(msg)


def _call(server, name, arguments=None):
    resp = _rpc(server, "tools/call", {"name": name, "arguments": arguments or {}})
    assert "result" in resp, resp
    return resp["result"]


def test_initialize_negotiates_version(db):
    server = mcp.McpServer(db["conn"])
    result = _rpc(server, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "claude-code", "version": "2.0"}})["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"]["tools"] == {"listChanged": False}
    assert result["serverInfo"]["name"] == "ptreport"
    assert "proposal" in result["instructions"]
    other = _rpc(mcp.McpServer(db["conn"]), "initialize", {"protocolVersion": "1999-01-01"})["result"]
    assert other["protocolVersion"] == mcp.PROTOCOL_VERSIONS[0]
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert _rpc(server, "ping")["result"] == {}


def test_json_rpc_errors(db):
    server = mcp.McpServer(db["conn"])
    assert server.handle_line(b"{not json")["error"]["code"] == -32700
    assert server.handle_line(b"\xff\xfe")["error"]["code"] == -32700
    assert server.handle_line(b"   \n") is None
    assert server.handle([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])["error"]["code"] == -32600
    assert server.handle("text")["error"]["code"] == -32600
    assert server.handle({"jsonrpc": "1.0", "id": 1, "method": "ping"})["error"]["code"] == -32600
    assert server.handle({"jsonrpc": "2.0", "id": True, "method": "ping"})["error"]["code"] == -32600
    assert server.handle({"jsonrpc": "2.0", "id": 4, "method": 5})["error"]["code"] == -32600
    assert server.handle({"jsonrpc": "2.0", "id": 5, "method": "nope"})["error"] == {
        "code": -32601, "message": "Method not found: nope"}
    assert server.handle({"jsonrpc": "2.0", "method": "nope"}) is None  # notifications are never answered
    assert server.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": [1]})["error"]["code"] == -32602
    assert _rpc(server, "tools/call", {"name": "nope"})["error"]["code"] == -32602
    assert _rpc(server, "tools/call", {"name": "list_reports", "arguments": [1]})["error"]["code"] == -32602
    assert server.handle({"jsonrpc": "2.0", "id": 7, "result": {}}) is None


def test_tools_list_has_schemas(db):
    tools = _rpc(mcp.McpServer(db["conn"]), "tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {"list_reports", "get_report", "get_scope", "search_cwe", "list_templates", "list_proposals",
                     "propose_finding", "propose_http_evidence", "propose_code_evidence", "propose_file",
                     "propose_retest_result"}
    for t in tools:
        assert t["inputSchema"]["type"] == "object"
        assert t["annotations"]["readOnlyHint"] == (not t["name"].startswith("propose_"))
    finding = next(t for t in tools if t["name"] == "propose_finding")["inputSchema"]
    assert finding["required"] == ["report_id", "title"]
    assert finding["properties"]["severity"]["enum"] == ["critical", "high", "medium", "low", "info"]


def test_read_tools(db):
    server = mcp.McpServer(db["conn"])
    reports = _call(server, "list_reports")["structuredContent"]["reports"]
    assert reports[0]["title"] == "Shop test" and reports[0]["findings"] == 1
    report = _call(server, "get_report", {"report_id": db["report_id"]})["structuredContent"]
    assert report["findings"][0]["display_id"] == "ACME-001"
    assert report["findings"][0]["cwe"] == "CWE-89"
    assert report["targets"][0]["address"] == "https://shop.example"
    scope_json = _call(server, "get_scope", {"report_id": db["report_id"]})["structuredContent"]
    assert scope_json["out_of_scope"] == "The payment provider."
    assert scope_json["scope"] == "The shop."
    brief = _call(server, "get_scope", {"report_id": db["report_id"], "format": "markdown"})
    assert brief["content"][0]["text"].startswith("# Engagement brief: Shop test")
    cwe = _call(server, "search_cwe", {"query": "79"})["structuredContent"]["cwe"]
    assert cwe[0]["id"] == "CWE-79"
    templates = _call(server, "list_templates", {"query": "xss", "language": "en"})["structuredContent"]
    assert templates["templates"]
    missing = _call(server, "get_report", {"report_id": 999})
    assert missing["isError"] and "not found" in missing["structuredContent"]["error"]
    bad = _call(server, "get_report", {})
    assert bad["isError"] and "report_id" in bad["structuredContent"]["error"]
    extra = _call(server, "list_reports", {"oops": 1})
    assert extra["isError"] and "Unknown argument" in extra["structuredContent"]["error"]


def test_propose_tools_create_proposals_only(db):
    server = mcp.McpServer(db["conn"])
    _rpc(server, "initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "codex", "version": "1.2"}})
    result = _call(server, "propose_finding", {
        "report_id": db["report_id"], "title": "Reflected XSS", "severity": "medium", "cwe": "CWE-79",
        "targets": ["https://shop.example/search"], "verdict": "verified",
        "evidence": [{"title": "Reflection", "request": REQUEST}],
        "source": {"tool": "ptai", "version": "1.6.2", "run_id": "7f3a", "model": "m"}})
    assert result["isError"] is False, result
    out = result["structuredContent"]
    assert out["status"] == "pending" and out["kind"] == "finding"
    conn, fid = db["conn"], db["finding_id"]
    p = repo.get_proposal(conn, out["proposal_id"])
    assert (p["source_tool"], p["run_id"], p["verdict"]) == ("ptai", "7f3a", "verified")
    assert len(repo.list_findings(conn, db["report_id"])) == 1  # the report itself is untouched

    default_source = _call(server, "propose_http_evidence", {"finding_id": fid, "request": REQUEST})
    p = repo.get_proposal(conn, default_source["structuredContent"]["proposal_id"])
    assert (p["source_tool"], p["source_version"], p["target_finding_id"]) == ("codex (MCP)", "1.2", fid)
    code = _call(server, "propose_code_evidence", {"finding_id": fid, "code": "mov eax, 1", "language": "asm",
                                                   "location": "0x401000"})
    assert code["isError"] is False
    file = _call(server, "propose_file", {"finding_id": fid, "filename": "sample.bin",
                                          "data_base64": base64.b64encode(b"MZ\x90\x00").decode()})
    assert file["isError"] is False
    retest = _call(server, "propose_retest_result", {"finding_id": fid, "result": "not_fixed",
                                                     "notes": "Still injectable."})
    assert retest["isError"] is False
    listed = _call(server, "list_proposals", {"report_id": db["report_id"], "status": "pending"})
    kinds = [x["kind"] for x in listed["structuredContent"]["proposals"]]
    assert kinds == ["finding", "evidence", "code", "file", "retest"]
    assert "data_base64" not in json.dumps(listed["structuredContent"])
    assert repo.get_finding(conn, fid)["evidence"] == [] and repo.get_finding(conn, fid)["retest_result"] == ""


def test_propose_validation_errors_are_tool_errors(db):
    server = mcp.McpServer(db["conn"])
    bad = _call(server, "propose_finding", {"report_id": db["report_id"], "title": "x", "severity": "high",
                                            "cvss_vector": "CVSS:3.1/AV:Z"})
    assert bad["isError"] and "data.cvss_vector" in json.dumps(bad["structuredContent"]["errors"])
    assert _call(server, "propose_finding", {"report_id": db["report_id"]})["isError"]  # title missing
    assert _call(server, "propose_http_evidence", {"finding_id": 999, "request": REQUEST})["isError"]
    assert _call(server, "propose_retest_result", {"finding_id": db["finding_id"], "result": "gone"})["isError"]
    assert _call(server, "propose_file", {"finding_id": db["finding_id"], "filename": "a",
                                          "data_base64": "!!"})["isError"]
    assert repo.list_proposals(db["conn"], db["report_id"]) == []


def test_read_only_hides_write_tools(db):
    server = mcp.McpServer(db["conn"], read_only=True)
    names = {t["name"] for t in _rpc(server, "tools/list")["result"]["tools"]}
    assert not any(n.startswith("propose_") for n in names) and "get_scope" in names
    resp = _rpc(server, "tools/call", {"name": "propose_finding",
                                       "arguments": {"report_id": db["report_id"], "title": "x"}})
    assert resp["error"]["code"] == -32602
    assert repo.list_proposals(db["conn"], db["report_id"]) == []


def test_pinned_report(db):
    conn = db["conn"]
    other = repo.create_report(conn, validate_report({"title": "Other"})[0])
    other_finding = repo.create_finding(conn, other, validate_finding({"title": "x", "severity": "low"})[0])
    server = mcp.McpServer(conn, report_id=db["report_id"])
    assert [r["id"] for r in _call(server, "list_reports")["structuredContent"]["reports"]] == [db["report_id"]]
    assert _call(server, "get_report")["structuredContent"]["report"]["id"] == db["report_id"]
    assert _call(server, "get_report", {"report_id": other})["isError"]
    assert _call(server, "propose_http_evidence", {"finding_id": other_finding, "request": REQUEST})["isError"]
    schema = next(t for t in _rpc(server, "tools/list")["result"]["tools"] if t["name"] == "propose_finding")
    assert schema["inputSchema"]["required"] == ["title"]
    ok = _call(server, "propose_finding", {"title": "Pinned", "severity": "low"})
    assert ok["structuredContent"]["report_id"] == db["report_id"]


def test_stdio_subprocess(db):
    """The real CLI: newline-delimited JSON in, protocol messages only on stdout."""
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "pytest"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "propose_finding", "arguments": {
            "report_id": db["report_id"], "title": "Open redirect", "severity": "low", "cwe": "601"}}},
        "this is not json",
        {"jsonrpc": "2.0", "id": 4, "method": "resources/list"},
    ]
    stdin = "\n".join(x if isinstance(x, str) else json.dumps(x) for x in lines) + "\n"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = _run(["--data-dir", db["data_dir"]], stdin, env=env)
    assert proc.returncode == 0, proc.stderr
    out = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [m["id"] for m in out] == [1, 2, 3, None, 4]
    assert out[0]["result"]["protocolVersion"] == "2025-11-25"
    assert any(t["name"] == "propose_finding" for t in out[1]["result"]["tools"])
    assert out[2]["result"]["isError"] is False
    assert out[3]["error"]["code"] == -32700
    assert out[4]["error"]["code"] == -32601
    assert "initialize from pytest" in proc.stderr
    titles = [p["data"]["title"] for p in repo.list_proposals(db["conn"], db["report_id"])]
    assert titles == ["Open redirect"]


def test_stdio_read_only_and_unknown_report(db):
    msg = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
    proc = _run(["--data-dir", db["data_dir"], "--read-only", "--report", str(db["report_id"])], msg)
    names = {t["name"] for t in json.loads(proc.stdout)["result"]["tools"]}
    assert "propose_finding" not in names and "get_report" in names
    proc = _run(["--data-dir", db["data_dir"], "--report", "999"], msg)
    assert proc.returncode == 1 and proc.stdout == "" and "report 999 not found" in proc.stderr


def test_oversized_line_is_rejected(db):
    import io

    server = mcp.McpServer(db["conn"])
    original = mcp.MAX_LINE_BYTES
    mcp.MAX_LINE_BYTES = 100
    try:
        stdin = io.BytesIO(b"x" * 500 + b"\n" + json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}).encode()
                           + b"\n")
        stdout = io.StringIO()
        server.serve(stdin, stdout)
    finally:
        mcp.MAX_LINE_BYTES = original
    out = [json.loads(x) for x in stdout.getvalue().splitlines()]
    assert out[0]["error"]["code"] == -32600 and out[1] == {"jsonrpc": "2.0", "id": 9, "result": {}}
