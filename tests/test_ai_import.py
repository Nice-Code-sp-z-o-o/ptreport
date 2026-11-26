"""AI result imports (SARIF, ptai capsule, proposal JSON), retest matching, code evidence, RE target kinds."""

import base64
import json
from io import BytesIO
from pathlib import Path

import pytest

from ptreport import ai_import, cli, export, latex, repo
from ptreport.db import connect

FIXTURES = Path(__file__).parent / "fixtures" / "ai"


def _bytes(name):
    return (FIXTURES / name).read_bytes()


def _conn(client):
    return connect(client.application.config["DATABASE"])


def _upload(client, csrf, report_id, name, data=None, fmt=""):
    return client.post(f"/reports/{report_id}/ai-import", data={
        "_csrf": csrf, "format": fmt, "file": (BytesIO(data if data is not None else _bytes(name)), name)})


# ------------------------------------------------------------------ parsing --

def test_detect_formats():
    assert ai_import.parse(_bytes("ptai.sarif"))["format"] == "sarif"
    assert ai_import.parse(_bytes("code-scan.sarif"))["format"] == "sarif"
    assert ai_import.parse(_bytes("ptai-capsule.json"))["format"] == "ptai"
    assert ai_import.parse(_bytes("proposals.json"))["format"] == "ptreport"
    with pytest.raises(ai_import.ImportError_, match="looks like SARIF"):
        ai_import.parse(_bytes("ptai.sarif"), "ptai")
    with pytest.raises(ai_import.ImportError_, match="Unrecognised"):
        ai_import.parse(b'{"hello": 1}')


@pytest.mark.parametrize("data,message", [
    (b"", "empty"),
    (b"\xff\xfe{}", "UTF-8"),
    (b"{nope", "not valid JSON"),
    (b"[" * 70 + b"]" * 70, "nested too deeply"),
    (b"[" * 100_000 + b"]" * 100_000, "nested too deeply"),
])
def test_hardened_loading(data, message):
    with pytest.raises(ai_import.ImportError_, match=message):
        ai_import.parse(data)


def test_size_limit(monkeypatch):
    monkeypatch.setattr(ai_import, "MAX_BYTES", 100)
    with pytest.raises(ai_import.ImportError_, match="too large"):
        ai_import.parse(b" " * 101)


def test_ptai_sarif_mapping():
    parsed = ai_import.parse(_bytes("ptai.sarif"))
    xss, sqli = parsed["items"]
    assert any("refuted" in w for w in parsed["warnings"])
    assert xss["verdict"] == "verified" and sqli["verdict"] == "candidate"
    assert xss["source"] == {"tool": "pentest-ai", "version": "1.6.2", "run_id": "eng-7f3a"}
    d = xss["data"]
    assert (d["title"], d["severity"], d["cwe"]) == ("Reflected XSS (query reflection)", "medium", "CWE-79")
    assert d["targets"] == [{"name": "shop.example", "kind": "web", "address": "https://shop.example"}]
    request = d["evidence"][0]["request"]
    assert request.startswith("GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\nHost: shop.example\r\n")
    assert d["evidence"][0]["response"].startswith("HTTP/1.1 200 OK\r\nContent-Type: text/html")
    assert "oracle `unescaped_reflection`, replayed 3/3" in d["technical_details"]
    assert d["remediation"].startswith("Encode user input")
    assert sqli["data"]["severity"] == "critical"  # cvss_score 9.8


def test_code_scan_sarif_mapping():
    parsed = ai_import.parse(_bytes("code-scan.sarif"))
    strcpy, evil = parsed["items"]
    assert "1 identical result(s) were imported once." in parsed["warnings"]
    assert any("suppressed" in w for w in parsed["warnings"]) and any("passing" in w for w in parsed["warnings"])
    assert strcpy["source"] == {"tool": "Semgrep OSS", "version": "1.99.0", "run_id": "nightly/2026-11-25"}
    d = strcpy["data"]
    assert (d["severity"], d["cwe"]) == ("high", "CWE-120")  # security-severity 8.1, external/cwe/cwe-120
    assert "from argv[1]" in d["description"]  # message arguments filled in
    code = d["code_evidence"][0]
    assert code == {"title": "check.c, lines 42-44", "location": "src/auth/check.c:42-44 check_login",
                    "language": "c", "code": "char buf[64];\nstrcpy(buf, argv[1]);\nreturn check_pw(buf);"}
    assert evil["data"]["cwe"] == "CWE-95" and evil["data"]["severity"] == "critical"
    assert evil["data"]["code_evidence"] == [] and "/srv/app/views.py:7" in evil["data"]["technical_details"]


def test_sarif_level_fallback_and_hostile_values():
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": ["x"], "rules": "nope"}}, "results": [
        {"level": "error", "message": {"text": "Weak TLS"}, "ruleId": 5, "properties": {"security-severity": "99"}},
        {"message": "not an object", "locations": [{"physicalLocation": "bad"}], "webResponse": {"statusCode": 200}},
        "garbage",
    ]}]}
    parsed = ai_import.parse(json.dumps(doc).encode())
    first, second, third = parsed["items"]
    assert (first["data"]["title"], first["data"]["severity"]) == ("Weak TLS", "high")
    assert first["source"]["tool"] == "SARIF"
    assert second["data"]["title"] == "not an object"  # a bare string message is taken as its text
    assert any("webResponse without a webRequest" in w for w in parsed["warnings"])
    assert third["data"]["title"] == "Untitled result"


def test_ptai_capsule_real_sample():
    parsed = ai_import.parse(_bytes("ptai-capsule.json"))
    assert parsed["warnings"] == []
    item = parsed["items"][0]
    assert item["verdict"] == "verified"
    assert item["source"] == {"tool": "ptai", "version": "1.6.2", "run_id": "demo-0"}
    d = item["data"]
    assert (d["title"], d["severity"], d["cwe"]) == ("Reflected XSS (query reflection)", "medium", "CWE-79")
    assert d["targets"][0]["address"] == "http://127.0.0.1:53005"
    assert "replayed 3/3" in d["technical_details"] and "(matches the content)" in d["technical_details"]
    assert "proves unescaped reflection, not that XSS executes" in d["technical_details"]
    assert d["evidence"] == []  # the sample's receipt has request/response = null; nothing is invented
    capsule_file = d["files"][0]
    assert capsule_file["filename"] == "ptai-capsule-demo-0.json"
    assert base64.b64decode(capsule_file["data_base64"]) == _bytes("ptai-capsule.json")


def test_ptai_capsule_tampered_refuted_and_with_request():
    cap = json.loads(_bytes("ptai-capsule.json"))
    cap["finding"]["severity"] = "critical"  # edited after ptai built it
    parsed = ai_import.parse(json.dumps(cap).encode())
    assert parsed["items"][0]["verdict"] == "candidate"
    assert any("integrity SHA-256 does not match" in w for w in parsed["warnings"])
    refuted = json.loads(_bytes("ptai-capsule.json"))
    refuted["receipt"]["verdict"] = "refuted"
    assert ai_import.parse(json.dumps(refuted).encode())["items"] == []
    full = json.loads(_bytes("ptai-capsule.json"))
    full["receipt"]["evidence"].update(request="GET /search?q=x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                                       response="HTTP/1.1 200 OK\r\n\r\nx")
    full["receipt"]["replay"]["curl"] = "curl 'http://127.0.0.1:53005/search?q=x'"
    full["integrity_sha256"] = ai_import.capsule_integrity(full)
    parsed = ai_import.parse(json.dumps({"capsules": [full, "junk"]}).encode())
    item = parsed["items"][0]
    assert item["verdict"] == "verified" and item["data"]["evidence"][0]["request"].startswith("GET /search")
    assert "```bash\ncurl" in item["data"]["poc"]
    assert any("not a ptai proof capsule" in w for w in parsed["warnings"])


# ---------------------------------------------------------------- web/CLI --

def test_web_import_queues_proposals(client, csrf, make_report):
    report_id = make_report()
    resp = _upload(client, csrf, report_id, "ptai.sarif")
    assert resp.status_code == 302 and resp.headers["Location"].endswith(f"/reports/{report_id}/ai-queue")
    conn = _conn(client)
    try:
        pending = repo.list_proposals(conn, report_id, "pending")
        assert [p["data"]["title"] for p in pending] == ["Reflected XSS (query reflection)", "SQL injection in login"]
        assert repo.list_findings(conn, report_id) == []
    finally:
        conn.close()
    page = client.get(f"/reports/{report_id}/ai-queue").get_data(as_text=True)
    assert "pentest-ai" in page and "run eng-7f3a" in page
    assert "Import AI results" in client.get(f"/reports/{report_id}").get_data(as_text=True)


def test_web_import_errors_and_csrf(client, csrf, make_report):
    report_id = make_report()
    assert client.get(f"/reports/{report_id}/ai-import").status_code == 200
    assert _upload(client, csrf, report_id, "x.json", b"").status_code == 422
    resp = _upload(client, csrf, report_id, "x.json", b"{broken")
    assert resp.status_code == 422 and "not valid JSON" in resp.get_data(as_text=True)
    assert _upload(client, csrf, report_id, "ptai.sarif", fmt="ptai").status_code == 422
    assert _upload(client, csrf, report_id, "ptai.sarif", fmt="evil").status_code == 422
    empty = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]}
    assert _upload(client, csrf, report_id, "e.sarif", json.dumps(empty).encode()).status_code == 422
    resp = client.post(f"/reports/{report_id}/ai-import",
                       data={"file": (BytesIO(_bytes("ptai.sarif")), "ptai.sarif")})
    assert resp.status_code == 400
    assert client.get("/reports/999/ai-import").status_code == 404


def test_invalid_items_are_skipped_with_a_warning(client, csrf, make_report):
    report_id = make_report()
    doc = [{"kind": "finding", "data": {"title": "Good", "severity": "low"}},
           {"kind": "finding", "data": {"title": "Bad", "severity": "low", "cvss_vector": "CVSS:3.1/XX"}}]
    resp = _upload(client, csrf, report_id, "p.json", json.dumps(doc).encode())
    assert resp.status_code == 302
    with client.session_transaction() as session:
        messages = [m for _, m in session.get("_flashes", [])]
    assert any('Skipped "Bad"' in m for m in messages)
    conn = _conn(client)
    try:
        assert [p["data"]["title"] for p in repo.list_proposals(conn, report_id)] == ["Good"]
    finally:
        conn.close()


def test_accepting_imported_proposals(client, csrf, make_report):
    report_id = make_report()
    _upload(client, csrf, report_id, "proposals.json")
    _upload(client, csrf, report_id, "ptai-capsule.json")
    conn = _conn(client)
    ids = [p["id"] for p in repo.list_proposals(conn, report_id)]
    conn.close()
    resp = client.post(f"/reports/{report_id}/ai-queue/bulk", data={"_csrf": csrf, "action": "accept",
                                                                    "proposal": ids})
    assert resp.status_code == 302
    conn = _conn(client)
    try:
        targets = repo.list_targets(conn, report_id)
        assert sorted(t["kind"] for t in targets) == ["firmware", "web"]
        findings = {f["title"]: f for f in repo.list_findings(conn, report_id)}
        fw = findings["Hard-coded root password in firmware"]
        assert fw["code_evidence"][0]["location"] == "bin/login: check_pw @ 0x401a2c"
        assert fw["origin"] == "re-agent 0.3 · run ghidra-12 · candidate · model local-model"
        assert [t["kind"] for t in fw["targets"]] == ["firmware"]
        xss = findings["Reflected XSS (query reflection)"]
        assert xss["files"][0]["filename"] == "ptai-capsule-demo-0.json"
        assert xss["confidence"] == "certain"
    finally:
        conn.close()


def _retest_setup(client, csrf, make_report, make_target, make_finding):
    report_id = make_report()
    target = make_target(report_id, name="Shop", address="https://shop.example")
    make_finding(report_id, title="XSS in search", cwe="CWE-79", target_ids=[target], severity="medium")
    make_finding(report_id, title="Directory listing", cwe="CWE-548", target_ids=[target], severity="low")
    resp = client.post(f"/reports/{report_id}/retest", data={"_csrf": csrf})
    return int(resp.headers["Location"].rsplit("/", 1)[1])


def test_retest_report_matches_results_to_findings(client, csrf, make_report, make_target, make_finding):
    retest_id = _retest_setup(client, csrf, make_report, make_target, make_finding)
    _upload(client, csrf, retest_id, "ptai.sarif")
    conn = _conn(client)
    try:
        pending = repo.list_proposals(conn, retest_id, "pending")
        kinds = {p["kind"]: p for p in pending}
        assert set(kinds) == {"retest", "finding"}  # XSS matched, SQLi is new
        retest = kinds["retest"]
        xss = next(f for f in repo.list_findings(conn, retest_id) if f["cwe"] == "CWE-79")
        assert retest["target_finding_id"] == xss["id"]
        assert retest["data"]["result"] == "not_fixed"
        assert retest["data"]["notes"].startswith("Still present according to pentest-ai (eng-7f3a) (verified).")
        assert len(retest["data"]["evidence"]) == 1
        # the finding missing from the file (directory listing) gets no proposal and is never marked fixed
        assert all(f["retest_result"] == "" for f in repo.list_findings(conn, retest_id))
    finally:
        conn.close()
    client.post(f"/ai-proposals/{retest['id']}/accept", data={"_csrf": csrf})
    conn = _conn(client)
    try:
        f = repo.get_finding(conn, xss["id"])
        assert f["retest_result"] == "not_fixed" and len(f["evidence"]) == 1
    finally:
        conn.close()


def test_ordinary_report_and_proposal_json_never_become_retests(client, csrf, make_report, make_target,
                                                                 make_finding):
    report_id = make_report()
    target = make_target(report_id, address="https://shop.example")
    make_finding(report_id, title="XSS in search", cwe="CWE-79", target_ids=[target], severity="medium")
    _upload(client, csrf, report_id, "ptai.sarif")
    conn = _conn(client)
    try:
        pending = repo.list_proposals(conn, report_id)
        assert {p["kind"] for p in pending} == {"finding"}
        assert pending[0]["duplicate_of_finding_id"] is not None
    finally:
        conn.close()


def test_cli_import_ai(tmp_path, capsys, monkeypatch):
    data_dir = str(tmp_path / "d")
    assert cli.main(["--data-dir", data_dir, "report", "create", "--title", "CLI"]) == 0
    report_id = int(capsys.readouterr().out.strip())
    sarif = str(FIXTURES / "code-scan.sarif")
    code = cli.main(["import-ai", str(report_id), sarif, "--dry-run", "--data-dir", data_dir])
    out, err = capsys.readouterr()
    assert code == 0 and "Dry run" in out and "Use of strcpy without bounds check" in out
    assert "suppressed" in err
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["import-ai", str(report_id), sarif, "--data-dir", data_dir]) == 2
    capsys.readouterr()
    assert cli.main(["import-ai", str(report_id), sarif, "--yes", "--data-dir", data_dir]) == 0
    assert "Queued 2 proposal(s)" in capsys.readouterr().out
    assert cli.main(["import-ai", "999", sarif, "--yes", "--data-dir", data_dir]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli.main(["import-ai", str(report_id), str(bad), "--yes", "--data-dir", data_dir]) == 1
    assert "Unrecognised" in capsys.readouterr().err
    assert cli.main(["import-ai", str(report_id), sarif, "--format", "ptai", "--yes", "--data-dir", data_dir]) == 1


# ------------------------------------------------------------ code evidence --

CODE = {"title": "check_pw", "location": "bin/authd: check_pw @ 0x401a2c", "language": "pseudo",
        "code": "if (strcmp(input, \"s3cr3t\") == 0) {\n    grant(); /* <script> & \\ $ % */\n}",
        "note": "Decompiled with Ghidra."}


def test_code_evidence_web_crud(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    assert client.post(f"/findings/{fid}/code-evidence", data={**CODE}).status_code == 400
    resp = client.post(f"/findings/{fid}/code-evidence", data={"_csrf": csrf, **CODE, "code": "  \n"})
    assert resp.status_code == 422 and "Code is required" in resp.get_data(as_text=True)
    resp = client.post(f"/findings/{fid}/code-evidence", data={"_csrf": csrf, **CODE, "language": "cobol"})
    assert resp.status_code == 422
    resp = client.post(f"/findings/{fid}/code-evidence", data={"_csrf": csrf, **CODE, "location": "x" * 301})
    assert resp.status_code == 422
    assert client.post(f"/findings/{fid}/code-evidence", data={"_csrf": csrf, **CODE}).status_code == 302
    page = client.get(f"/findings/{fid}/edit").get_data(as_text=True)
    assert "Code evidence <span class=\"muted\">(1)</span>" in page
    assert "grant(); /* &lt;script&gt; &amp;" in page and "Pseudocode" in page
    conn = _conn(client)
    code_id = repo.get_finding(conn, fid)["code_evidence"][0]["id"]
    conn.close()
    assert client.post(f"/code-evidence/{code_id}/edit", data={"_csrf": csrf, **CODE, "language": "c",
                                                                "title": "Renamed"}).status_code == 302
    conn = _conn(client)
    try:
        item = repo.get_code_evidence(conn, code_id)
        assert (item["title"], item["language"]) == ("Renamed", "c")
    finally:
        conn.close()
    client.post(f"/code-evidence/{code_id}/edit", data={"_csrf": csrf, **CODE, "code": ""})
    conn = _conn(client)
    assert repo.get_code_evidence(conn, code_id)["code"] == CODE["code"]  # invalid edit changes nothing
    conn.close()
    assert client.post(f"/code-evidence/{code_id}/delete").status_code == 400
    assert client.post(f"/code-evidence/{code_id}/delete", data={"_csrf": csrf}).status_code == 302
    assert client.post(f"/code-evidence/{code_id}/delete", data={"_csrf": csrf}).status_code == 404


def test_code_evidence_api(client, csrf, make_report, make_finding, api_headers):
    report_id = make_report()
    fid = make_finding(report_id)
    resp = client.post(f"/api/v1/findings/{fid}/code-evidence", headers=api_headers, json=CODE)
    assert resp.status_code == 201 and resp.get_json()["code_evidence"]["language"] == "pseudo"
    assert client.post(f"/api/v1/findings/{fid}/code-evidence", headers=api_headers,
                       json={"code": ""}).status_code == 422
    assert client.post("/api/v1/findings/999/code-evidence", headers=api_headers, json=CODE).status_code == 404
    detail = client.get(f"/api/v1/findings/{fid}", headers=api_headers).get_json()["finding"]
    assert detail["code_evidence_count"] == 1 and detail["code_evidence"][0]["title"] == "check_pw"
    listed = client.get(f"/api/v1/reports/{report_id}/findings", headers=api_headers).get_json()["findings"]
    assert "code_evidence" not in listed[0] and listed[0]["code_evidence_count"] == 1
    resp = client.post("/settings/integrations", data={"_csrf": csrf, "name": "x", "scopes": ["read", "propose"]})
    token = resp.get_data(as_text=True).split('id="new-int-token"')[1].split('value="')[1].split('"')[0]
    assert client.post(f"/api/v1/findings/{fid}/code-evidence", headers={"Authorization": f"Bearer {token}"},
                       json=CODE).status_code == 403


def _finding_with_code(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    client.post(f"/findings/{fid}/code-evidence", data={"_csrf": csrf, **CODE})
    return report_id, fid


def test_code_evidence_in_exports(client, csrf, make_report, make_finding):
    report_id, _ = _finding_with_code(client, csrf, make_report, make_finding)
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Code evidence" in html and "bin/authd: check_pw @ 0x401a2c" in html
    assert "/* &lt;script&gt; &amp;" in html and "<script> &" not in html
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "#### Code evidence" in md and "*Location:* `bin/authd: check_pw @ 0x401a2c` · Pseudocode" in md
    assert "```c\nif (strcmp" in md
    with client.application.app_context():
        conn = _conn(client)
        try:
            ctx = export.build_context(conn, report_id, inline_images=True)
        finally:
            conn.close()
        source, files = latex.render(ctx)
    assert r"\ptBlockTitle{Code evidence}" in source and "check\\_pw" in source
    assert "strcmp" not in source  # the code itself is only in a file read by \VerbatimInput
    assert any(b"strcmp(input" in data for data in files.values())


def test_code_evidence_json_roundtrip_and_clone(client, csrf, make_report, make_finding):
    report_id, _ = _finding_with_code(client, csrf, make_report, make_finding)
    doc = json.loads(client.get(f"/reports/{report_id}/export/json").get_data())
    assert doc["findings"][0]["code_evidence"][0]["location"] == CODE["location"]
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")})
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    dup_id = int(client.post(f"/reports/{report_id}/duplicate", data={"_csrf": csrf}).headers["Location"]
                 .rsplit("/", 1)[1])
    conn = _conn(client)
    try:
        for rid in (new_id, dup_id):
            assert repo.list_findings(conn, rid)[0]["code_evidence"][0]["code"] == CODE["code"]
    finally:
        conn.close()
    doc["findings"][0]["code_evidence"][0]["language"] = "brainfuck"
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")})
    assert resp.status_code == 422 and "code evidence #1" in resp.get_data(as_text=True)


@pytest.mark.skipif(latex.find_engine() is None, reason="no LaTeX engine installed")
def test_real_pdf_with_code_evidence(client, csrf, make_report, make_finding):
    report_id, fid = _finding_with_code(client, csrf, make_report, make_finding)
    long_code = "\n".join(f"mov eax, [rbp-0x{i:x}]  ; {'x' * 150}" for i in range(400))
    client.post(f"/findings/{fid}/code-evidence", data={"_csrf": csrf, "title": "Long listing",
                                                        "language": "asm", "code": long_code,
                                                        "location": "a" * 300})
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 200 and resp.data.startswith(b"%PDF")


# ------------------------------------------------------- RE target kinds --

def test_binary_and_firmware_targets(client, csrf, make_report):
    report_id = make_report(language="pl")
    for kind in ("binary", "firmware"):
        resp = client.post(f"/reports/{report_id}/targets/new", data={"_csrf": csrf, "name": f"t-{kind}",
                                                                      "kind": kind, "address": "fw/x.bin"})
        assert resp.status_code == 302
    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "Binary" in page and "Firmware" in page and "#i-chip" in page
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "Plik wykonywalny" in md
    resp = client.post(f"/reports/{report_id}/targets/new", data={"_csrf": csrf, "name": "x", "kind": "toaster"})
    assert resp.status_code == 422


# ------------------------------------------------- real ptai engagement output --

def test_ptai_json_report_real_output():
    parsed = ai_import.parse(_bytes("ptai-report.json"))
    assert parsed["format"] == "ptai"
    items = parsed["items"]
    def by_title(prefix):
        return next(i for i in items if i["data"]["title"].startswith(prefix))

    assert len(items) == 8
    traversal = by_title("Path traversal")
    assert traversal["verdict"] == "verified"
    assert traversal["data"]["severity"] == "critical"
    assert traversal["data"]["cwe"] == "CWE-22"
    assert "idempotent_replay" in traversal["data"]["technical_details"]
    assert "replayed 3/3" in traversal["data"]["technical_details"]
    assert "root:x:0:0" in traversal["data"]["technical_details"]
    assert "curl" in traversal["data"]["poc"]
    assert traversal["data"]["remediation"].startswith("Validate the file argument")
    assert traversal["data"]["targets"][0]["address"].startswith("http://127.0.0.1:8002")
    assert traversal["source"] == {"tool": "ptai", "version": "", "run_id": "6f4854e0"}
    sqli = by_title("SQLi login bypass")
    assert (sqli["verdict"], sqli["data"]["severity"], sqli["data"]["cwe"]) == ("candidate", "critical", "CWE-89")
    assert {i["data"]["cwe"] for i in items if "XSS" in i["data"]["title"]} == {"CWE-79"}
    assert by_title("Open Redirect")["data"]["cwe"] == "CWE-601"
    assert by_title("Missing security headers")["data"]["cwe"] == "CWE-693"
    assert all(not i["data"]["files"] for i in items)  # no capsule to attach for a report


def test_ptai_json_report_refuted_and_receipt_json(tmp_path):
    doc = json.loads(_bytes("ptai-report.json"))
    doc["findings"][0]["verdict"] = "refuted"
    doc["findings"][0].pop("receipt")
    doc["findings"][0]["receipt_json"] = json.dumps({"verdict": "refuted"})
    doc["findings"][1] = "not an object"
    parsed = ai_import.parse(json.dumps(doc).encode())
    assert len(parsed["items"]) == 6
    assert any("refuted" in w for w in parsed["warnings"])
    assert any("not an object" in w for w in parsed["warnings"])


def test_ptai_real_sarif_warns_about_grouped_rules():
    parsed = ai_import.parse(_bytes("ptai-real.sarif"))
    assert parsed["format"] == "sarif"
    assert any("ptai report <id> -f json" in w for w in parsed["warnings"])
    # the hand-written SARIF has a message per result: no warning
    assert not any("-f json" in w for w in ai_import.parse(_bytes("ptai.sarif"))["warnings"])


def test_web_import_of_ptai_json_report(client, csrf, make_report):
    report = make_report()
    r = _upload(client, csrf, report, "ptai-report.json")
    assert r.status_code == 302
    conn = _conn(client)
    rows = conn.execute("SELECT kind, verdict FROM ai_proposals WHERE report_id = ?", (report,)).fetchall()
    assert len(rows) == 8 and sum(1 for r in rows if r["verdict"] == "verified") == 5
