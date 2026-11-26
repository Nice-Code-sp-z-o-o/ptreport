"""AI intake queue: integration tokens, proposals API, review UI (accept / merge / reject), provenance."""

import base64
import hashlib
import json
import re

import pytest

from ptreport import proposals, repo
from ptreport.app import create_app
from ptreport.db import MIGRATIONS, connect

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
REQUEST = "GET /search?q=%3Cscript%3E HTTP/1.1\r\nHost: shop.example\r\n\r\n"


def _conn(client):
    return connect(client.application.config["DATABASE"])


def _finding_proposal(**data):
    body = {"title": "Reflected XSS in search", "severity": "medium", "cvss_vector": VECTOR, "cwe": "CWE-79",
            "description": "The q parameter is reflected without encoding.",
            "targets": ["https://shop.example/search?q=1"],
            "evidence": [{"title": "Reflection", "request": REQUEST, "response": "HTTP/1.1 200 OK\r\n\r\n<script>"}]}
    body.update(data)
    return {"kind": "finding", "verdict": "verified",
            "source": {"tool": "ptai", "version": "1.6.2", "run_id": "7f3a", "model": "test-model"},
            "data": body}


def _token(client, csrf, scopes=("read", "propose"), name="agent"):
    resp = client.post("/settings/integrations", data={"_csrf": csrf, "name": name, "scopes": list(scopes)})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    html = resp.get_data(as_text=True)
    token = re.search(r'id="new-int-token"[^>]*value="(ptr_[^"]+)"', html).group(1)
    return token, {"Authorization": f"Bearer {token}"}


def _queue(client, report_id, items, headers):
    return client.post(f"/api/v1/reports/{report_id}/proposals", headers=headers, json=items)


# ---------------------------------------------------------------- schema --

def test_migration_15_tables(app):
    conn = connect(app.config["DATABASE"])
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS) >= 15
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        assert {"ai_proposals", "integration_tokens", "code_evidence", "idx_ai_proposals_report_status"} <= names
        cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        assert "origin" in cols
    finally:
        conn.close()


# ------------------------------------------------------------ tokens/auth --

def test_integration_token_shown_once_and_stored_hashed(client, csrf):
    token, _ = _token(client, csrf, ("read",), name="CI job")
    assert token.startswith("ptr_")
    conn = _conn(client)
    try:
        row = conn.execute("SELECT * FROM integration_tokens").fetchone()
        assert row["token_sha256"] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in json.dumps(dict(row))
        assert row["scopes"] == "read"
    finally:
        conn.close()
    page = client.get("/settings").get_data(as_text=True)
    assert "CI job" in page and token not in page


def test_integration_token_validation_and_csrf(client, csrf):
    resp = client.post("/settings/integrations", data={"_csrf": csrf, "name": "", "scopes": []})
    assert resp.status_code == 422
    html = resp.get_data(as_text=True)
    assert "Name is required" in html and "Choose at least one scope" in html
    resp = client.post("/settings/integrations", data={"_csrf": csrf, "name": "x", "scopes": ["admin"]})
    assert resp.status_code == 422
    assert client.post("/settings/integrations", data={"name": "x", "scopes": ["read"]}).status_code == 400


def test_scopes_are_enforced(client, csrf, make_report, api_headers):
    report_id = make_report()
    _, read = _token(client, csrf, ("read",))
    _, propose = _token(client, csrf, ("propose",))
    assert client.get("/api/v1/reports", headers=read).status_code == 200
    assert client.get(f"/api/v1/reports/{report_id}/findings", headers=read).status_code == 200
    assert client.get("/api/v1/cwe?q=xss", headers=read).status_code == 200
    assert client.get("/api/v1/ping", headers=propose).status_code == 200
    # read cannot propose or write; propose cannot read; neither reaches full-token endpoints
    assert _queue(client, report_id, _finding_proposal(), read).status_code == 403
    assert client.post(f"/api/v1/reports/{report_id}/findings", headers=read,
                       json={"title": "x", "severity": "low"}).status_code == 403
    assert client.get("/api/v1/reports", headers=propose).status_code == 403
    assert client.get(f"/api/v1/reports/{report_id}/notes", headers=read).status_code == 403
    assert _queue(client, report_id, _finding_proposal(), propose).status_code == 201
    # the main token keeps full access
    assert _queue(client, report_id, _finding_proposal(), api_headers).status_code == 201
    assert client.get(f"/api/v1/reports/{report_id}/notes", headers=api_headers).status_code == 200


def test_revoked_and_unknown_tokens_are_rejected(client, csrf, make_report):
    report_id = make_report()
    _, headers = _token(client, csrf)
    assert client.get("/api/v1/reports", headers=headers).status_code == 200
    conn = _conn(client)
    try:
        token_id = conn.execute("SELECT id FROM integration_tokens").fetchone()[0]
        assert conn.execute("SELECT last_used_at FROM integration_tokens").fetchone()[0] is not None
    finally:
        conn.close()
    assert client.post(f"/settings/integrations/{token_id}/revoke", data={"_csrf": csrf}).status_code == 302
    assert client.get("/api/v1/reports", headers=headers).status_code == 401
    assert _queue(client, report_id, _finding_proposal(), headers).status_code == 401
    bad = {"Authorization": "Bearer ptr_" + "x" * 43}
    assert client.get("/api/v1/reports", headers=bad).status_code == 401
    assert client.post("/settings/integrations/999/revoke", data={"_csrf": csrf}).status_code == 404


# -------------------------------------------------------------- proposals --

def test_create_and_list_proposals(client, make_report, api_headers):
    report_id = make_report()
    resp = _queue(client, report_id, _finding_proposal(), api_headers)
    assert resp.status_code == 201, resp.get_json()
    out = resp.get_json()
    assert out["proposals"][0]["status"] == "pending"
    assert out["review_url"].endswith(f"/reports/{report_id}/ai-queue")
    envelope = {"format": "ptreport-proposals", "version": 1, "source": {"tool": "re-agent", "model": "m1"},
                "proposals": [{"kind": "target", "data": {"name": "router.bin", "kind": "firmware",
                                                          "address": "fw/router-2.1.bin"}},
                              _finding_proposal(title="SQL injection in login", cwe="89")]}
    resp = _queue(client, report_id, envelope, api_headers)
    assert resp.status_code == 201, resp.get_json()
    created = resp.get_json()["proposals"]
    assert created[0]["source_tool"] == "re-agent" and created[0]["model"] == "m1"
    assert created[1]["source_tool"] == "ptai"  # a proposal's own source wins over the envelope's
    listed = client.get(f"/api/v1/reports/{report_id}/proposals?status=pending", headers=api_headers).get_json()
    assert len(listed["proposals"]) == 3
    assert client.get(f"/api/v1/reports/{report_id}/proposals?status=nope", headers=api_headers).status_code == 422
    # nothing reached the report itself
    assert client.get(f"/api/v1/reports/{report_id}/findings", headers=api_headers).get_json()["findings"] == []


def test_proposal_validation_is_all_or_nothing(client, make_report, make_finding, api_headers):
    report_id = make_report()
    other_finding = make_finding(make_report())
    bad = [
        _finding_proposal(),
        _finding_proposal(cvss_vector="CVSS:3.1/AV:X"),
        _finding_proposal(cwe="XSS"),
        _finding_proposal(title=""),
        {"kind": "evidence", "data": {"request": REQUEST}},
        {"kind": "evidence", "finding_id": other_finding, "data": {"request": REQUEST}},
        {"kind": "file", "finding_id": other_finding, "data": {"filename": "a.bin", "data_base64": "%%%"}},
        {"kind": "finding", "verdict": "maybe", "data": {"title": "x", "severity": "low"}},
        {"kind": "nope"},
        "text",
    ]
    resp = _queue(client, report_id, bad, api_headers)
    assert resp.status_code == 422
    errors = resp.get_json()["errors"]
    for key in ("[1].data.cvss_vector", "[2].data.cwe", "[3].data.title", "[4].finding_id", "[5].finding_id",
                "[7].verdict", "[8].kind", "[9].proposal"):
        assert key in errors, (key, errors)
    conn = _conn(client)
    try:
        assert repo.list_proposals(conn, report_id) == []
    finally:
        conn.close()
    assert _queue(client, report_id, [_finding_proposal()] * 201, api_headers).status_code == 422
    assert _queue(client, report_id, [], api_headers).status_code == 422
    assert client.post(f"/api/v1/reports/{report_id}/proposals", headers=api_headers, data="x",
                       content_type="application/json").status_code == 400
    assert _queue(client, 999, _finding_proposal(), api_headers).status_code == 404


def test_untrusted_lengths_and_types(client, make_report, api_headers):
    report_id = make_report()
    resp = _queue(client, report_id, _finding_proposal(title="x" * 301, description=["not", "text"],
                                                       targets="https://a.example"), api_headers)
    assert resp.status_code == 422
    errors = resp.get_json()["errors"]
    assert "[0].data.title" in errors and "[0].data.description" in errors and "[0].data.targets" in errors
    item = _finding_proposal()
    item["source"] = {"tool": "a\nb"}
    resp = _queue(client, report_id, item, api_headers)
    assert "[0].source.tool" in resp.get_json()["errors"]


def test_proposal_rate_limit(tmp_path):
    app = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "API_TOKEN": "t" * 40,
                      "PROPOSAL_RATE_CAPACITY": 3, "PROPOSAL_RATE_PER_SECOND": 0.0001})
    client = app.test_client()
    headers = {"Authorization": "Bearer " + "t" * 40}
    conn = connect(app.config["DATABASE"])
    from ptreport.validation import validate_report
    report_id = repo.create_report(conn, validate_report({"title": "R"})[0])
    conn.close()
    assert _queue(client, report_id, [_finding_proposal()] * 2, headers).status_code == 201
    assert _queue(client, report_id, [_finding_proposal()] * 2, headers).status_code == 429


# --------------------------------------------------------------- review UI --

def test_queue_page_groups_and_duplicate_hint(client, make_report, make_finding, make_target, api_headers):
    report_id = make_report()
    target = make_target(report_id, name="Shop", address="https://shop.example")
    make_finding(report_id, title="Cross-site scripting in search", cwe="CWE-79", target_ids=[target],
                 severity="medium")
    _queue(client, report_id, [_finding_proposal(), {"kind": "target", "data": {"address": "10.0.0.5"}}],
           api_headers)
    html = client.get(f"/reports/{report_id}/ai-queue").get_data(as_text=True)
    assert "Findings <span class=\"muted\">(1)</span>" in html and "Targets <span" in html
    assert "Looks like" in html and "ACME-001" in html and "same CWE-79 on the same target" in html
    assert "verified" in html and "ptai" in html and "run 7f3a" in html and "test-model" in html
    detail = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "AI queue" in detail and 'aria-label="2 pending"' in detail


def test_title_similarity_hint(client, make_report, make_finding, api_headers):
    report_id = make_report()
    make_finding(report_id, title="Reflected XSS in the search", severity="low")
    _queue(client, report_id, _finding_proposal(cwe="", targets=[]), api_headers)
    html = client.get(f"/reports/{report_id}/ai-queue").get_data(as_text=True)
    assert "similar title" in html


def test_accept_creates_finding_with_origin(client, csrf, make_report, make_target, api_headers):
    report_id = make_report()
    make_target(report_id, name="Existing shop", address="https://shop.example")
    pid = _queue(client, report_id, _finding_proposal(), api_headers).get_json()["proposals"][0]["id"]
    resp = client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf})
    assert resp.status_code == 302
    conn = _conn(client)
    try:
        findings = repo.list_findings(conn, report_id)
        assert len(findings) == 1
        f = findings[0]
        assert f["status"] == "open" and f["confidence"] == "certain" and f["cwe"] == "CWE-79"
        assert f["cvss_score"] == 6.1
        assert f["origin"] == "ptai 1.6.2 · run 7f3a · verified · model test-model"
        assert [t["name"] for t in f["targets"]] == ["Existing shop"]  # reused by address
        assert len(repo.list_targets(conn, report_id)) == 1
        assert f["evidence"][0]["source"] == "ai"
        assert f["history"][-1]["description"] == "Added from ptai (7f3a) – AI proposal accepted"
        assert repo.get_proposal(conn, pid)["status"] == "accepted"
    finally:
        conn.close()
    detail = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert 'class="chip pill-src pill-ai" title="ptai 1.6.2 · run 7f3a · verified · model test-model"' in detail
    page = client.get(f"/findings/{f['id']}/edit").get_data(as_text=True)
    assert "pill-ai" in page
    # deciding again is refused
    client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf})
    conn = _conn(client)
    try:
        assert len(repo.list_findings(conn, report_id)) == 1
    finally:
        conn.close()


def test_candidate_maps_to_unknown_confidence(client, csrf, make_report, api_headers):
    report_id = make_report()
    item = _finding_proposal()
    item["verdict"] = "candidate"
    pid = _queue(client, report_id, item, api_headers).get_json()["proposals"][0]["id"]
    client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf})
    conn = _conn(client)
    try:
        assert repo.list_findings(conn, report_id)[0]["confidence"] == "unknown"
    finally:
        conn.close()


def test_merge_into_existing_finding(client, csrf, make_report, make_finding, api_headers):
    report_id = make_report()
    fid = make_finding(report_id, title="XSS", cwe="CWE-79", severity="medium")
    item = _finding_proposal(code_evidence=[{"title": "Sink", "location": "web/search.py:42", "language": "python",
                                             "code": "return f'<p>{q}</p>'"}])
    pid = _queue(client, report_id, item, api_headers).get_json()["proposals"][0]["id"]
    assert client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf, "merge_into": fid}).status_code == 302
    conn = _conn(client)
    try:
        f = repo.get_finding(conn, fid)
        assert len(f["evidence"]) == 1 and len(f["code_evidence"]) == 1
        assert f["title"] == "XSS" and f["origin"] == ""  # text and provenance of the finding stay
        assert "Merged AI proposal from ptai (7f3a)" in f["history"][-1]["description"]
        assert repo.get_proposal(conn, pid)["status"] == "merged"
        assert len(repo.list_findings(conn, report_id)) == 1
    finally:
        conn.close()


def test_merge_into_foreign_finding_is_refused(client, csrf, make_report, make_finding, api_headers):
    report_id = make_report()
    foreign = make_finding(make_report())
    pid = _queue(client, report_id, _finding_proposal(), api_headers).get_json()["proposals"][0]["id"]
    client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf, "merge_into": foreign})
    conn = _conn(client)
    try:
        assert repo.get_proposal(conn, pid)["status"] == "pending"
        assert repo.get_finding(conn, foreign)["evidence"] == []
    finally:
        conn.close()
    assert client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf, "merge_into": "x"}).status_code == 400


def test_reject_and_csrf(client, csrf, make_report, api_headers):
    report_id = make_report()
    pid = _queue(client, report_id, _finding_proposal(), api_headers).get_json()["proposals"][0]["id"]
    assert client.post(f"/ai-proposals/{pid}/reject").status_code == 400
    assert client.post(f"/ai-proposals/{pid}/accept").status_code == 400
    assert client.post(f"/ai-proposals/{pid}/reject", data={"_csrf": csrf}).status_code == 302
    conn = _conn(client)
    try:
        assert repo.get_proposal(conn, pid)["status"] == "rejected"
        assert repo.list_findings(conn, report_id) == []
    finally:
        conn.close()
    assert client.post("/ai-proposals/999/reject", data={"_csrf": csrf}).status_code == 404


def test_bulk_accept_and_reject(client, csrf, make_report, api_headers):
    report_id = make_report()
    ids = [p["id"] for p in _queue(client, report_id, [_finding_proposal(title=f"Issue {i}") for i in range(3)],
                                   api_headers).get_json()["proposals"]]
    other = make_report()
    foreign = _queue(client, other, _finding_proposal(), api_headers).get_json()["proposals"][0]["id"]
    resp = client.post(f"/reports/{report_id}/ai-queue/bulk",
                       data={"_csrf": csrf, "action": "accept", "proposal": [ids[0], ids[1], foreign]})
    assert resp.status_code == 302
    client.post(f"/reports/{report_id}/ai-queue/bulk", data={"_csrf": csrf, "action": "reject",
                                                             "proposal": [ids[2]]})
    conn = _conn(client)
    try:
        assert [repo.get_proposal(conn, i)["status"] for i in ids] == ["accepted", "accepted", "rejected"]
        assert repo.get_proposal(conn, foreign)["status"] == "pending"
        assert len(repo.list_findings(conn, report_id)) == 2
    finally:
        conn.close()
    assert client.post(f"/reports/{report_id}/ai-queue/bulk", data={"_csrf": csrf, "action": "x"}).status_code == 400
    assert client.post(f"/reports/{report_id}/ai-queue/bulk", data={"action": "accept"}).status_code == 400


def test_evidence_code_file_proposals(client, csrf, make_report, make_finding, api_headers):
    report_id = make_report()
    fid = make_finding(report_id)
    blob = b"\x7fELF fake sample"
    items = [
        {"kind": "evidence", "finding_id": fid, "data": {"title": "Replay", "request": REQUEST}},
        {"kind": "code", "finding_id": fid, "data": {"title": "check_pw", "location": "auth.c:120 check_pw @ 0x401a2c",
                                                     "language": "pseudo", "code": "if (strcmp(a, b)) {}"}},
        {"kind": "file", "finding_id": fid, "data": {"filename": "../../sample.bin", "description": "Analysed",
                                                     "data_base64": base64.b64encode(blob).decode()}},
    ]
    created = _queue(client, report_id, items, api_headers).get_json()["proposals"]
    assert created[2]["data"]["sha256"] == hashlib.sha256(blob).hexdigest()
    assert "data_base64" not in created[2]["data"]
    for p in created:
        assert client.post(f"/ai-proposals/{p['id']}/accept", data={"_csrf": csrf}).status_code == 302
    conn = _conn(client)
    try:
        f = repo.get_finding(conn, fid)
        assert f["evidence"][0]["source"] == "ai"
        assert f["code_evidence"][0]["language"] == "pseudo"
        assert f["files"][0]["filename"] == "sample.bin"
        assert f["files"][0]["sha256"] == hashlib.sha256(blob).hexdigest()
        assert all(repo.get_proposal(conn, p["id"])["status"] == "accepted" for p in created)
    finally:
        conn.close()


def test_retest_proposal_fills_retest_fields(client, csrf, make_report, make_finding, api_headers):
    report_id = make_report()
    fid = make_finding(report_id)
    item = {"kind": "retest", "finding_id": fid, "verdict": "verified", "source": {"tool": "ptai", "run_id": "r2"},
            "data": {"result": "not_fixed", "date": "2026-11-20", "notes": "Payload still executes.",
                     "evidence": [{"request": REQUEST, "response": "HTTP/1.1 200 OK\r\n\r\n<script>"}]}}
    pid = _queue(client, report_id, item, api_headers).get_json()["proposals"][0]["id"]
    assert _queue(client, report_id, {**item, "data": {"result": "gone"}}, api_headers).status_code == 422
    assert _queue(client, report_id, {**item, "data": {"notes": "x"}}, api_headers).status_code == 422
    client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf})
    conn = _conn(client)
    try:
        f = repo.get_finding(conn, fid)
        assert (f["retest_result"], f["retest_date"], f["retest_notes"]) == ("not_fixed", "2026-11-20",
                                                                             "Payload still executes.")
        assert f["status"] == "open"  # the status is the tester's call
        assert len(f["evidence"]) == 1
        assert f["history"][-1]["description"] == "Retest: Not fixed – from ptai (r2) – AI proposal accepted"
    finally:
        conn.close()


def test_stored_payload_is_revalidated_on_accept(client, csrf, make_report, api_headers):
    report_id = make_report()
    pid = _queue(client, report_id, _finding_proposal(), api_headers).get_json()["proposals"][0]["id"]
    conn = _conn(client)
    try:
        payload = json.loads(conn.execute("SELECT payload FROM ai_proposals WHERE id = ?", (pid,)).fetchone()[0])
        payload["cvss_vector"] = "CVSS:3.1/broken"
        conn.execute("UPDATE ai_proposals SET payload = ? WHERE id = ?", (json.dumps(payload), pid))
    finally:
        conn.close()
    client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf})
    conn = _conn(client)
    try:
        assert repo.get_proposal(conn, pid)["status"] == "pending"
        assert repo.list_findings(conn, report_id) == []
    finally:
        conn.close()


def test_origin_survives_json_export_import_and_clone_but_not_html(client, csrf, make_report, api_headers):
    report_id = make_report()
    pid = _queue(client, report_id, _finding_proposal(), api_headers).get_json()["proposals"][0]["id"]
    client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf})
    doc = json.loads(client.get(f"/reports/{report_id}/export/json").get_data())
    assert doc["findings"][0]["origin"].startswith("ptai 1.6.2")
    for fmt in ("html", "md"):
        assert "ptai 1.6.2" not in client.get(f"/reports/{report_id}/export/{fmt}").get_data(as_text=True)
    from io import BytesIO
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")})
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    copy_id = int(client.post(f"/reports/{report_id}/retest", data={"_csrf": csrf}).headers["Location"]
                  .rsplit("/", 1)[1])
    conn = _conn(client)
    try:
        for rid in (new_id, copy_id):
            assert repo.list_findings(conn, rid)[0]["origin"].startswith("ptai 1.6.2")
    finally:
        conn.close()
    doc["findings"][0]["origin"] = "x\ny"
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")})
    assert resp.status_code == 422


def test_editing_a_finding_keeps_its_origin(client, csrf, make_report, api_headers):
    report_id = make_report()
    pid = _queue(client, report_id, _finding_proposal(), api_headers).get_json()["proposals"][0]["id"]
    client.post(f"/ai-proposals/{pid}/accept", data={"_csrf": csrf})
    conn = _conn(client)
    fid = repo.list_findings(conn, report_id)[0]["id"]
    conn.close()
    resp = client.post(f"/findings/{fid}/edit", data={"_csrf": csrf, "title": "Edited", "severity": "low",
                                                      "status": "fixed"})
    assert resp.status_code == 302
    conn = _conn(client)
    try:
        assert repo.get_finding(conn, fid)["origin"].startswith("ptai")
    finally:
        conn.close()


@pytest.mark.parametrize("address,expected", [
    ("https://Shop.example:443/x", "shop.example"),
    ("http://127.0.0.1:53005/search", "127.0.0.1:53005"),
    ("10.0.0.5", "10.0.0.5"),
    ("shop.example/path", "shop.example"),
    ("http://[::1", ""),
])
def test_host_key(address, expected):
    assert proposals.host_key(address) == expected
