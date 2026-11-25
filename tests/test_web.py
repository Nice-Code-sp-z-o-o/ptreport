import json
import re

from ptreport import repo
from ptreport.db import connect

XSS = "<script>alert(1)</script>"


def db(client):
    return connect(client.application.config["DATABASE"])


def test_index_and_create_report(client, make_report):
    assert client.get("/").status_code == 200
    report_id = make_report(title="Portal test")
    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "Portal test" in page


def test_report_validation_errors_return_422(client, csrf):
    resp = client.post("/reports/new", data={"_csrf": csrf, "title": "", "assessor": "R2D2", "finding_prefix": "VULN"})
    assert resp.status_code == 422
    body = resp.get_data(as_text=True)
    assert "Report title is required." in body
    assert "no digits" in body


def test_post_without_csrf_is_rejected(client):
    resp = client.post("/reports/new", data={"title": "x", "finding_prefix": "VULN"})
    assert resp.status_code == 400
    resp = client.post("/reports/new", data={"_csrf": "forged", "title": "x", "finding_prefix": "VULN"})
    assert resp.status_code == 400


def test_untrusted_host_header_is_rejected(client):
    assert client.get("/", headers={"Host": "evil.example:5055"}).status_code == 400
    assert client.get("/", headers={"Host": "127.0.0.1:5055"}).status_code == 200
    assert client.get("/", headers={"Host": "[::1]:5055"}).status_code == 200


def test_security_headers(client):
    resp = client.get("/")
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    cookie = client.get("/reports/new").headers.get("Set-Cookie", "")
    assert "SameSite=Strict" in cookie and "HttpOnly" in cookie


def test_missing_resources_404(client):
    for path in ("/reports/999", "/findings/999/edit", "/targets/999/edit", "/reports/999/export/html"):
        assert client.get(path).status_code == 404


def test_finding_lifecycle_and_numbering(client, csrf, make_report, make_target, make_finding):
    report_id = make_report(finding_prefix="ACME")
    target_id = make_target(report_id)
    low = make_finding(report_id, title="Low thing", cvss_version="", cvss_vector="", severity="low",
                       target_ids=[str(target_id)])
    crit = make_finding(report_id, title="Crit thing")

    conn = db(client)
    findings = repo.list_findings(conn, report_id)
    assert [(f["id"], f["position"]) for f in findings] == [(low, 1), (crit, 2)]
    assert findings[0]["targets"][0]["id"] == target_id
    assert findings[1]["severity"] == "critical" and findings[1]["cvss_score"] == 9.8

    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "ACME-001" in page and "ACME-002" in page

    assert client.post(f"/reports/{report_id}/findings/renumber", data={"_csrf": csrf}).status_code == 302
    assert [f["id"] for f in repo.list_findings(conn, report_id)] == [crit, low]

    assert client.post(f"/findings/{crit}/move", data={"_csrf": csrf, "direction": "down"}).status_code == 302
    assert [f["id"] for f in repo.list_findings(conn, report_id)] == [low, crit]
    assert client.post(f"/findings/{crit}/move", data={"_csrf": csrf, "direction": "sideways"}).status_code == 400

    assert client.post(f"/findings/{low}/delete", data={"_csrf": csrf}).status_code == 302
    remaining = repo.list_findings(conn, report_id)
    assert [(f["id"], f["position"]) for f in remaining] == [(crit, 1)]
    conn.close()


def test_edit_finding(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    resp = client.post(f"/findings/{fid}/edit", data={
        "_csrf": csrf, "title": "Updated", "cvss_version": "4.0",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cwe": "89", "status": "fixed", "poc": "sqlmap -u ...", "severity": "high"})
    assert resp.status_code == 302
    conn = db(client)
    f = repo.get_finding(conn, fid)
    conn.close()
    assert (f["title"], f["cvss_version"], f["cvss_score"], f["cwe"], f["status"]) == ("Updated", "4.0", 9.3, "CWE-89", "fixed")
    assert f["severity"] == "high"  # kept as chosen although CVSS 9.3 rates Critical


def test_finding_invalid_input_422(client, csrf, make_report):
    report_id = make_report()
    resp = client.post(f"/reports/{report_id}/findings/new", data={
        "_csrf": csrf, "title": "", "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/AV:N", "cwe": "abc"})
    assert resp.status_code == 422
    body = resp.get_data(as_text=True)
    assert "Vulnerability title is required." in body
    assert "CWE must look like" in body


def test_finding_cannot_link_targets_of_another_report(client, csrf, make_report, make_target):
    r1, r2 = make_report(), make_report()
    foreign = make_target(r2)
    resp = client.post(f"/reports/{r1}/findings/new", data={
        "_csrf": csrf, "title": "x", "cvss_version": "", "severity": "low", "target_ids": [str(foreign)]})
    assert resp.status_code == 422
    assert "must belong to this report" in resp.get_data(as_text=True)


def test_user_content_is_escaped_everywhere(client, csrf, make_report, make_target, make_finding):
    report_id = make_report(title=XSS, executive_summary=XSS)
    target_id = make_target(report_id, name=XSS, address=XSS)
    fid = make_finding(report_id, title=XSS, description=XSS, poc=f"```\n{XSS}\n```",
                       refs="javascript:alert(1)", target_ids=[str(target_id)])
    client.post(f"/findings/{fid}/evidence", data={"_csrf": csrf, "title": XSS, "request": XSS, "response": XSS})
    for path in (f"/reports/{report_id}", f"/findings/{fid}/edit",
                 f"/reports/{report_id}/export/html", "/"):
        body = client.get(path).get_data(as_text=True)
        assert XSS not in body, path
        assert 'href="javascript:' not in body, path


def test_evidence_add_and_delete(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    assert client.post(f"/findings/{fid}/evidence", data={"_csrf": csrf, "request": ""}).status_code == 422
    resp = client.post(f"/findings/{fid}/evidence", data={
        "_csrf": csrf, "title": "Proof", "request": "GET / HTTP/1.1\nHost: x\n\n", "response": "HTTP/1.1 200 OK"})
    assert resp.status_code == 302
    conn = db(client)
    ev = repo.list_evidence(conn, fid)
    assert len(ev) == 1 and ev[0]["source"] == "manual"
    assert client.post(f"/evidence/{ev[0]['id']}/delete", data={"_csrf": csrf}).status_code == 302
    assert repo.list_evidence(conn, fid) == []
    conn.close()


def test_delete_report_cascades(client, csrf, make_report, make_target, make_finding):
    report_id = make_report()
    make_target(report_id)
    make_finding(report_id)
    assert client.post(f"/reports/{report_id}/delete", data={"_csrf": csrf}).status_code == 302
    conn = db(client)
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0] == 0
    conn.close()


def test_exports(client, csrf, make_report, make_target, make_finding):
    report_id = make_report(title="My/Report: 1", language="pl")
    target_id = make_target(report_id)
    fid = make_finding(report_id, cwe="79", target_ids=[str(target_id)], poc="```\ncode ``` inside\n```")
    client.post(f"/findings/{fid}/evidence", data={"_csrf": csrf, "request": "GET /a```b HTTP/1.1"})

    html = client.get(f"/reports/{report_id}/export/html")
    assert html.status_code == 200
    assert 'filename="My_Report_1.html"' in html.headers["Content-Disposition"]
    body = html.get_data(as_text=True)
    assert "<style>" in body and "<script" not in body
    assert "Raport z testów penetracyjnych" in body and "ACME-001" in body

    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "### ACME-001: SQL injection" in md
    assert "````http\nGET /a```b HTTP/1.1\n````" in md
    assert "CWE-79" in md

    exported = json.loads(client.get(f"/reports/{report_id}/export/json").get_data(as_text=True))
    assert exported["format"] == "ptreport"
    assert exported["findings"][0]["targets"] == [target_id]


def test_json_import_roundtrip(client, csrf, make_report, make_target, make_finding):
    report_id = make_report(title="Original")
    target_id = make_target(report_id)
    fid = make_finding(report_id, target_ids=[str(target_id)])
    client.post(f"/findings/{fid}/evidence", data={"_csrf": csrf, "request": "GET / HTTP/1.1"})
    exported = client.get(f"/reports/{report_id}/export/json").get_data()

    from io import BytesIO
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(exported), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    assert new_id != report_id
    conn = db(client)
    findings = repo.list_findings(conn, new_id)
    assert len(findings) == 1 and findings[0]["cvss_score"] == 9.8
    assert findings[0]["targets"][0]["report_id"] == new_id
    assert findings[0]["evidence"][0]["request"] == "GET / HTTP/1.1"
    conn.close()


def test_json_import_rejects_invalid(client, csrf):
    from io import BytesIO
    bad_docs = [
        b"not json",
        json.dumps({"format": "other"}).encode(),
        json.dumps({"format": "ptreport", "version": 1, "report": {"title": ""}, "targets": [], "findings": []}).encode(),
        json.dumps({"format": "ptreport", "version": 1, "report": {"title": "x"}, "targets": [],
                    "findings": [{"title": "f", "severity": "low", "targets": [{"x": 1}]}]}).encode(),
    ]
    for doc in bad_docs:
        resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(doc), "r.json")},
                           content_type="multipart/form-data")
        assert resp.status_code == 422
    conn = db(client)
    assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0
    conn.close()


def test_settings_shows_and_regenerates_token(client, csrf, app):
    old = app.config["API_TOKEN"]
    assert old in client.get("/settings").get_data(as_text=True)
    assert client.post("/settings/api-token", data={"_csrf": csrf}).status_code == 302
    assert app.config["API_TOKEN"] != old
    assert client.get("/api/v1/ping", headers={"Authorization": f"Bearer {old}"}).status_code == 401


def test_finding_form_renders_cvss_calculator(client, make_report):
    report_id = make_report()
    body = client.get(f"/reports/{report_id}/findings/new").get_data(as_text=True)
    assert 'id="cvss-defs"' in body
    defs = json.loads(re.search(r'<script type="application/json" id="cvss-defs">(.*?)</script>', body, re.S).group(1))
    assert set(defs) == {"4.0", "3.1", "3.0", "2.0"}
    assert "CWE-79" in body


def test_cvss_versions_only_in_column_header(client, make_report, make_finding):
    report_id = make_report()
    make_finding(report_id)  # CVSS 3.1
    make_finding(report_id, title="v4", cvss_version="4.0",
                 cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert '<th scope="col" class="col-cvss">CVSS 4.0 / 3.1</th>' in page
    assert ">v3.1<" not in page and ">v4.0<" not in page
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "<th>CVSS 4.0 / 3.1</th>" in html
