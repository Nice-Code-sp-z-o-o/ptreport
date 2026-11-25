VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_api_requires_token(client):
    assert client.get("/api/v1/ping").status_code == 401
    assert client.get("/api/v1/ping", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/v1/ping", headers={"Authorization": "Basic abc"}).status_code == 401
    resp = client.post("/api/v1/reports/1/findings", json={"title": "x"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "unauthorized"


def test_ping_and_list_reports(client, api_headers, make_report):
    assert client.get("/api/v1/ping", headers=api_headers).get_json()["api"] == "v1"
    report_id = make_report(title="API report")
    reports = client.get("/api/v1/reports", headers=api_headers).get_json()["reports"]
    assert [r["id"] for r in reports] == [report_id]
    assert client.get("/api/v1/reports/999", headers=api_headers).status_code == 404


def test_create_target_and_finding_with_evidence(client, api_headers, make_report):
    report_id = make_report(finding_prefix="BURP")
    t = client.post(f"/api/v1/reports/{report_id}/targets", headers=api_headers,
                    json={"name": "Shop", "kind": "web", "address": "https://shop.example"})
    assert t.status_code == 201
    target_id = t.get_json()["target"]["id"]

    resp = client.post(f"/api/v1/reports/{report_id}/findings", headers=api_headers, json={
        "title": "IDOR on /api/orders/{id}", "cvss_version": "3.1", "cvss_vector": VECTOR, "cwe": "639",
        "severity": "critical",
        "target_ids": [target_id],
        "evidence": [{"title": "Other user's order", "request": "GET /api/orders/2 HTTP/1.1\r\nHost: shop.example\r\n\r\n",
                      "response": "HTTP/1.1 200 OK\r\n\r\n{}"}],
    })
    assert resp.status_code == 201, resp.get_json()
    finding = resp.get_json()["finding"]
    assert finding["display_id"] == "BURP-001"
    assert finding["severity"] == "critical"
    assert finding["target_ids"] == [target_id]
    assert finding["evidence_count"] == 1

    detail = client.get(f"/api/v1/findings/{finding['id']}", headers=api_headers).get_json()["finding"]
    assert detail["evidence"][0]["source"] == "burp"

    ev = client.post(f"/api/v1/findings/{finding['id']}/evidence", headers=api_headers,
                     json={"request": "POST /x HTTP/1.1\r\n\r\nid=1"})
    assert ev.status_code == 201
    listed = client.get(f"/api/v1/reports/{report_id}/findings", headers=api_headers).get_json()["findings"]
    assert listed[0]["evidence_count"] == 2


def test_api_validation_errors(client, api_headers, make_report, make_target):
    report_id = make_report()
    other = make_report()
    foreign_target = make_target(other)
    resp = client.post(f"/api/v1/reports/{report_id}/findings", headers=api_headers, json={
        "title": "", "cvss_version": "3.1", "cvss_vector": "bad", "target_ids": [foreign_target],
        "evidence": [{"request": ""}, "nope"]})
    assert resp.status_code == 422
    errors = resp.get_json()["errors"]
    assert {"title", "cvss_vector", "evidence[0].request", "evidence[1]"} <= set(errors)

    resp = client.post(f"/api/v1/reports/{report_id}/findings", headers=api_headers, json={
        "title": "x", "severity": "low", "target_ids": [foreign_target]})
    assert resp.status_code == 422 and "target_ids" in resp.get_json()["errors"]

    resp = client.post(f"/api/v1/reports/{report_id}/findings", headers=api_headers, data="[]",
                       content_type="application/json")
    assert resp.status_code == 400

    assert client.post("/api/v1/reports/999/findings", headers=api_headers, json={"title": "x"}).status_code == 404
    assert client.post("/api/v1/findings/999/evidence", headers=api_headers, json={"request": "x"}).status_code == 404


def test_api_does_not_need_csrf_but_web_does(client, api_headers, make_report):
    report_id = make_report()
    resp = client.post(f"/api/v1/reports/{report_id}/findings", headers=api_headers,
                       json={"title": "No CSRF needed", "severity": "info"})
    assert resp.status_code == 201
