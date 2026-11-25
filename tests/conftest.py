import re

import pytest

from ptreport.app import create_app

API_TOKEN = "test-token-0123456789abcdefghijklmnop"


@pytest.fixture()
def app(tmp_path):
    app = create_app({"DATA_DIR": str(tmp_path), "TESTING": True, "API_TOKEN": API_TOKEN})
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def csrf(client):
    html = client.get("/reports/new").get_data(as_text=True)
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


@pytest.fixture()
def api_headers():
    return {"Authorization": f"Bearer {API_TOKEN}"}


@pytest.fixture()
def make_report(client, csrf):
    def _make(**overrides):
        data = {"_csrf": csrf, "title": "Test report", "client_name": "ACME", "assessor": "Jan Kowalski",
                "finding_prefix": "ACME", "language": "en", "start_date": "2026-11-01", "end_date": "2026-11-10"}
        data.update(overrides)
        resp = client.post("/reports/new", data=data)
        assert resp.status_code == 302, resp.get_data(as_text=True)
        return int(resp.headers["Location"].rsplit("/", 1)[1])
    return _make


@pytest.fixture()
def make_target(client, csrf):
    def _make(report_id, **overrides):
        data = {"_csrf": csrf, "name": "Portal", "kind": "web", "address": "https://portal.example"}
        data.update(overrides)
        assert client.post(f"/reports/{report_id}/targets/new", data=data).status_code == 302
        from ptreport import repo
        from ptreport.db import connect
        conn = connect(client.application.config["DATABASE"])
        try:
            return max(t["id"] for t in repo.list_targets(conn, report_id))
        finally:
            conn.close()
    return _make


@pytest.fixture()
def make_finding(client, csrf):
    def _make(report_id, **overrides):
        data = {"_csrf": csrf, "title": "SQL injection", "cvss_version": "3.1",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "status": "open",
                "severity": "critical"}
        data.update(overrides)
        resp = client.post(f"/reports/{report_id}/findings/new", data=data)
        assert resp.status_code == 302, resp.get_data(as_text=True)
        return int(resp.headers["Location"].split("/")[-2])
    return _make
