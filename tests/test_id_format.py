import pytest

from ptreport import ids, repo
from ptreport.db import connect


@pytest.mark.parametrize("template,prefix,n,year,expected", [
    ("{prefix}-{n:3}", "ACME", 1, None, "ACME-001"),
    ("{prefix}-{n:4}", "SEC", 2, None, "SEC-0002"),
    ("{prefix}_{n}", "VULN", 12, None, "VULN_12"),
    ("{year}/{prefix}/{n:2}", "PT", 7, 2026, "2026/PT/07"),
    ("#{n}", "X", 5, None, "#5"),
])
def test_render(template, prefix, n, year, expected):
    assert ids.render(template, prefix, n, year) == expected


@pytest.mark.parametrize("template", ["", "{prefix}", "{n}-{n}", "{n:7}", "{prefix}-{x}-{n}", "<{n}>", "{n}" + "a" * 40, "{n:}"])
def test_invalid_templates(template):
    assert ids.template_error(template)


@pytest.mark.parametrize("template", ["{prefix}-{n:3}", "{n}", "{year}/{prefix}/{n:6}", "F {n:2}"])
def test_valid_templates(template):
    assert ids.template_error(template) is None


def _settings_post(client, csrf, **data):
    return client.post("/settings/finding-ids", data={"_csrf": csrf, **data})


def test_settings_change_ids_everywhere(client, csrf, make_report, make_finding, api_headers):
    report_id = make_report(finding_prefix="ACME")
    make_finding(report_id)
    assert "ACME-001" in client.get(f"/reports/{report_id}").get_data(as_text=True)

    resp = _settings_post(client, csrf, id_format="{prefix}-{n:4}", id_start="0", default_prefix="pt")
    assert resp.status_code == 302
    page = client.get("/settings").get_data(as_text=True)
    assert "PT-0000, PT-0001, PT-0002" in page
    assert 'value="0"' in page

    assert "ACME-0000" in client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "ACME-0000" in client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    findings = client.get(f"/api/v1/reports/{report_id}/findings", headers=api_headers).get_json()["findings"]
    assert findings[0]["display_id"] == "ACME-0000"
    # new reports start with the default prefix
    assert 'value="PT"' in client.get("/reports/new").get_data(as_text=True)


@pytest.mark.parametrize("field,value", [
    ("id_format", "{prefix}"), ("id_format", ""), ("id_start", "-1"), ("id_start", "abc"), ("id_start", "10000"),
    ("default_prefix", "1AB"), ("default_prefix", ""),
])
def test_settings_validation(client, csrf, field, value):
    data = {"id_format": "{prefix}-{n:3}", "id_start": "1", "default_prefix": "VULN", field: value}
    resp = _settings_post(client, csrf, **data)
    assert resp.status_code == 422
    conn = connect(client.application.config["DATABASE"])
    assert repo.get_settings(conn) == {"id_format": "{prefix}-{n:3}", "id_start": 1, "default_prefix": "VULN",
                                      "default_language": "en"}
    conn.close()


def test_settings_require_csrf(client):
    assert client.post("/settings/finding-ids", data={"id_format": "{n}", "id_start": "1",
                                                      "default_prefix": "A"}).status_code == 400


def test_report_override_and_external_id_precedence(client, csrf, make_report, make_finding):
    _settings_post(client, csrf, id_format="{prefix}-{n:3}", id_start="1", default_prefix="VULN")
    report_id = make_report(finding_prefix="NB", id_format="{year}-{prefix}-{n:2}", start_date="2025-03-01")
    make_finding(report_id)
    make_finding(report_id, title="Own id", external_id="CUSTOM-9")
    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "2025-NB-01" in page and "CUSTOM-9" in page

    resp = client.post(f"/reports/{report_id}/edit", data={"_csrf": csrf, "title": "T", "finding_prefix": "NB",
                                                          "language": "en", "id_format": "{n:9}"})
    assert resp.status_code == 422
