"""Scope out to agents: scope document, Markdown brief, CLI and API."""

import json

import pytest

from ptreport import cli, scope

SCOPE_TEXT = "The customer portal and its API.\n\n## Out of scope\n\n- The payment provider\n- DoS tests\n\n## Notes\n\nTest accounts from the client."


@pytest.mark.parametrize("text,inside,outside", [
    ("Only the shop.", "Only the shop.", ""),
    (SCOPE_TEXT, "The customer portal and its API.\n\n## Notes\n\nTest accounts from the client.",
     "- The payment provider\n- DoS tests"),
    ("Shop\nOut of scope:\nPayments", "Shop", "Payments"),
    ("Sklep\n\n### Poza zakresem\n\nPłatności", "Sklep", "Płatności"),
    ("**Excluded**\nMail server", "", "Mail server"),
])
def test_split_scope(text, inside, outside):
    assert scope.split_scope(text) == (inside, outside)


def _report(client, csrf, make_report, make_target):
    report_id = make_report(scope=SCOPE_TEXT, methodology="OWASP WSTG 4.2", vendor_name="Example Security",
                            vendor_contact="pentest@example.com", classification="TLP:AMBER")
    make_target(report_id, name="Portal", address="https://portal.example", description="Prod | EU")
    make_target(report_id, name="Router fw", kind="firmware", address="fw/router.bin")
    return report_id


def test_scope_api_json_and_markdown(client, csrf, make_report, make_target, api_headers):
    report_id = _report(client, csrf, make_report, make_target)
    doc = client.get(f"/api/v1/reports/{report_id}/scope", headers=api_headers).get_json()["scope"]
    assert doc["format"] == "ptreport-scope" and doc["client"] == "ACME"
    assert doc["dates"] == {"start": "2026-11-01", "end": "2026-11-10", "report_date": None}
    assert doc["out_of_scope"] == "- The payment provider\n- DoS tests"
    assert {t["kind"] for t in doc["targets"]} == {"web", "firmware"}
    assert doc["contacts"] == {"assessor": "Jan Kowalski", "prepared_by": "Example Security",
                               "contact": "pentest@example.com"}
    resp = client.get(f"/api/v1/reports/{report_id}/scope?format=md", headers=api_headers)
    assert resp.mimetype == "text/markdown"
    md = resp.get_data(as_text=True)
    assert md.startswith("# Engagement brief: Test report")
    assert "- **Testing window:** 2026-11-01 – 2026-11-10" in md
    assert "| Portal | Web application | https://portal.example | Prod \\| EU |" in md
    assert "## Out of scope\n\n- The payment provider" in md and "### Notes" in md
    assert f"POST /api/v1/reports/{report_id}/proposals" in md
    assert client.get(f"/api/v1/reports/{report_id}/scope?format=pdf", headers=api_headers).status_code == 422
    assert client.get("/api/v1/reports/999/scope", headers=api_headers).status_code == 404
    assert client.get(f"/api/v1/reports/{report_id}/scope").status_code == 401


def test_scope_needs_read_scope(client, csrf, make_report, make_target):
    report_id = _report(client, csrf, make_report, make_target)
    tokens = {}
    for scopes in (["read"], ["propose"]):
        html = client.post("/settings/integrations", data={"_csrf": csrf, "name": "x", "scopes": scopes}
                           ).get_data(as_text=True)
        tokens[scopes[0]] = html.split('id="new-int-token"')[1].split('value="')[1].split('"')[0]
    assert client.get(f"/api/v1/reports/{report_id}/scope",
                      headers={"Authorization": f"Bearer {tokens['read']}"}).status_code == 200
    assert client.get(f"/api/v1/reports/{report_id}/scope",
                      headers={"Authorization": f"Bearer {tokens['propose']}"}).status_code == 403


def test_brief_without_targets_or_out_of_scope(client, csrf, make_report, api_headers):
    report_id = make_report(scope="", start_date="", end_date="")
    md = client.get(f"/api/v1/reports/{report_id}/scope?format=md", headers=api_headers).get_data(as_text=True)
    assert "No targets are listed yet." in md and "Testing window:** not set" in md
    assert "everything not listed under Targets is out of scope" in md


def test_scope_cli(tmp_path, capsys):
    data_dir = str(tmp_path / "d")
    assert cli.main(["--data-dir", data_dir, "report", "create", "--title", "CLI \x1b[31mred", "--client",
                     "ACME", "--start-date", "2026-11-01"]) == 1  # control characters are rejected at input
    capsys.readouterr()
    assert cli.main(["--data-dir", data_dir, "report", "create", "--title", "CLI scope", "--client", "ACME"]) == 0
    report_id = capsys.readouterr().out.strip()
    assert cli.main(["scope", report_id, "--data-dir", data_dir]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["report"]["title"] == "CLI scope" and doc["client"] == "ACME"
    assert cli.main(["scope", report_id, "--format", "md", "--data-dir", data_dir]) == 0
    assert capsys.readouterr().out.startswith("# Engagement brief: CLI scope\n")
    assert cli.main(["scope", "999", "--data-dir", data_dir]) == 1
    assert "not found" in capsys.readouterr().err
