from ptreport import export, repo
from ptreport.cwe import catalogue_version, cwe_choices, cwe_name, cwe_reference
from ptreport.db import connect


def db(client):
    return connect(client.application.config["DATABASE"])


def test_full_mitre_catalogue_is_bundled():
    choices = cwe_choices()
    assert len(choices) > 900 and catalogue_version()
    assert cwe_name("CWE-89").startswith("Improper Neutralization of Special Elements used in an SQL Command")
    ref = cwe_reference("CWE-79")
    assert "web page" in ref["description"] and ref["mitigation"].startswith("Phase:")
    assert cwe_reference("CWE-999999") == {"name": "", "description": "", "mitigation": ""}


def test_library_search_edit_and_use_in_reports(client, csrf, make_report, make_finding):
    page = client.get("/cwe-library?q=sql").get_data(as_text=True)
    assert "CWE-89" in page
    assert "CWE-79" in client.get("/cwe-library?q=79").get_data(as_text=True)
    assert "Nothing found" in client.get("/cwe-library?q=zzzzqqq").get_data(as_text=True)

    report_id = make_report(group_by_cwe="1")
    make_finding(report_id, cwe="79")
    conn = db(client)
    with client.application.app_context():
        group = export.build_context(conn, report_id)["groups"][0]
    assert group["description"] == cwe_reference("CWE-79")["description"]  # MITRE by default

    resp = client.post("/cwe-library/79", data={"_csrf": csrf, "description": "Our XSS intro", "mitigation": ""})
    assert resp.status_code == 302
    assert repo.get_cwe_library(conn, "CWE-79")["description"] == "Our XSS intro"
    with client.application.app_context():
        group = export.build_context(conn, report_id)["groups"][0]
    assert group["description"] == "Our XSS intro"
    assert group["mitigation"] == cwe_reference("CWE-79")["mitigation"]  # still MITRE for the empty field

    # a report's own text wins over the library
    client.post(f"/reports/{report_id}/cwe-groups", data={"_csrf": csrf, "cwe": "CWE-79", "description": "Report text"})
    with client.application.app_context():
        group = export.build_context(conn, report_id)["groups"][0]
    assert group["description"] == "Report text"

    # without MITRE text only the user's library is used
    client.post(f"/reports/{report_id}/cwe-groups", data={"_csrf": csrf, "cwe": "CWE-79", "description": ""})
    assert client.post("/cwe-library/settings", data={"_csrf": csrf, "use_mitre": "0"}).status_code == 302
    with client.application.app_context():
        group = export.build_context(conn, report_id)["groups"][0]
    assert (group["description"], group["mitigation"]) == ("Our XSS intro", "")

    # emptying both fields removes the entry
    client.post("/cwe-library/79", data={"_csrf": csrf, "description": "", "mitigation": ""})
    assert repo.get_cwe_library(conn, "CWE-79") is None
    assert client.post("/cwe-library/79", data={"description": "x"}).status_code == 400  # CSRF
    conn.close()


def test_default_language_for_new_reports(client, csrf):
    assert 'value="en" selected' in client.get("/reports/new").get_data(as_text=True)
    resp = client.post("/settings/finding-ids", data={"_csrf": csrf, "id_format": "{prefix}-{n:3}", "id_start": "1",
                                                     "default_prefix": "VULN", "default_language": "pl"})
    assert resp.status_code == 302
    assert 'value="pl" selected' in client.get("/reports/new").get_data(as_text=True)
    bad = client.post("/settings/finding-ids", data={"_csrf": csrf, "id_format": "{prefix}-{n:3}", "id_start": "1",
                                                    "default_prefix": "VULN", "default_language": "de"})
    assert bad.status_code == 422
