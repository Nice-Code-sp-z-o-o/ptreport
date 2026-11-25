import json
import re
from io import BytesIO
from pathlib import Path

from ptreport import repo
from ptreport.db import connect
from ptreport.rendering import richtext, text_blocks

from .test_screenshots_versions_meta import png_bytes, upload

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"


def db(client):
    return connect(client.application.config["DATABASE"])


def template_form(csrf, **overrides):
    data = {"_csrf": csrf, "title": "Weak password policy", "language": "en", "severity": "medium",
            "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "cwe": "521",
            "description": "Passwords may be short.", "remediation": "Require 12+ characters.", "tags": "auth"}
    data.update(overrides)
    return data


# ------------------------------------------------------------------ templates --

def test_starter_templates_are_seeded_once_in_both_languages(client):
    conn = db(client)
    rows = repo.list_templates(conn)
    assert len(rows) == 24
    assert {r["language"] for r in rows} == {"en", "pl"}
    assert any(r["title"] == "Składowany Cross-Site Scripting (XSS)" for r in rows)
    repo.delete_template(conn, rows[0])
    assert repo.seed_templates(conn) == 0  # deletions are respected, nothing comes back
    assert len(repo.list_templates(conn)) == 23
    conn.close()


def test_template_list_search_and_language_filter(client):
    page = client.get("/templates?q=xss&language=pl").get_data(as_text=True)
    assert "Odbity Cross-Site Scripting (XSS)" in page
    assert "Reflected Cross-Site Scripting (XSS)" not in page
    page = client.get("/templates?q=CWE-89").get_data(as_text=True)
    assert page.count("SQL Injection") >= 2
    # LIKE wildcards in the query are literal
    assert "No templates match" in client.get("/templates?q=%25%25_").get_data(as_text=True)


def test_template_crud_and_validation(client, csrf):
    assert client.post("/templates/new", data=template_form(csrf)).status_code == 302
    conn = db(client)
    tpl = repo.list_templates(conn, "Weak password")[0]
    assert (tpl["cwe"], tpl["severity"], tpl["tags"]) == ("CWE-521", "medium", "auth")

    for bad in ({"title": ""}, {"language": "de"}, {"severity": ""}, {"cvss_vector": "CVSS:3.1/AV:N"},
                {"cwe": "xss"}):
        assert client.post("/templates/new", data=template_form(csrf, **bad)).status_code == 422, bad
    assert client.post("/templates/new", data={k: v for k, v in template_form(csrf).items()
                                               if k != "_csrf"}).status_code == 400

    resp = client.post(f"/templates/{tpl['id']}/edit", data=template_form(csrf, title="Weak password policy v2",
                                                                         language="pl"))
    assert resp.status_code == 302
    assert repo.get_template(conn, tpl["id"])["language"] == "pl"
    assert client.post(f"/templates/{tpl['id']}/delete", data={"_csrf": csrf}).status_code == 302
    assert repo.get_template(conn, tpl["id"]) is None
    assert client.get(f"/templates/{tpl['id']}/edit").status_code == 404
    conn.close()


def test_new_finding_from_template_and_save_as_template(client, csrf, make_report, make_finding):
    report_id = make_report(language="pl")
    conn = db(client)
    tpl = next(t for t in repo.list_templates(conn) if t["title"] == "SQL Injection" and t["language"] == "pl")
    page = client.get(f"/reports/{report_id}/findings/new").get_data(as_text=True)
    assert "Start from a template" in page and "Report language (PL)" in page
    page = client.get(f"/reports/{report_id}/findings/new?template={tpl['id']}").get_data(as_text=True)
    assert 'value="SQL Injection"' in page
    assert "Stosować zapytania parametryzowane" in page
    assert client.get(f"/reports/{report_id}/findings/new?template=99999").status_code == 404

    fid = make_finding(report_id, title="Own finding", description="Custom text", cwe="CWE-200")
    assert client.post(f"/findings/{fid}/save-as-template", data={"_csrf": csrf}).status_code == 302
    saved = repo.list_templates(conn, "Own finding")[0]
    assert (saved["language"], saved["description"], saved["cwe"]) == ("pl", "Custom text", "CWE-200")
    assert client.post(f"/findings/{fid}/save-as-template").status_code == 400
    conn.close()


def test_template_export_import(client, csrf):
    exported = client.get("/templates/export")
    assert exported.status_code == 200 and "attachment" in exported.headers["Content-Disposition"]
    doc = json.loads(exported.data)
    assert doc["format"] == "ptreport-templates" and len(doc["templates"]) == 24

    resp = client.post("/templates/import", data={"_csrf": csrf, "file": (BytesIO(exported.data), "t.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    conn = db(client)
    assert len(repo.list_templates(conn)) == 48

    doc["templates"][1]["severity"] = "apocalyptic"
    resp = client.post("/templates/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "t.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 303
    assert len(repo.list_templates(conn)) == 48  # all or nothing
    for body in (b"not json", b"[]", b'{"templates": "x"}'):
        resp = client.post("/templates/import", data={"_csrf": csrf, "file": (BytesIO(body), "t.json")},
                           content_type="multipart/form-data")
        assert resp.status_code == 303
    conn.close()


def test_api_templates(client, api_headers):
    assert client.get("/api/v1/templates").status_code == 401
    rows = client.get("/api/v1/templates?language=en&q=csrf", headers=api_headers).get_json()["templates"]
    assert [r["title"] for r in rows] == ["Cross-Site Request Forgery (CSRF)"]


# --------------------------------------------------------------------- retest --

def test_retest_report_copies_everything_and_links_back(client, csrf, make_report, make_target, make_finding):
    report_id = make_report(title="Q1 test", group_by_cwe="1")
    target_id = make_target(report_id)
    fid = make_finding(report_id, target_ids=str(target_id), cwe="CWE-89")
    client.post(f"/findings/{fid}/evidence", data={"_csrf": csrf, "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n"})
    upload(client, csrf, fid, png_bytes(), caption="Proof")

    resp = client.post(f"/reports/{report_id}/retest", data={"_csrf": csrf})
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = db(client)
    new = repo.get_report(conn, new_id)
    assert new["retest_of"] == report_id and new["title"] == "Retest: Q1 test" and new["group_by_cwe"] == 1
    f = repo.list_findings(conn, new_id)[0]
    assert f["evidence"][0]["request"].startswith("GET /") and f["attachments"][0]["caption"] == "Proof"
    assert [t["name"] for t in f["targets"]] == ["Portal"] and f["targets"][0]["id"] != target_id
    assert conn.execute("SELECT original_finding_id FROM findings WHERE id = ?", (f["id"],)).fetchone()[0] == fid
    assert repo.list_sections(conn, new_id)[0]["kind"] == "retest_summary"
    # the original is untouched
    assert len(repo.list_findings(conn, report_id)) == 1 and repo.get_report(conn, report_id)["retest_of"] is None

    page = client.get(f"/reports/{new_id}").get_data(as_text=True)
    assert "This is a retest of" in page and ">Retest</th>" in page
    conn.close()


def test_retest_result_on_finding_history_and_exports(client, csrf, make_report, make_finding):
    report_id = make_report(language="pl")
    fid = make_finding(report_id, title="SQLi")
    new_id = int(client.post(f"/reports/{report_id}/retest", data={"_csrf": csrf}).headers["Location"]
                 .rsplit("/", 1)[1])
    conn = db(client)
    f = repo.list_findings(conn, new_id)[0]
    form = {"_csrf": csrf, "title": "SQLi", "severity": "critical", "status": "fixed", "retest_result": "fixed",
            "retest_date": "2026-11-20", "retest_notes": "Parametrised queries in place."}
    assert client.post(f"/findings/{f['id']}/edit", data=form).status_code == 302
    history = repo.list_history(conn, f["id"])
    assert any(h["description"] == "Retest: Usunięta" and h["date"] == "2026-11-20" for h in history)
    # saving again with the same result does not add another entry
    client.post(f"/findings/{f['id']}/edit", data=form)
    assert sum(h["description"].startswith("Retest") for h in repo.list_history(conn, f["id"])) == 1

    html = client.get(f"/reports/{new_id}/export/html").get_data(as_text=True)
    for text in ("Podsumowanie retestu", "Raport pierwotny", "Wynik retestu", "Usunięta", "2026-11-20",
                 "Parametrised queries in place."):
        assert text in html, text
    md = client.get(f"/reports/{new_id}/export/md").get_data(as_text=True)
    assert "| Usunięta | 2026-11-20 |" in md and "**Retest:** Usunięta (2026-11-20)" in md
    doc = json.loads(client.get(f"/reports/{new_id}/export/json").data)
    assert doc["findings"][0]["retest_result"] == "fixed"
    assert fid != f["id"]
    conn.close()


def test_retest_validation_and_duplicate(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    bad = {"_csrf": csrf, "title": "x", "severity": "low", "retest_result": "maybe"}
    assert client.post(f"/findings/{fid}/edit", data=bad).status_code == 422
    bad = {"_csrf": csrf, "title": "x", "severity": "low", "retest_date": "2026-02-31"}
    assert client.post(f"/findings/{fid}/edit", data=bad).status_code == 422

    resp = client.post(f"/reports/{report_id}/duplicate", data={"_csrf": csrf})
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = db(client)
    assert repo.get_report(conn, new_id)["retest_of"] is None
    assert all(s["kind"] != "retest_summary" for s in repo.list_sections(conn, new_id))
    assert client.post(f"/reports/{report_id}/retest").status_code == 400
    assert client.post("/reports/9999/retest", data={"_csrf": csrf}).status_code == 404
    conn.close()


def test_retest_summary_section_can_be_added_and_removed(client, csrf, make_report):
    report_id = make_report()
    assert client.post(f"/reports/{report_id}/sections", data={"_csrf": csrf, "kind": "retest_summary",
                                                               "level": "1"}).status_code == 302
    conn = db(client)
    sec = [s for s in repo.list_sections(conn, report_id) if s["kind"] == "retest_summary"][0]
    assert "Retest summary" in client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert client.post(f"/sections/{sec['id']}/delete", data={"_csrf": csrf}).status_code == 302
    conn.close()


# -------------------------------------------------------------- scanner import --

def scan_upload(client, csrf, report_id, name="burp.xml", **fields):
    data = {"_csrf": csrf, "file": (BytesIO((FIXTURES / name).read_bytes()), name), **fields}
    return client.post(f"/reports/{report_id}/scan-import", data=data, content_type="multipart/form-data")


def test_scan_import_review_and_apply(client, csrf, make_report, make_target):
    report_id = make_report()
    existing = make_target(report_id, name="Shop", address="https://shop.example.com")
    resp = scan_upload(client, csrf, report_id)
    assert resp.status_code == 302
    import_id = int(resp.headers["Location"].rsplit("/", 1)[1])

    page = client.get(f"/scan-imports/{import_id}").get_data(as_text=True)
    assert "Cross-site scripting (reflected)" in page and "already in report" in page
    assert "informational" in page  # the importer's note is shown

    resp = client.post(f"/scan-imports/{import_id}", data={"_csrf": csrf, "finding": "f1"})
    assert resp.status_code == 302
    conn = db(client)
    findings = repo.list_findings(conn, report_id)
    assert [f["title"] for f in findings] == ["Cross-site scripting (reflected)"]
    f = findings[0]
    assert {t["address"] for t in f["targets"]} == {"https://shop.example.com", "https://admin.example.com"}
    assert existing in {t["id"] for t in f["targets"]}  # reused, not duplicated
    assert len(repo.list_targets(conn, report_id)) == 2
    assert f["evidence"] and all(e["source"] == "import" for e in f["evidence"])
    assert f["status"] == "open" and "Imported from Burp Suite (burp.xml)" in f["history"][0]["description"]
    # applied imports are gone
    assert client.get(f"/scan-imports/{import_id}").status_code == 404
    conn.close()


def test_scan_import_nothing_selected_discard_and_errors(client, csrf, make_report):
    report_id = make_report()
    import_id = int(scan_upload(client, csrf, report_id, "nmap.xml").headers["Location"].rsplit("/", 1)[1])
    resp = client.post(f"/scan-imports/{import_id}", data={"_csrf": csrf})
    assert resp.status_code == 302 and resp.headers["Location"].endswith(f"/scan-imports/{import_id}")
    assert client.post(f"/scan-imports/{import_id}", data={"_csrf": csrf, "discard": "1"}).status_code == 302
    assert client.get(f"/scan-imports/{import_id}").status_code == 404

    for name in ("xxe.xml", "billion_laughs.xml", "not_xml.txt", "wrong_root.xml"):
        assert scan_upload(client, csrf, report_id, name).status_code == 422, name
    assert scan_upload(client, csrf, report_id, "burp.xml", format="nessus").status_code == 422
    assert scan_upload(client, csrf, report_id, "burp.xml", format="word").status_code == 422
    resp = client.post(f"/reports/{report_id}/scan-import", data={"_csrf": csrf}, content_type="multipart/form-data")
    assert resp.status_code == 422
    resp = client.post(f"/reports/{report_id}/scan-import",
                       data={"file": (BytesIO((FIXTURES / "burp.xml").read_bytes()), "b.xml")},
                       content_type="multipart/form-data")
    assert resp.status_code == 400
    assert client.get("/scan-imports/9999").status_code == 404


def test_scan_import_formats_end_to_end(client, csrf, make_report):
    for name in ("nessus.nessus", "zap.xml", "openvas.xml"):
        report_id = make_report(title=name)
        resp = scan_upload(client, csrf, report_id, name, include_info="1")
        assert resp.status_code == 302, name
        import_id = int(resp.headers["Location"].rsplit("/", 1)[1])
        page = client.get(f"/scan-imports/{import_id}").get_data(as_text=True)
        keys = re.findall(r'name="finding" value="([^"]+)"', page)
        assert keys, name
        client.post(f"/scan-imports/{import_id}", data={"_csrf": csrf, "finding": keys})
        conn = db(client)
        assert len(repo.list_findings(conn, report_id)) == len(keys), name
        conn.close()
        # the report with imported findings exports fine
        assert client.get(f"/reports/{report_id}/export/html").status_code == 200


# ---------------------------------------------------------------------- tables --

def test_pipe_tables_in_rich_text():
    body = "Intro\n\n| Port | Service |\n|---|:---:|\n| 22 | ssh |\n| 443 | https \\| tls |\n\nAfter"
    kinds = [k for k, _ in text_blocks(body)]
    assert kinds == ["para", "table", "para"]
    table = text_blocks(body)[1][1]
    assert table["header"] == ["Port", "Service"] and table["rows"][1][0] == "443"
    html = str(richtext(body + "\n\n| <b>x</b> |\n|---|\n| `code` |"))
    assert '<table class="tbl rt-table">' in html and "<th>Port</th>" in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html and "<code>code</code>" in html
    # a lone pipe line without a separator stays text
    assert [k for k, _ in text_blocks("| not a table |")] == ["para"]


def test_pipe_table_latex_escapes_cells():
    from ptreport import latex

    out = str(latex.make_env(latex.Build()).filters["richtext"]("| A & B | 100% |\n|---|---|\n| $x_1$ | #1 |"))
    assert "longtable" in out and r"A \& B" in out and r"100\%" in out and r"\#1" in out
