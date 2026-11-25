import json
from io import BytesIO

import pytest

from ptreport import export, latex, repo
from ptreport.db import connect
from ptreport.rendering import richtext, text_blocks


def db(client):
    return connect(client.application.config["DATABASE"])


# ---------------------------------------------------------------- rich text --

def test_text_blocks_headings_lists_and_paragraphs():
    blocks = text_blocks("Intro line\nsecond\n\n## Scope\n\n- **A** – one\n\n- two\n  wrapped\n\n### Deeper\nText")
    assert blocks == [
        ("para", ["Intro line", "second"]),
        ("heading", (2, "Scope")),
        ("list", ["**A** – one", "two wrapped"]),
        ("heading", (3, "Deeper")),
        ("para", ["Text"]),
    ]


def test_richtext_html_is_escaped_and_formatted():
    html = str(richtext("## Head <b>\n\n- **bold** <i>\n\nSee https://example.com/x. and `<code>`"))
    assert '<h3 class="rt-h">Head &lt;b&gt;</h3>' in html
    assert "<li><strong>bold</strong> &lt;i&gt;</li>" in html
    assert '<a href="https://example.com/x" rel="noopener noreferrer">https://example.com/x</a>.' in html
    assert "<code>&lt;code&gt;</code>" in html


def test_latex_headings_follow_section_numbering():
    ctx = latex.sample_context()
    ctx["report"]["executive_summary"] = "## Sub\n\n### Subsub\n\n- **x** – y"
    source, _ = latex.render(ctx)
    assert "\\subsection{Sub}" in source and "\\subsubsection{Subsub}" in source
    assert "\\item \\textbf{x} – y" in source
    # the unnumbered "Appendix" section of the sample keeps its headings unnumbered
    assert "\\subsection*{Notes}\\addcontentsline{toc}{subsection}{Notes}" in source


# ---------------------------------------------------------------- structure --

def test_default_structure_and_editing(client, csrf, make_report):
    report_id = make_report()
    conn = db(client)
    kinds = [s["kind"] for s in repo.list_sections(conn, report_id)]
    assert kinds == ["executive_summary", "scope", "methodology", "summary", "findings"]

    resp = client.post(f"/reports/{report_id}/sections", data={
        "_csrf": csrf, "kind": "text", "title": "Future directions", "level": "1", "body": "## Plugins\n\nCheck them."})
    assert resp.status_code == 302
    custom = repo.list_sections(conn, report_id)[-1]
    assert custom["title"] == "Future directions" and custom["kind"] == "text"

    # move it to the top, rename, make it unnumbered on a new page
    for _ in range(5):
        client.post(f"/sections/{custom['id']}/move", data={"_csrf": csrf, "direction": "up"})
    assert repo.list_sections(conn, report_id)[0]["id"] == custom["id"]
    resp = client.post(f"/sections/{custom['id']}/edit", data={
        "_csrf": csrf, "title": "Outlook", "level": "2", "body": "Text", "enabled": ["0", "1"],
        "numbered": "0", "new_page": ["0", "1"]})
    assert resp.status_code == 302
    sec = repo.get_section(conn, custom["id"])
    assert (sec["title"], sec["level"], sec["numbered"], sec["new_page"], sec["enabled"]) == ("Outlook", 2, 0, 1, 1)

    # switch the methodology off; built-ins cannot be deleted, custom sections can
    methodology = [s for s in repo.list_sections(conn, report_id) if s["kind"] == "methodology"][0]
    client.post(f"/sections/{methodology['id']}/edit", data={"_csrf": csrf, "title": "", "enabled": "0"})
    with client.application.app_context():
        ctx = export.build_context(conn, report_id)
    assert "methodology" not in [s["kind"] for s in ctx["sections"]]
    assert client.post(f"/sections/{methodology['id']}/delete", data={"_csrf": csrf}).status_code == 400
    assert client.post(f"/sections/{custom['id']}/delete", data={"_csrf": csrf}).status_code == 302

    bad = client.post(f"/reports/{report_id}/sections", data={"_csrf": csrf, "kind": "findings"})
    assert bad.status_code == 400  # only text/charts/tables can be added
    assert client.post(f"/reports/{report_id}/sections", data={"kind": "text", "title": "x"}).status_code == 400
    conn.close()


def test_structure_drives_html_markdown_and_latex(client, csrf, make_report, make_finding):
    report_id = make_report(executive_summary="Summary text")
    make_finding(report_id)
    client.post(f"/reports/{report_id}/sections", data={"_csrf": csrf, "kind": "charts", "title": ""})
    client.post(f"/reports/{report_id}/sections", data={"_csrf": csrf, "kind": "text", "title": "CWE License",
                                                       "body": "MITRE text"})
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Results summary" in html and "CWE License" in html and "MITRE text" in html
    assert html.index("Executive summary") < html.index("CWE License")
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "## 6 Results summary" in md and "## 7 CWE License" in md
    conn = db(client)
    with client.application.app_context():
        ctx = export.build_context(conn, report_id, inline_images=True)
    conn.close()
    source, _ = latex.render(ctx)
    assert "\\section{Results summary}" in source and "\\section{CWE License}" in source
    assert len(ctx["fingerprint"]) == 64


# ---------------------------------------------------------------- CWE groups --

def test_cwe_groups(client, csrf, make_report, make_finding):
    report_id = make_report(group_by_cwe="1")
    a = make_finding(report_id, title="XSS one", cwe="79")
    make_finding(report_id, title="SQLi", cwe="89")
    make_finding(report_id, title="XSS two", cwe="79")
    make_finding(report_id, title="Note", cwe="", cvss_version="", cvss_vector="", severity="info")
    conn = db(client)
    assert repo.get_report(conn, report_id)["group_by_cwe"] == 1

    resp = client.post(f"/reports/{report_id}/cwe-groups", data={
        "_csrf": csrf, "cwe": "CWE-79", "title": "", "description": "XSS intro", "mitigation": "Encode output"})
    assert resp.status_code == 302
    client.post(f"/reports/{report_id}/cwe-groups", data={"_csrf": csrf, "cwe": "", "title": "Informative note",
                                                         "description": "", "mitigation": "General notes"})
    client.post(f"/reports/{report_id}/cwe-groups/move", data={"_csrf": csrf, "cwe": "CWE-89", "direction": "up"})
    with client.application.app_context():
        ctx = export.build_context(conn, report_id, inline_images=True)
    titles = [g["title"] for g in ctx["groups"]]
    assert titles[0].startswith("CWE-89") and titles[1].startswith("CWE-79") and titles[-1] == "Informative note"
    xss = ctx["groups"][1]
    assert [f["title"] for f in xss["findings"]] == ["XSS one", "XSS two"]
    assert (xss["description"], xss["mitigation"]) == ("XSS intro", "Encode output")

    source, _ = latex.render(ctx)
    assert "\\subsection{CWE-79: " in source and "\\subsubsection{Mitigation}" in source
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "XSS intro" in html and "Encode output" in html

    # round trip keeps structure, grouping and notes
    exported = client.get(f"/reports/{report_id}/export/json").get_data()
    doc = json.loads(exported)
    assert any(n["cwe"] == "CWE-79" for n in doc["cwe_notes"])
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(exported), "r.json")},
                       content_type="multipart/form-data")
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    assert repo.get_report(conn, new_id)["group_by_cwe"] == 1
    assert repo.list_cwe_notes(conn, new_id)["CWE-79"]["mitigation"] == "Encode output"
    assert [s["kind"] for s in repo.list_sections(conn, new_id)] == [s["kind"] for s in doc["sections"]]

    assert client.post(f"/reports/{report_id}/cwe-groups", data={"_csrf": csrf, "cwe": "XSS"}).status_code == 302
    assert "XSS" not in repo.list_cwe_notes(conn, report_id)
    assert client.post(f"/reports/{report_id}/cwe-groups/move",
                       data={"_csrf": csrf, "cwe": "nope", "direction": "up"}).status_code == 400
    conn.close()
    del a


# ------------------------------------------------------------------- labels --

def test_label_overrides(client, csrf, make_report, make_finding):
    resp = client.post("/settings/labels", data={
        "_csrf": csrf, "en:status.open": "New", "en:status.risk_accepted": "Won't fix", "en:sev.info": "Info",
        "pl:status.open": "Nowa", "en:table_of_findings": "Findings at a glance", "en:bogus": "x", "de:sev.high": "x"})
    assert resp.status_code == 302
    conn = db(client)
    overrides = repo.get_label_overrides(conn)
    assert overrides["en"] == {"status.open": "New", "status.risk_accepted": "Won't fix", "sev.info": "Info",
                               "table_of_findings": "Findings at a glance"}
    assert overrides["pl"] == {"status.open": "Nowa"}

    report_id = make_report()
    make_finding(report_id)
    client.post(f"/reports/{report_id}/sections", data={"_csrf": csrf, "kind": "findings_table", "title": ""})
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "<td>New</td>" in html and "Findings at a glance" in html

    long = client.post("/settings/labels", data={"_csrf": csrf, "en:sev.high": "x" * 81})
    assert long.status_code == 302
    assert repo.get_label_overrides(conn)["en"].get("sev.high") is None
    conn.close()


# ------------------------------------------------------------------ preview --

def test_preview_is_the_pdf(client, make_report, monkeypatch):
    report_id = make_report()
    monkeypatch.setattr(latex, "compile_pdf", lambda source, files, timeout=0, volatile="": b"%PDF-1.7 x")
    resp = client.get(f"/reports/{report_id}/preview")
    assert resp.mimetype == "application/pdf" and resp.headers["Content-Disposition"].startswith("inline")
    assert "frame-ancestors 'self'" in resp.headers["Content-Security-Policy"]


@pytest.mark.skipif(latex.find_engine() is None, reason="no LaTeX engine installed")
def test_real_pdf_with_structure_groups_and_charts(client, csrf, make_report, make_finding, make_target):
    report_id = make_report(group_by_cwe="1", methodology="## Classes\n\n- **INFO** – none")
    target = make_target(report_id)
    make_finding(report_id, cwe="79", target_ids=[str(target)])
    make_finding(report_id, cwe="", cvss_version="", cvss_vector="", severity="low", status="risk_accepted")
    for kind in ("charts", "findings_table", "text"):
        client.post(f"/reports/{report_id}/sections", data={"_csrf": csrf, "kind": kind, "title": "Extra & 100%",
                                                           "body": "## A\n\nB"})
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 200, resp.get_data(as_text=True)[-2000:]


def test_preview_dialog_markup(client, make_report):
    report_id = make_report()
    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert 'id="pdf-dialog"' in page and "data-pdf-preview" in page and "/static/preview.js" in page
    assert "frame-src blob:" in client.get(f"/reports/{report_id}").headers["Content-Security-Policy"]


def test_pdf_cache_reuses_unchanged_reports(monkeypatch):
    calls = []

    def fake(source, files, timeout, engine):
        calls.append(source)
        return b"%PDF-" + str(len(calls)).encode()

    monkeypatch.setattr(latex, "find_engine", lambda: ("tectonic", "/x/tectonic"))
    monkeypatch.setattr(latex, "_compile_pdf", fake)
    latex._PDF_CACHE.clear()
    first = latex.compile_pdf("doc 12:00", {"a.png": b"1"}, volatile="12:00")
    again = latex.compile_pdf("doc 12:05", {"a.png": b"1"}, volatile="12:05")  # only the time changed
    changed = latex.compile_pdf("doc changed 12:05", {"a.png": b"1"}, volatile="12:05")
    image = latex.compile_pdf("doc 12:05", {"a.png": b"2"}, volatile="12:05")
    assert first == again and len(calls) == 3 and changed != first and image != first
    latex._PDF_CACHE.clear()
