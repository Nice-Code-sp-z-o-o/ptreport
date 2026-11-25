import io
import re
import zipfile
from io import BytesIO

import pytest

from ptreport import latex, repo
from ptreport.db import connect

NASTY = r"\input{/etc/passwd} \write18{id} $x$ & 100% #1 _a ^b ~c {d} <e> \"f\" \end{Verbatim}"


def db(client):
    return connect(client.application.config["DATABASE"])


# ------------------------------------------------------------------ escaping --

def test_escape_tex_neutralises_every_special_character():
    out = latex.escape_tex(NASTY)
    assert "\\input{" not in out and "\\write18{" not in out
    stripped = re.sub(r"\\text[a-z]+\{\}|\\[&%$#_{}]", "", out)
    assert not re.search(r"[\\&%$#_{}^~]", stripped), stripped
    assert r"\textbackslash{}input\{/etc/passwd\}" in out


def test_template_output_is_escaped_and_verbatim_goes_to_files():
    ctx = latex.sample_context()
    f = ctx["findings"][0]
    f["title"] = NASTY
    f["description"] = NASTY + "\n```\n" + NASTY + "\n```"
    f["evidence"][0]["request"] = NASTY
    source, files = latex.render(ctx)
    assert "\\input{/etc/passwd}" not in source and "\\write18{id}" not in source
    assert "\\end{Verbatim}" not in source
    # raw text survives untouched in the verbatim input files only
    assert any(NASTY.encode() in data for data in files.values())
    assert all(name.startswith("assets/") for name in files)


def test_urls_become_links_only_when_safe():
    ctx = latex.sample_context()
    ctx["findings"][0]["refs"] = "https://example.com/a?b=1#frag\njavascript:alert(1)\nhttps://x.test/{bad}"
    source, _ = latex.render(ctx)
    assert r"\href{https://example.com/a?b=1\#frag}" in source
    assert "\\href{javascript" not in source and "\\href{https://x.test/{bad}" not in source


@pytest.mark.parametrize("template,problem", [
    ("no document class \\VAR{report.title}", "documentclass"),
    ("\\documentclass{article}\\begin{document}\\VAR{report.title\\end{document}", "Template error"),
    ("\\documentclass{article}\\begin{document}\\VAR{report.nope}\\end{document}", "Template error"),
    ("\\documentclass{article}\\begin{document}\\VAR{report.__class__.__mro__}\\end{document}", "Template error"),
    ("\\documentclass{article}\\begin{document}\\VAR{''.__class__.__mro__[1].__subclasses__()}\\end{document}",
     "Template error"),
])
def test_template_problems(template, problem):
    assert problem in latex.template_problem(template, latex.sample_context())


def test_valid_custom_template():
    tpl = "\\documentclass{article}\\begin{document}\\VAR{report.title} \\VAR{findings|length}\\end{document}"
    assert latex.template_problem(tpl, latex.sample_context()) is None
    source, _ = latex.render(latex.sample_context(), tpl)
    assert "Sample report 1" in source


# --------------------------------------------------------------- web export --

def test_pdf_and_tex_exports(client, make_report, make_finding, monkeypatch):
    report_id = make_report(title="My Report")
    make_finding(report_id, title=NASTY)
    seen = {}

    def fake_compile(source, files, timeout=0, volatile=""):
        seen["source"] = source
        return b"%PDF-1.7 fake"

    monkeypatch.setattr(latex, "compile_pdf", fake_compile)
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 200 and resp.mimetype == "application/pdf"
    assert 'filename="My_Report.pdf"' in resp.headers["Content-Disposition"]
    assert "\\write18{id}" not in seen["source"]

    preview = client.get(f"/reports/{report_id}/preview")
    assert preview.mimetype == "application/pdf"
    assert preview.headers["Content-Disposition"].startswith("inline;")

    resp = client.get(f"/reports/{report_id}/export/tex")
    assert resp.mimetype == "application/zip"
    names = zipfile.ZipFile(io.BytesIO(resp.data)).namelist()
    assert "report.tex" in names and "README.txt" in names


def test_pdf_export_error_page(client, make_report, monkeypatch):
    report_id = make_report()

    def broken(source, files, timeout=0, volatile=""):
        raise latex.LatexError("LaTeX compilation failed.", "! Undefined control sequence.")

    monkeypatch.setattr(latex, "compile_pdf", broken)
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 500
    assert "Undefined control sequence" in resp.get_data(as_text=True)


@pytest.mark.skipif(latex.find_engine() is None, reason="no LaTeX engine installed")
def test_real_pdf_compilation(client, csrf, make_report, make_finding):
    from tests.test_screenshots_versions_meta import png_bytes, upload
    report_id = make_report(language="pl")
    fid = make_finding(report_id, title=NASTY, description=NASTY, poc="```\n" + NASTY + "\n```")
    client.post(f"/findings/{fid}/evidence", data={"_csrf": csrf, "request": NASTY, "response": NASTY})
    upload(client, csrf, fid, png_bytes(), caption=NASTY)
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 200, resp.get_data(as_text=True)[-2000:]
    assert resp.data.startswith(b"%PDF")


def test_template_settings_flow(client, csrf):
    assert b"\\documentclass" in client.get("/settings/latex-template/default").data
    good = b"\\documentclass{article}\\begin{document}Custom \\VAR{report.title}\\end{document}"
    resp = client.post("/settings/latex-template", data={"_csrf": csrf, "file": (BytesIO(good), "t.tex")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    assert b"Custom" in client.get("/settings/latex-template/current").data
    assert "custom template" in client.get("/settings").get_data(as_text=True).lower()

    bad = b"\\documentclass{article}\\begin{document}\\VAR{report.__class__}\\end{document}"
    client.post("/settings/latex-template", data={"_csrf": csrf, "file": (BytesIO(bad), "t.tex")},
                content_type="multipart/form-data")
    assert b"Custom" in client.get("/settings/latex-template/current").data  # bad upload did not replace it

    assert client.post("/settings/latex-template/reset", data={"_csrf": csrf}).status_code == 302
    conn = db(client)
    assert repo.get_latex_template(conn) is None
    conn.close()
    assert client.post("/settings/latex-template/reset").status_code == 400  # CSRF


# ----------------------------------------------------------------- changelog --

def test_status_change_is_recorded_and_manual_entries(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    client.post(f"/findings/{fid}/edit", data={
        "_csrf": csrf, "title": "SQL injection", "severity": "critical", "status": "fixed"})
    conn = db(client)
    entry = repo.list_history(conn, fid)[0]
    assert (entry["kind"], entry["status_from"], entry["status_to"]) == ("status", "open", "fixed")

    resp = client.post(f"/findings/{fid}/history", data={
        "_csrf": csrf, "date": "2026-11-20", "author": "Anna Nowak", "description": "Retest: fixed"})
    assert resp.status_code == 302
    bad = client.post(f"/findings/{fid}/history", data={"_csrf": csrf, "date": "", "author": "R2D2",
                                                         "description": ""})
    assert bad.status_code == 422
    note = [h for h in repo.list_history(conn, fid) if h["kind"] == "note"][0]
    assert client.post(f"/history/{note['id']}/edit", data={
        "_csrf": csrf, "date": "2026-11-21", "author": "Anna Nowak", "description": "Retest 2: fixed"}
    ).status_code == 302
    assert repo.get_history_entry(conn, note["id"])["description"] == "Retest 2: fixed"

    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Status: Open → Fixed" in html and "Retest 2: fixed" in html and "Anna Nowak" in html

    assert client.post(f"/history/{note['id']}/delete", data={"_csrf": csrf}).status_code == 302
    assert len(repo.list_history(conn, fid)) == 1
    conn.close()


def test_version_author_edit_and_export_switches(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    client.post(f"/findings/{fid}/history", data={"_csrf": csrf, "date": "2026-11-20", "description": "Note X"})
    client.post(f"/reports/{report_id}/versions", data={"_csrf": csrf, "version": "1.0", "author": "Jan Kowalski",
                                                       "description": "Final"})
    conn = db(client)
    version = repo.list_report_versions(conn, report_id)[0]
    assert version["author"] == "Jan Kowalski"
    assert client.post(f"/report-versions/{version['id']}/edit", data={
        "_csrf": csrf, "version": "1.1", "date": "2026-11-25", "author": "Anna Nowak", "description": "Retest"}
    ).status_code == 302
    assert repo.get_report_version(conn, version["id"])["version"] == "1.1"

    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Anna Nowak" in html and "Note X" in html

    # switch both off (hidden "0" only, as the form sends with unticked boxes)
    resp = client.post(f"/reports/{report_id}/edit", data={
        "_csrf": csrf, "title": "Test report", "finding_prefix": "ACME", "language": "en",
        "show_version_history": "0", "show_finding_history": "0"})
    assert resp.status_code == 302
    assert repo.get_report(conn, report_id)["show_version_history"] == 0
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Anna Nowak" not in html and "Note X" not in html
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "Note X" not in md
    # JSON keeps everything for backups, and the import restores it
    exported = client.get(f"/reports/{report_id}/export/json").get_data()
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(exported), "r.json")},
                       content_type="multipart/form-data")
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    assert repo.list_report_versions(conn, new_id)[0]["author"] == "Anna Nowak"
    assert repo.list_findings(conn, new_id)[0]["history"][0]["description"] == "Note X"
    assert repo.get_report(conn, new_id)["show_finding_history"] == 0
    conn.close()


# ----------------------------------------------------------------- branding --

def test_branding_settings_and_exports(client, csrf, make_report, make_finding):
    from tests.test_screenshots_versions_meta import png_bytes
    bad = client.post("/settings/branding", data={"_csrf": csrf, "brand_color": "red"})
    assert bad.status_code == 302
    conn = db(client)
    assert repo.get_brand(conn)["color"] == "1D3557"  # unchanged default

    resp = client.post("/settings/branding", data={"_csrf": csrf, "brand_color": "#a1b2c3",
                                                  "logo": (BytesIO(png_bytes()), "logo.png")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    brand = repo.get_brand(conn)
    assert brand["color"] == "A1B2C3" and brand["logo"]["mime"] == "image/png"
    assert client.get("/brand.css").get_data(as_text=True).strip() == ":root { --brand: #A1B2C3; }"
    assert client.get("/settings/branding/logo").mimetype == "image/png"

    svg = b"<svg xmlns='http://www.w3.org/2000/svg'/>"
    client.post("/settings/branding", data={"_csrf": csrf, "brand_color": "#A1B2C3",
                                           "logo": (BytesIO(svg), "logo.svg")}, content_type="multipart/form-data")
    assert repo.get_brand(conn)["logo"]["mime"] == "image/png"  # rejected, old logo kept

    report_id = make_report(classification="TLP:AMBER")
    make_finding(report_id)
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "--brand: #A1B2C3" in html and "TLP:AMBER" in html and 'class="cover-logo"' in html

    from ptreport import export
    with client.application.app_context():
        ctx = export.build_context(conn, report_id, inline_images=True)
    source, files = latex.render(ctx)
    assert "\\def\\ptClassification{TLP:AMBER}" in source and "{A1B2C3}" in source
    assert any(name.startswith("assets/logo-") for name in files)

    assert client.post("/settings/branding/logo/delete", data={"_csrf": csrf}).status_code == 302
    assert repo.get_brand(conn)["logo"] is None
    assert client.get("/settings/branding/logo").status_code == 404
    assert client.post("/settings/branding", data={"brand_color": "#000000"}).status_code == 400  # CSRF
    conn.close()


@pytest.mark.skipif(latex.find_engine() is None, reason="no LaTeX engine installed")
def test_real_pdf_with_branding(client, csrf, make_report, make_finding):
    from tests.test_screenshots_versions_meta import png_bytes
    client.post("/settings/branding", data={"_csrf": csrf, "brand_color": "#7A1F3D",
                                           "logo": (BytesIO(png_bytes()), "logo.png")},
                content_type="multipart/form-data")
    report_id = make_report(classification="CONFIDENTIAL & internal_use 100%")
    make_finding(report_id)
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 200, resp.get_data(as_text=True)[-2000:]
    assert resp.data.startswith(b"%PDF")
