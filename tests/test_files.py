"""Evidence files of any type per finding: upload, limits, safe download, exports, JSON round trip, clone, API."""

import base64
import hashlib
import json
from io import BytesIO

import pytest

from ptreport import export, latex, repo
from ptreport.db import connect
from ptreport.validation import sanitize_filename

PCAP = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + bytes(range(256)) * 4
LOG = b"2026-11-20 10:00:01 POST /login 200\n2026-11-20 10:00:02 POST /login 401\n"


def db(client):
    return connect(client.application.config["DATABASE"])


def upload(client, csrf, finding_id, files, description="", with_csrf=True):
    data = {"description": description, "files": [(BytesIO(body), name) for name, body in files]}
    if with_csrf:
        data["_csrf"] = csrf
    return client.post(f"/findings/{finding_id}/files", data=data, content_type="multipart/form-data")


@pytest.fixture()
def finding(make_report, make_finding):
    report_id = make_report()
    return report_id, make_finding(report_id)


# ------------------------------------------------------------------ upload --

def test_upload_several_files_with_server_side_hash(client, csrf, finding):
    report_id, fid = finding
    resp = upload(client, csrf, fid, [("capture.pcap", PCAP), ("app.log", LOG)], description="Login traffic")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("#files")
    conn = db(client)
    files = repo.list_files(conn, fid)
    conn.close()
    assert [f["filename"] for f in files] == ["capture.pcap", "app.log"]
    assert [f["position"] for f in files] == [1, 2]
    assert files[0]["sha256"] == hashlib.sha256(PCAP).hexdigest()
    assert files[1]["sha256"] == hashlib.sha256(LOG).hexdigest()
    assert (files[0]["size"], files[0]["mime"]) == (len(PCAP), "application/vnd.tcpdump.pcap")
    assert files[1]["mime"] == "text/plain" and files[1]["description"] == "Login traffic"
    assert files[0]["uploaded_at"]

    page = client.get(f"/findings/{fid}/edit").get_data(as_text=True)
    assert 'id="files"' in page and "capture.pcap" in page and "app.log" in page
    assert files[0]["sha256"][:12] + "…" in page                       # short hash ...
    assert f'title="SHA-256: {files[0]["sha256"]}"' in page            # ... full one in the title
    assert f'data-copy-text="{files[0]["sha256"]}"' in page
    assert "#i-file-capture" in page and "#i-file-text" in page
    assert "1.0 KB" in page


def test_client_content_type_is_ignored(client, csrf, finding):
    _, fid = finding
    data = {"_csrf": csrf, "files": [(BytesIO(b"<script>alert(1)</script>"), "notes.txt", "text/html")]}
    assert client.post(f"/findings/{fid}/files", data=data, content_type="multipart/form-data").status_code == 302
    conn = db(client)
    assert repo.list_files(conn, fid)[0]["mime"] == "text/plain"
    conn.close()


def test_rejects_empty_oversized_and_bad_names(client, csrf, finding, monkeypatch):
    import ptreport.validation as validation
    _, fid = finding
    resp = upload(client, csrf, fid, [("empty.log", b"")])
    assert resp.status_code == 422 and "empty.log: the file is empty." in resp.get_data(as_text=True)
    for bad in ("../..", "..", "/", "\x00\x01"):
        resp = upload(client, csrf, fid, [(bad, b"data")])
        assert resp.status_code == 422, bad
    assert upload(client, csrf, fid, [], description="x").status_code == 422
    monkeypatch.setattr(validation, "FILE_MAX_BYTES", 10)
    resp = upload(client, csrf, fid, [("big.bin", b"x" * 11)])
    assert resp.status_code == 422 and "at most" in resp.get_data(as_text=True)
    assert upload(client, csrf, fid, [("ok.bin", b"x" * 10)]).status_code == 302
    # a batch is all or nothing: one bad file rejects the others
    assert upload(client, csrf, fid, [("fine.txt", b"fine"), ("bad.txt", b"")]).status_code == 422
    conn = db(client)
    assert [f["filename"] for f in repo.list_files(conn, fid)] == ["ok.bin"]
    conn.close()


def test_description_validated(client, csrf, finding):
    _, fid = finding
    assert upload(client, csrf, fid, [("a.txt", b"a")], description="x" * 301).status_code == 422
    assert upload(client, csrf, fid, [("a.txt", b"a")], description="line\nbreak").status_code == 422


def test_per_finding_total_and_count_limits(client, csrf, finding, monkeypatch):
    import ptreport.validation as validation
    _, fid = finding
    monkeypatch.setattr(validation, "FILE_MAX_TOTAL_PER_FINDING", 100)
    assert upload(client, csrf, fid, [("a.bin", b"a" * 60)]).status_code == 302
    resp = upload(client, csrf, fid, [("b.bin", b"b" * 41)])
    assert resp.status_code == 422 and "in total" in resp.get_data(as_text=True)
    assert upload(client, csrf, fid, [("b.bin", b"b" * 40)]).status_code == 302
    monkeypatch.setattr(validation, "FILE_MAX_PER_FINDING", 3)
    resp = upload(client, csrf, fid, [("c.txt", b"c"), ("d.txt", b"d")])
    assert resp.status_code == 422 and "at most 3 files" in resp.get_data(as_text=True)


@pytest.mark.parametrize("raw, expected", [
    ("../../etc/passwd.txt", "passwd.txt"),
    ("C:\\Users\\me\\evil.html", "evil.html"),
    ("invoice\u202egpj.exe", "invoicegpj.exe"),     # right-to-left override removed
    ("  .hidden.log. ", "hidden.log"),
    ('a<b>:c"d|e?f*.txt', "a_b__c_d_e_f_.txt"),
    ("con.txt", "_con.txt"),
    ("tab\there.txt", "tabhere.txt"),
    ("zażółć gęślą.txt", "zażółć gęślą.txt"),
    ("...", ""), ("../", ""), ("", ""), (None, ""), ("\x00\x1f", ""),
])
def test_sanitize_filename(raw, expected):
    assert sanitize_filename(raw) == expected


def test_sanitize_filename_length_cap_keeps_extension():
    name = sanitize_filename("a" * 500 + ".pcapng")
    assert len(name) == 180 and name.endswith(".pcapng")


def test_path_parts_stripped_on_upload(client, csrf, finding):
    _, fid = finding
    assert upload(client, csrf, fid, [("../../../tmp/x/out.json", b"{}")]).status_code == 302
    conn = db(client)
    assert repo.list_files(conn, fid)[0]["filename"] == "out.json"
    conn.close()


# ---------------------------------------------------------------- download --

def _only_file(client, fid):
    conn = db(client)
    try:
        return repo.list_files(conn, fid)[-1]
    finally:
        conn.close()


@pytest.mark.parametrize("name", ["page.html", "x.svg", "a.js", "data.xml", "report.pdf", "tool.exe", "noext"])
def test_active_types_download_as_octet_stream(client, csrf, finding, name):
    _, fid = finding
    body = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    assert upload(client, csrf, fid, [(name, body)]).status_code == 302
    resp = client.get(f"/files/{_only_file(client, fid)['id']}")
    assert resp.status_code == 200 and resp.data == body
    assert resp.mimetype == "application/octet-stream"
    assert resp.headers["Content-Disposition"].startswith("attachment;")
    assert f'filename="{name}"' in resp.headers["Content-Disposition"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in resp.headers["Content-Security-Policy"]


def test_safe_types_keep_their_type_but_are_never_inline(client, csrf, finding):
    _, fid = finding
    upload(client, csrf, fid, [("app.log", LOG)])
    f = _only_file(client, fid)
    resp = client.get(f"/files/{f['id']}")
    assert resp.mimetype == "text/plain" and resp.headers["Content-Disposition"].startswith("attachment;")
    assert resp.headers["ETag"] == f'"{f["sha256"]}"'
    digest = base64.b64encode(hashlib.sha256(LOG).digest()).decode()
    assert resp.headers["Repr-Digest"] == f"sha-256=:{digest}:"
    assert client.get("/files/9999").status_code == 404


def test_unicode_name_in_content_disposition(client, csrf, finding):
    _, fid = finding
    upload(client, csrf, fid, [("zrzut sieci łódź.pcap", PCAP)])
    cd = client.get(f"/files/{_only_file(client, fid)['id']}").headers["Content-Disposition"]
    assert 'filename="zrzut sieci __d_.pcap"' in cd
    assert "filename*=UTF-8''zrzut%20sieci%20%C5%82%C3%B3d%C5%BA.pcap" in cd


# --------------------------------------------------- description and delete --

def test_description_edit_and_delete_need_csrf(client, csrf, finding):
    _, fid = finding
    upload(client, csrf, fid, [("app.log", LOG)])
    file_id = _only_file(client, fid)["id"]
    assert client.post(f"/files/{file_id}/description", data={"description": "x"}).status_code == 400
    assert client.post(f"/files/{file_id}/description",
                       data={"_csrf": csrf, "description": "Web server log"}).status_code == 302
    assert _only_file(client, fid)["description"] == "Web server log"

    assert client.post(f"/files/{file_id}/delete", data={}).status_code == 400
    assert client.post(f"/files/{file_id}/delete", data={"_csrf": "wrong"}).status_code == 400
    assert _only_file(client, fid)["id"] == file_id
    assert client.post(f"/files/{file_id}/delete", data={"_csrf": csrf}).status_code == 302
    conn = db(client)
    assert repo.list_files(conn, fid) == []
    conn.close()
    assert client.post(f"/files/{file_id}/delete", data={"_csrf": csrf}).status_code == 404


def test_upload_needs_csrf(client, csrf, finding):
    _, fid = finding
    assert upload(client, csrf, fid, [("app.log", LOG)], with_csrf=False).status_code == 400
    assert upload(client, csrf, 9999, [("app.log", LOG)]).status_code == 404


def test_files_deleted_with_finding(client, csrf, finding):
    _, fid = finding
    upload(client, csrf, fid, [("app.log", LOG)])
    assert client.post(f"/findings/{fid}/delete", data={"_csrf": csrf}).status_code == 302
    conn = db(client)
    assert conn.execute("SELECT COUNT(*) FROM finding_files").fetchone()[0] == 0
    conn.close()


# ------------------------------------------------------------------ exports --

def test_exports_list_attached_files(client, csrf, make_report, make_finding):
    report_id = make_report(language="pl")
    fid = make_finding(report_id)
    upload(client, csrf, fid, [("capture_&_<b>.pcap", PCAP)], description="Ruch <i>logowania</i>")
    sha = hashlib.sha256(PCAP).hexdigest()

    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Załączone pliki" in html and sha in html and "1.0 KB" in html
    assert "capture_&amp;__b_.pcap" in html and "Ruch &lt;i&gt;logowania&lt;/i&gt;" in html

    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "#### Załączone pliki" in md
    assert f"| capture\\_&\\_\\_b\\_.pcap<br>*Ruch \\<i\\>logowania\\</i\\>* | 1.0 KB | `{sha}` |" in md

    conn = db(client)
    ctx = export.build_context(conn, report_id, inline_images=True)
    conn.close()
    source, _ = latex.render(ctx)
    assert r"\ptBlockTitle{Załączone pliki}" in source
    assert r"\texttt{" + sha[:32] + r"}\newline\texttt{" + sha[32:] + "}" in source
    assert r"W{.44}>{\raggedleft\arraybackslash}W{.12}W{.44}" in source
    assert r"capture\_\allowbreak{}\&\_\allowbreak{}\_\allowbreak{}b\_\allowbreak{}.\allowbreak{}pcap" in source


def test_no_files_no_section(client, csrf, make_report, make_finding):
    report_id = make_report()
    make_finding(report_id)
    assert "Attached files" not in client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Attached files" not in client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)


def test_breakable_filter_escapes_every_chunk():
    from ptreport.latex import Build, make_env
    env = make_env(Build())
    out = env.from_string(r"\VAR{name|breakable}").render(name="a_very$long%file{name}\\with#odd&chars.txt")
    assert r"\allowbreak{}" in out
    for raw in ("$", "%", "#", "&"):
        assert ("\\" + raw) in out
    assert "\\textbackslash" in out


@pytest.mark.skipif(latex.find_engine() is None, reason="no LaTeX engine installed")
def test_pdf_with_attached_files_compiles(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    upload(client, csrf, fid, [("a" * 170 + ".pcapng", PCAP), ("evil_$%#&{}~^\\.txt", LOG)], description="x" * 300)
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 200, resp.get_data(as_text=True)[-2000:]
    assert resp.data.startswith(b"%PDF")


# ------------------------------------------------------------ JSON round trip --

def _export_json(client, report_id):
    return json.loads(client.get(f"/reports/{report_id}/export/json").get_data(as_text=True))


def _import(client, csrf, doc):
    payload = json.dumps(doc).encode()
    return client.post("/import", data={"_csrf": csrf, "file": (BytesIO(payload), "r.json")},
                       content_type="multipart/form-data")


def test_json_round_trip_with_hash_check(client, csrf, finding):
    report_id, fid = finding
    upload(client, csrf, fid, [("capture.pcap", PCAP), ("app.log", LOG)], description="Evidence")
    doc = _export_json(client, report_id)
    files = doc["findings"][0]["files"]
    assert [f["filename"] for f in files] == ["capture.pcap", "app.log"]
    assert files[0]["sha256"] == hashlib.sha256(PCAP).hexdigest()
    assert base64.b64decode(files[0]["data_base64"]) == PCAP
    assert set(files[0]) == {"filename", "description", "mime", "size", "sha256", "uploaded_at", "data_base64"}

    resp = _import(client, csrf, doc)
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = db(client)
    new_finding = repo.list_findings(conn, new_id)[0]
    copied = new_finding["files"]
    assert [(f["filename"], f["sha256"], f["size"], f["description"]) for f in copied] == \
        [(f["filename"], f["sha256"], f["size"], f["description"]) for f in files]
    assert copied[0]["uploaded_at"] == files[0]["uploaded_at"]
    assert repo.file_data(conn, [copied[0]["id"]])[copied[0]["id"]] == PCAP
    conn.close()


def test_json_import_rejects_hash_mismatch_and_bad_entries(client, csrf, finding):
    report_id, fid = finding
    upload(client, csrf, fid, [("capture.pcap", PCAP)])
    doc = _export_json(client, report_id)
    conn = db(client)
    before = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    conn.close()

    tampered = json.loads(json.dumps(doc))
    tampered["findings"][0]["files"][0]["data_base64"] = base64.b64encode(PCAP + b"!").decode()
    resp = _import(client, csrf, tampered)
    assert resp.status_code == 422 and "SHA-256 does not match" in resp.get_data(as_text=True)

    for change, message in (
        ({"sha256": "abc"}, "sha256 must be 64"),
        ({"sha256": None}, "sha256 must be 64"),
        ({"data_base64": "***"}, "not valid base64"),
        ({"data_base64": ""}, "the file is empty"),
        ({"filename": "../.."}, "usable name"),
        ({"size": 1}, "size does not match"),
    ):
        bad = json.loads(json.dumps(doc))
        bad["findings"][0]["files"][0].update(change)
        if change.get("data_base64") == "":
            bad["findings"][0]["files"][0]["sha256"] = hashlib.sha256(b"").hexdigest()
        resp = _import(client, csrf, bad)
        assert resp.status_code == 422, change
        assert message in resp.get_data(as_text=True), change
    bad = json.loads(json.dumps(doc))
    bad["findings"][0]["files"] = "nope"
    assert _import(client, csrf, bad).status_code == 422

    conn = db(client)
    assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == before
    conn.close()


def test_json_without_files_still_imports(client, csrf, finding):
    report_id, _ = finding
    doc = _export_json(client, report_id)
    del doc["findings"][0]["files"]
    assert _import(client, csrf, doc).status_code == 302


def test_fingerprint_covers_file_hashes(client, csrf, finding):
    report_id, fid = finding
    conn = db(client)
    before = export.build_context(conn, report_id, inline_images=True)["fingerprint"]
    upload(client, csrf, fid, [("app.log", LOG)])
    after = export.build_context(conn, report_id, inline_images=True)["fingerprint"]
    conn.close()
    assert before != after


# --------------------------------------------------------------------- clone --

@pytest.mark.parametrize("action", ["duplicate", "retest"])
def test_duplicate_and_retest_copy_files(client, csrf, finding, action):
    report_id, fid = finding
    upload(client, csrf, fid, [("capture.pcap", PCAP)], description="Evidence")
    resp = client.post(f"/reports/{report_id}/{action}", data={"_csrf": csrf})
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = db(client)
    original = repo.list_findings(conn, report_id)[0]["files"][0]
    copy = repo.list_findings(conn, new_id)[0]["files"][0]
    assert copy["id"] != original["id"]
    for key in ("filename", "description", "mime", "size", "sha256", "uploaded_at"):
        assert copy[key] == original[key]
    assert repo.file_data(conn, [copy["id"]])[copy["id"]] == PCAP
    conn.close()


# ----------------------------------------------------------------------- API --

def test_api_list_and_upload(client, finding, api_headers):
    _, fid = finding
    assert client.get(f"/api/v1/findings/{fid}/files").status_code == 401
    assert client.get(f"/api/v1/findings/{fid}/files", headers=api_headers).get_json() == {"files": []}

    resp = client.post(f"/api/v1/findings/{fid}/files", headers=api_headers, content_type="multipart/form-data",
                       data={"file": [(BytesIO(PCAP), "burp.pcap"), (BytesIO(LOG), "x/../app.log")],
                             "description": "From Burp"})
    assert resp.status_code == 201, resp.get_json()
    created = resp.get_json()["files"]
    assert [f["filename"] for f in created] == ["burp.pcap", "app.log"]
    assert created[0]["sha256"] == hashlib.sha256(PCAP).hexdigest()
    assert created[0]["download_url"].endswith(f"/files/{created[0]['id']}")
    assert "data" not in created[0]

    listed = client.get(f"/api/v1/findings/{fid}/files", headers=api_headers).get_json()["files"]
    assert [f["id"] for f in listed] == [f["id"] for f in created]
    finding_out = client.get(f"/api/v1/findings/{fid}", headers=api_headers).get_json()["finding"]
    assert finding_out["file_count"] == 2 and "files" not in finding_out


def test_api_upload_validation_and_auth(client, finding, api_headers, monkeypatch):
    import ptreport.validation as validation
    _, fid = finding
    url = f"/api/v1/findings/{fid}/files"
    no_auth = client.post(url, content_type="multipart/form-data", data={"file": (BytesIO(LOG), "a.log")})
    assert no_auth.status_code == 401
    assert client.post(url, headers=api_headers, json={"file": "x"}).status_code == 415
    resp = client.post(url, headers=api_headers, content_type="multipart/form-data",
                       data={"file": (BytesIO(b""), "a.log")})
    assert resp.status_code == 422 and resp.get_json()["errors"]["file"] == "a.log: the file is empty."
    resp = client.post(url, headers=api_headers, content_type="multipart/form-data", data={"description": "x"})
    assert resp.status_code == 422
    monkeypatch.setattr(validation, "FILE_MAX_BYTES", 5)
    resp = client.post(url, headers=api_headers, content_type="multipart/form-data",
                       data={"file": (BytesIO(b"123456"), "a.log")})
    assert resp.status_code == 422
    assert client.get("/api/v1/findings/9999/files", headers=api_headers).status_code == 404
