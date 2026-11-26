import json
from io import BytesIO

from ptreport import repo
from ptreport.db import connect


def db(client):
    return connect(client.application.config["DATABASE"])


def note_id_from(resp):
    return int(resp.headers["Location"].rsplit("note=", 1)[1])


def test_notes_crud_and_report_button(client, csrf, make_report):
    report_id = make_report()
    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert f"/reports/{report_id}/notes" in page
    assert "No notes yet." in client.get(f"/reports/{report_id}/notes").get_data(as_text=True)

    resp = client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": "Nmap DMZ",
                                                            "body": "## Ports\n\n| Port | Svc |\n|---|---|\n| 22 | ssh |"})
    assert resp.status_code == 302
    nid = note_id_from(resp)
    page = client.get(f"/reports/{report_id}/notes?note={nid}").get_data(as_text=True)
    assert "Nmap DMZ" in page and '<table class="tbl rt-table">' in page
    assert '<span class="tab-count">1</span>' in client.get(f"/reports/{report_id}").get_data(as_text=True)

    assert client.post(f"/notes/{nid}/edit", data={"_csrf": csrf, "title": "Nmap DMZ v2", "body": "x",
                                                   "pinned": "1"}).status_code == 302
    conn = db(client)
    note = repo.get_note(conn, nid)
    assert (note["title"], note["pinned"]) == ("Nmap DMZ v2", 1)
    assert client.post(f"/notes/{nid}/delete", data={"_csrf": csrf}).status_code == 302
    assert repo.get_note(conn, nid) is None
    conn.close()


def test_notes_validation_csrf_and_isolation(client, csrf, make_report):
    report_id = make_report()
    other = make_report(title="Other")
    assert client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": ""}).status_code == 422
    assert client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": "x" * 301}).status_code == 422
    assert client.post(f"/reports/{report_id}/notes", data={"title": "no csrf"}).status_code == 400
    nid = note_id_from(client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": "Secret"}))
    # a note is only shown under its own report
    assert client.get(f"/reports/{other}/notes?note={nid}").status_code == 404
    assert client.get(f"/reports/{report_id}/notes?note=999").status_code == 404
    assert client.post("/notes/999/edit", data={"_csrf": csrf, "title": "x"}).status_code == 404
    # notes are never part of the report itself
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "Secret" not in html


def test_notes_escape_html_pinned_first_and_search(client, csrf, make_report):
    report_id = make_report()
    client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": "Old", "body": "<script>alert(1)</script>"})
    client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": "Pinned", "pinned": "1",
                                                     "body": "100%_done"})
    conn = db(client)
    assert [n["title"] for n in repo.list_notes(conn, report_id)] == ["Pinned", "Old"]
    assert [n["title"] for n in repo.list_notes(conn, report_id, "100%_")] == ["Pinned"]
    assert repo.list_notes(conn, report_id, "%zz") == []  # % is literal, not a wildcard
    old = repo.list_notes(conn, report_id)[1]
    page = client.get(f"/reports/{report_id}/notes?note={old['id']}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    page = client.get(f"/reports/{report_id}/notes?q=Old").get_data(as_text=True)
    assert "Pinned" not in page.split("note-list")[1].split("</ul>")[0]
    conn.close()


def test_notes_in_json_backup_and_copies(client, csrf, make_report):
    report_id = make_report()
    client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": "First"})
    client.post(f"/reports/{report_id}/notes", data={"_csrf": csrf, "title": "Second", "pinned": "1"})
    exported = client.get(f"/reports/{report_id}/export/json").data
    assert [n["title"] for n in json.loads(exported)["notes"]] == ["First", "Second"]
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(exported), "r.json")},
                       content_type="multipart/form-data")
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = db(client)
    assert {n["title"] for n in repo.list_notes(conn, new_id)} == {"First", "Second"}
    retest = int(client.post(f"/reports/{report_id}/retest", data={"_csrf": csrf}).headers["Location"].rsplit("/", 1)[1])
    assert len(repo.list_notes(conn, retest)) == 2
    doc = json.loads(exported)
    doc["notes"] = [{"title": ""}]
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 422
    conn.close()


def test_notes_api(client, api_headers, make_report):
    report_id = make_report()
    assert client.post(f"/api/v1/reports/{report_id}/notes", json={"title": "x"}).status_code == 401
    resp = client.post(f"/api/v1/reports/{report_id}/notes", headers=api_headers,
                       json={"title": "From Burp", "body": "GET /admin -> 403", "pinned": True})
    assert resp.status_code == 201 and resp.get_json()["note"]["pinned"] == 1
    assert client.post(f"/api/v1/reports/{report_id}/notes", headers=api_headers, json={"body": "x"}).status_code == 422
    rows = client.get(f"/api/v1/reports/{report_id}/notes", headers=api_headers).get_json()["notes"]
    assert [n["title"] for n in rows] == ["From Burp"]
    assert client.get("/api/v1/reports/999/notes", headers=api_headers).status_code == 404
