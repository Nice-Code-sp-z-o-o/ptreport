import base64
import io
import json
import struct
import zipfile
import zlib
from io import BytesIO

import pytest

from ptreport import repo
from ptreport.db import MIGRATIONS, connect, migrate
from ptreport.validation import image_dimensions, validate_edited_image


def png(width=4, height=3, color=(255, 0, 0)) -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes(color) * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def jpeg_header(width, height) -> bytes:
    """SOI + APP0 + SOF0 + EOI: enough for the header checks (not a decodable picture)."""
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + app0 + sof0 + b"\xff\xd9"


def db(client):
    return connect(client.application.config["DATABASE"])


@pytest.fixture()
def shot(client, csrf, make_report, make_finding):
    """A report with one finding and one 4x3 red screenshot; returns (report_id, finding_id, attachment_id)."""
    report_id = make_report()
    fid = make_finding(report_id)
    resp = client.post(f"/findings/{fid}/attachments",
                       data={"_csrf": csrf, "caption": "Login page", "file": (BytesIO(png()), "a.png")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    conn = db(client)
    att_id = repo.list_attachments(conn, fid)[0]["id"]
    conn.close()
    return report_id, fid, att_id


def save_edit(client, csrf, att_id, data, name="screenshot.png"):
    form = {"file": (BytesIO(data), name)}
    if csrf:
        form["_csrf"] = csrf
    return client.post(f"/attachments/{att_id}/edit", data=form, content_type="multipart/form-data")


# ---------------------------------------------------------------- validation --

def test_image_dimensions_png_and_jpeg():
    assert image_dimensions(png(7, 5)) == (7, 5)
    assert image_dimensions(jpeg_header(640, 480)) == (640, 480)
    assert image_dimensions(b"\x89PNG\r\n\x1a\n" + b"\x00" * 30) is None   # no IHDR
    assert image_dimensions(b"\xff\xd8\xff\xd9") is None                      # no frame header
    assert image_dimensions(b"GIF89a....") is None


def test_validate_edited_image_rules():
    source = png(4, 3)
    clean, errors = validate_edited_image(png(2, 2), source)
    assert not errors and (clean["mime"], clean["width"], clean["height"]) == ("image/png", 2, 2)
    assert "larger than the original" in validate_edited_image(png(5, 3), source)[1]["file"]
    assert "incomplete" in validate_edited_image(png(2, 2)[:-12], source)[1]["file"]
    assert validate_edited_image(None, source)[1]["file"]
    assert validate_edited_image(b"<svg/>", source)[1]["file"]
    assert not validate_edited_image(jpeg_header(4, 3), source)[1]


# --------------------------------------------------------------- save/restore --

def test_save_edited_image_keeps_original_and_shows_badge(client, csrf, shot):
    _, fid, att_id = shot
    edited = png(2, 2, (0, 0, 255))
    resp = save_edit(client, csrf, att_id, edited)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["ok"] is True and (body["width"], body["height"]) == (2, 2)
    assert body["redirect"].endswith(f"/findings/{fid}/edit#screenshots")

    assert client.get(f"/attachments/{att_id}").data == edited
    original = client.get(f"/attachments/{att_id}/original")
    assert original.status_code == 200 and original.data == png() and original.mimetype == "image/png"
    assert "sandbox" in original.headers["Content-Security-Policy"]

    conn = db(client)
    att = repo.get_attachment(conn, att_id)
    assert att["edited"] == 1 and att["edited_at"] and att["caption"] == "Login page"
    conn.close()

    page = client.get(f"/findings/{fid}/edit").get_data(as_text=True)
    assert "Edited</span>" in page and f"/attachments/{att_id}/restore" in page
    assert f'data-action="/attachments/{att_id}/edit"' in page and "screenshot-editor.js" in page
    assert 'id="shot-editor"' in page


def test_second_edit_keeps_the_first_original(client, csrf, shot):
    _, _, att_id = shot
    assert save_edit(client, csrf, att_id, png(3, 3, (0, 255, 0))).status_code == 200
    # the second edit is checked against the original's size, not the (smaller) first edit
    assert save_edit(client, csrf, att_id, png(4, 3, (0, 0, 255))).status_code == 200
    assert client.get(f"/attachments/{att_id}/original").data == png()
    assert client.get(f"/attachments/{att_id}").data == png(4, 3, (0, 0, 255))


def test_jpeg_edit_is_accepted(client, csrf, shot):
    _, _, att_id = shot
    resp = save_edit(client, csrf, att_id, jpeg_header(4, 3), "screenshot.jpg")
    assert resp.status_code == 200
    assert client.get(f"/attachments/{att_id}").mimetype == "image/jpeg"


@pytest.mark.parametrize("data, message", [
    (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "Only PNG and JPEG"),
    (b"not an image at all", "Only PNG and JPEG"),
    (b"", "Choose an image"),
    (png(8, 8), "larger than the original"),
    (b"\x89PNG\r\n\x1a\n" + b"\x00" * 40, "damaged"),
])
def test_edit_rejects_bad_images(client, csrf, shot, data, message):
    _, _, att_id = shot
    resp = save_edit(client, csrf, att_id, data)
    assert resp.status_code == 422
    assert message in resp.get_json()["message"]
    assert client.get(f"/attachments/{att_id}").data == png()
    assert client.get(f"/attachments/{att_id}/original").status_code == 404


def test_edit_rejects_oversized_upload(client, csrf, shot, monkeypatch):
    import ptreport.validation as validation
    monkeypatch.setattr(validation, "IMAGE_MAX_BYTES", 20)
    _, _, att_id = shot
    resp = save_edit(client, csrf, att_id, png(2, 2))
    assert resp.status_code == 422 and "at most" in resp.get_json()["message"]


def test_edit_and_restore_require_csrf_and_existing_attachment(client, csrf, shot):
    _, _, att_id = shot
    assert save_edit(client, None, att_id, png(2, 2)).status_code == 400
    assert client.post(f"/attachments/{att_id}/edit", data={"_csrf": "wrong", "file": (BytesIO(png(2, 2)), "a.png")},
                       content_type="multipart/form-data").status_code == 400
    assert client.get(f"/attachments/{att_id}").data == png()
    assert save_edit(client, csrf, 9999, png(2, 2)).status_code == 404
    assert client.post("/attachments/9999/restore", data={"_csrf": csrf}).status_code == 404
    assert save_edit(client, csrf, att_id, png(2, 2)).status_code == 200
    assert client.post(f"/attachments/{att_id}/restore", data={}).status_code == 400
    assert client.get(f"/attachments/{att_id}").data == png(2, 2)
    assert client.get(f"/attachments/{att_id}/edit").status_code == 405


def test_restore_original(client, csrf, shot):
    _, fid, att_id = shot
    save_edit(client, csrf, att_id, png(2, 2, (0, 0, 255)))
    resp = client.post(f"/attachments/{att_id}/restore", data={"_csrf": csrf})
    assert resp.status_code == 302 and resp.headers["Location"].endswith(f"/findings/{fid}/edit#screenshots")
    assert client.get(f"/attachments/{att_id}").data == png()
    assert client.get(f"/attachments/{att_id}/original").status_code == 404
    conn = db(client)
    att = repo.get_attachment(conn, att_id, with_data=True)
    assert att["edited"] == 0 and att["original_data"] is None and att["edited_at"] is None
    assert att["sha256"] == repo.get_attachment(conn, att_id)["sha256"]
    conn.close()
    page = client.get(f"/findings/{fid}/edit").get_data(as_text=True)
    assert "Edited</span>" not in page and "/restore" not in page
    # restoring again is harmless
    assert client.post(f"/attachments/{att_id}/restore", data={"_csrf": csrf}).status_code == 302
    assert client.get(f"/attachments/{att_id}").data == png()


def test_no_editor_without_screenshots(client, make_report, make_finding):
    fid = make_finding(make_report())
    page = client.get(f"/findings/{fid}/edit").get_data(as_text=True)
    assert 'id="shot-editor"' not in page and "screenshot-editor.js" not in page


# -------------------------------------------------------------------- exports --

def test_exports_use_the_edited_image(client, csrf, shot):
    report_id, _, att_id = shot
    edited = png(2, 2, (0, 0, 255))
    save_edit(client, csrf, att_id, edited)
    edited_b64 = base64.b64encode(edited).decode()
    original_b64 = base64.b64encode(png()).decode()

    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert edited_b64 in html and original_b64 not in html
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert edited_b64 in md and original_b64 not in md
    tex = zipfile.ZipFile(io.BytesIO(client.get(f"/reports/{report_id}/export/tex").data))
    figures = [n for n in tex.namelist() if n.endswith(".png")]
    assert figures and all(tex.read(n) == edited for n in figures)


def test_json_export_import_keeps_original(client, csrf, shot):
    report_id, _, att_id = shot
    edited = png(2, 2, (0, 0, 255))
    save_edit(client, csrf, att_id, edited)
    exported = client.get(f"/reports/{report_id}/export/json").get_data()
    doc = json.loads(exported)
    att = doc["findings"][0]["attachments"][0]
    assert base64.b64decode(att["data_base64"]) == edited
    assert base64.b64decode(att["original"]["data_base64"]) == png()
    assert att["original"]["mime"] == "image/png" and att["original"]["edited_at"]

    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(exported), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = db(client)
    new_att = repo.list_findings(conn, new_id)[0]["attachments"][0]
    stored = repo.get_attachment(conn, new_att["id"], with_data=True)
    assert stored["data"] == edited and stored["original_data"] == png() and stored["edited"] == 1
    assert stored["edited_at"] == att["original"]["edited_at"]
    conn.close()


def test_fingerprint_ignores_the_original(client, csrf, shot, app):
    """The PDF fingerprint covers report content; the hidden original is not part of it."""
    from ptreport import export
    report_id, _, att_id = shot
    save_edit(client, csrf, att_id, png(2, 2, (0, 0, 255)))
    with app.test_request_context():
        conn = db(client)
        ctx = export.build_context(conn, report_id, inline_images=True)
        assert "original" not in export.to_json(ctx)["findings"][0]["attachments"][0]
        conn.close()


def test_json_import_rejects_bad_original(client, csrf, shot):
    report_id, _, att_id = shot
    save_edit(client, csrf, att_id, png(2, 2))
    doc = json.loads(client.get(f"/reports/{report_id}/export/json").get_data())
    for bad in ({"data_base64": base64.b64encode(b"<svg/>").decode()}, {"data_base64": "!!!"}, "nope"):
        doc["findings"][0]["attachments"][0]["original"] = bad
        resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")},
                           content_type="multipart/form-data")
        assert resp.status_code == 422, bad
    # an older backup without "original" still imports as an unedited screenshot
    del doc["findings"][0]["attachments"][0]["original"]
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302


# ---------------------------------------------------------- duplicate/retest --

@pytest.mark.parametrize("action", ["duplicate", "retest"])
def test_clone_keeps_edited_and_original(client, csrf, shot, action):
    report_id, _, att_id = shot
    edited = png(2, 2, (0, 0, 255))
    save_edit(client, csrf, att_id, edited)
    resp = client.post(f"/reports/{report_id}/{action}", data={"_csrf": csrf})
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rstrip("/").rsplit("/", 1)[1])
    conn = db(client)
    copy = repo.list_findings(conn, new_id)[0]["attachments"][0]
    stored = repo.get_attachment(conn, copy["id"], with_data=True)
    assert copy["id"] != att_id and stored["data"] == edited and stored["original_data"] == png()
    conn.close()
    # restoring the copy does not touch the source report
    assert client.post(f"/attachments/{copy['id']}/restore", data={"_csrf": csrf}).status_code == 302
    assert client.get(f"/attachments/{copy['id']}").data == png()
    assert client.get(f"/attachments/{att_id}").data == edited


def test_unedited_clone_stays_unedited(client, csrf, shot):
    report_id, _, _ = shot
    new_id = int(client.post(f"/reports/{report_id}/duplicate", data={"_csrf": csrf}).headers["Location"]
                 .rstrip("/").rsplit("/", 1)[1])
    conn = db(client)
    assert repo.list_findings(conn, new_id)[0]["attachments"][0]["edited"] == 0
    conn.close()


def test_migration_adds_columns_to_existing_attachments(tmp_path):
    conn = connect(tmp_path / "old.db")
    for version, script in enumerate(MIGRATIONS[:11], start=1):
        conn.executescript("BEGIN;\n" + script + f"\nPRAGMA user_version = {version};\nCOMMIT;")
    assert migrate(conn) == len(MIGRATIONS) == 14
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(attachments)")}
    assert {"original_mime", "original_data", "original_sha256", "edited_at"} <= columns
    conn.close()
