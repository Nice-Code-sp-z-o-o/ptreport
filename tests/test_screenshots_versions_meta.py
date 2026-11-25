import base64
import json
import struct
import zlib
from io import BytesIO

from ptreport import repo
from ptreport.db import connect


def png_bytes(color=(255, 0, 0)) -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"\x00" + bytes(color)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def upload(client, csrf, finding_id, data, name="shot.png", caption="XSS attack execution"):
    return client.post(f"/findings/{finding_id}/attachments",
                       data={"_csrf": csrf, "caption": caption, "file": (BytesIO(data), name)},
                       content_type="multipart/form-data")


def db(client):
    return connect(client.application.config["DATABASE"])


def test_upload_serve_caption_delete(client, csrf, make_report, make_finding):
    fid = make_finding(make_report())
    resp = upload(client, csrf, fid, png_bytes())
    assert resp.status_code == 302
    conn = db(client)
    att = repo.list_attachments(conn, fid)[0]
    assert (att["mime"], att["caption"], att["position"]) == ("image/png", "XSS attack execution", 1)

    served = client.get(f"/attachments/{att['id']}")
    assert served.status_code == 200 and served.mimetype == "image/png"
    assert served.data == png_bytes()
    assert "sandbox" in served.headers["Content-Security-Policy"]
    assert served.headers["X-Content-Type-Options"] == "nosniff"

    page = client.get(f"/findings/{fid}/edit").get_data(as_text=True)
    assert f"/attachments/{att['id']}" in page

    assert client.post(f"/attachments/{att['id']}/caption", data={"_csrf": csrf, "caption": "New"}).status_code == 302
    assert repo.get_attachment(conn, att["id"])["caption"] == "New"
    assert client.post(f"/attachments/{att['id']}/delete", data={"_csrf": csrf}).status_code == 302
    assert repo.list_attachments(conn, fid) == []
    conn.close()


def test_upload_rejects_non_images_and_requires_csrf(client, csrf, make_report, make_finding):
    fid = make_finding(make_report())
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    for data, name in ((svg, "x.svg"), (b"not an image", "fake.png"), (b"", "empty.png")):
        resp = upload(client, csrf, fid, data, name)
        assert resp.status_code == 422, name
    resp = client.post(f"/findings/{fid}/attachments", data={"file": (BytesIO(png_bytes()), "a.png")},
                       content_type="multipart/form-data")
    assert resp.status_code == 400
    assert client.get("/attachments/999").status_code == 404


def test_upload_size_limit(client, csrf, make_report, make_finding, monkeypatch):
    import ptreport.validation as validation
    monkeypatch.setattr(validation, "IMAGE_MAX_BYTES", 10)
    fid = make_finding(make_report())
    assert upload(client, csrf, fid, png_bytes()).status_code == 422


def test_figures_in_exports(client, csrf, make_report, make_finding):
    report_id = make_report(language="pl")
    first = make_finding(report_id, title="A")
    second = make_finding(report_id, title="B")
    upload(client, csrf, first, png_bytes(), caption="Pierwszy")
    upload(client, csrf, second, png_bytes((0, 255, 0)), caption="Drugi")

    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert html.count("data:image/png;base64,") == 2
    assert "Rysunek 1: Pierwszy" in html and "Rysunek 2: Drugi" in html
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "![Rysunek 1: Pierwszy](data:image/png;base64," in md


def test_report_metadata_versions_and_confidence(client, csrf, make_report, make_finding):
    report_id = make_report(vendor_name="LogicalTrust", vendor_contact="www.logicaltrust.net",
                            report_version="1.0", report_date="2023-07-12")
    make_finding(report_id, confidence="certain")
    assert client.post(f"/reports/{report_id}/versions", data={
        "_csrf": csrf, "version": "0.1", "date": "2023-07-05", "description": "Draft report"}).status_code == 302
    assert client.post(f"/reports/{report_id}/versions", data={
        "_csrf": csrf, "version": "1.0", "date": "2023-07-12", "description": "Final version after the retest"}
    ).status_code == 302
    bad = client.post(f"/reports/{report_id}/versions", data={"_csrf": csrf, "version": "", "date": "x"})
    assert bad.status_code == 422

    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    for text in ("LogicalTrust", "www.logicaltrust.net", "2023-07-12", "Report version history",
                 "Final version after the retest", "Confidence", "Certain"):
        assert text in html, text

    conn = db(client)
    version = repo.list_report_versions(conn, report_id)[0]
    assert version["version"] == "0.1"
    assert client.post(f"/report-versions/{version['id']}/delete", data={"_csrf": csrf}).status_code == 302
    assert len(repo.list_report_versions(conn, report_id)) == 1
    conn.close()


def test_invalid_metadata_and_confidence(client, csrf, make_report):
    resp = client.post("/reports/new", data={"_csrf": csrf, "title": "T", "finding_prefix": "A",
                                             "report_version": "1.0 final!", "report_date": "2023-13-01"})
    assert resp.status_code == 422
    report_id = make_report()
    resp = client.post(f"/reports/{report_id}/findings/new", data={"_csrf": csrf, "title": "x", "severity": "low",
                                                                  "confidence": "sure"})
    assert resp.status_code == 422


def test_json_roundtrip_with_screenshots_and_versions(client, csrf, make_report, make_finding):
    report_id = make_report(vendor_name="ACME Security", report_version="2.0")
    fid = make_finding(report_id, confidence="probable")
    upload(client, csrf, fid, png_bytes(), caption="Proof")
    client.post(f"/reports/{report_id}/versions", data={"_csrf": csrf, "version": "2.0", "description": "Final"})
    exported = client.get(f"/reports/{report_id}/export/json").get_data()
    doc = json.loads(exported)
    assert doc["findings"][0]["attachments"][0]["caption"] == "Proof"
    assert base64.b64decode(doc["findings"][0]["attachments"][0]["data_base64"]) == png_bytes()

    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(exported), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = db(client)
    f = repo.list_findings(conn, new_id)[0]
    assert f["confidence"] == "probable" and f["attachments"][0]["caption"] == "Proof"
    assert repo.get_report(conn, new_id)["vendor_name"] == "ACME Security"
    assert repo.list_report_versions(conn, new_id)[0]["description"] == "Final"
    conn.close()

    doc["findings"][0]["attachments"] = [{"caption": "x", "data_base64": "!!!"}]
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 422
    doc["findings"][0]["attachments"] = [{"caption": "x", "data_base64": base64.b64encode(b"<svg/>").decode()}]
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(json.dumps(doc).encode()), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 422


def test_api_screenshot(client, api_headers, make_report, make_finding):
    fid = make_finding(make_report())
    body = {"caption": "From Burp", "data_base64": base64.b64encode(png_bytes()).decode()}
    resp = client.post(f"/api/v1/findings/{fid}/attachments", headers=api_headers, json=body)
    assert resp.status_code == 201 and resp.get_json()["attachment"]["mime"] == "image/png"
    assert "data" not in resp.get_json()["attachment"]
    bad = client.post(f"/api/v1/findings/{fid}/attachments", headers=api_headers,
                      json={"data_base64": base64.b64encode(b"GIF-not").decode()})
    assert bad.status_code == 422
    assert client.post(f"/api/v1/findings/{fid}/attachments", json=body).status_code == 401
    detail = client.get(f"/api/v1/findings/{fid}", headers=api_headers).get_json()["finding"]
    assert detail["screenshot_count"] == 1
