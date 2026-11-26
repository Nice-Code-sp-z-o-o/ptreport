import sqlite3

import pytest

from ptreport import repo
from ptreport.cvss_service import rating_for_score
from ptreport.db import MIGRATIONS, connect, migrate
from ptreport.validation import validate_finding

VECTOR_46 = "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"  # 4.6 Medium


def test_severity_and_cvss_rating_are_separate():
    clean, errors = validate_finding({"title": "x", "cvss_version": "3.1", "cvss_vector": VECTOR_46, "severity": "low"})
    assert errors == {}
    assert (clean["severity"], clean["cvss_score"]) == ("low", 4.6)
    assert rating_for_score(clean["cvss_score"], "3.1") == "medium"


def test_old_severity_manual_flag_is_ignored():
    clean, errors = validate_finding({"title": "x", "severity": "high", "severity_manual": "1"})
    assert errors == {} and "severity_manual" not in clean


@pytest.mark.parametrize("value", ["SEC-0002", "WEB.1", "A", "x:y_z-9"])
def test_valid_external_ids(value):
    clean, errors = validate_finding({"title": "x", "severity": "low", "external_id": value})
    assert errors == {} and clean["external_id"] == value


@pytest.mark.parametrize("value", ["-SEC", "SEC 01", "<b>", "A" * 33, "SEC/1"])
def test_invalid_external_ids(value):
    assert "external_id" in validate_finding({"title": "x", "severity": "low", "external_id": value})[1]


@pytest.mark.parametrize("score,version,rating", [
    (None, "3.1", ""), (0.0, "3.1", "none"), (3.5, "3.1", "low"), (4.6, "3.1", "medium"),
    (8.4, "3.1", "high"), (9.3, "4.0", "critical"), (7.5, "2.0", "high"), (0.0, "2.0", "none"),
])
def test_rating_for_score(score, version, rating):
    assert rating_for_score(score, version) == rating


def test_display_id_and_uniqueness_in_ui(client, csrf, make_report, make_finding):
    report_id = make_report(finding_prefix="SEC")
    fid = make_finding(report_id, external_id="SEC-0002", cvss_version="3.1", cvss_vector=VECTOR_46,
                       severity="low")
    auto = make_finding(report_id, title="Second")
    page = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "SEC-0002" in page and "SEC-002" in page

    resp = client.post(f"/findings/{auto}/edit", data={"_csrf": csrf, "title": "Second", "severity": "low",
                                                       "external_id": "sec-0002"})
    assert resp.status_code == 422
    assert "already uses this ID" in resp.get_data(as_text=True)
    # saving a finding with its own ID is fine
    resp = client.post(f"/findings/{fid}/edit", data={"_csrf": csrf, "title": "Renamed", "external_id": "SEC-0002",
                                                      "cvss_version": "3.1", "cvss_vector": VECTOR_46,
                                                      "severity": "low"})
    assert resp.status_code == 302

    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    assert "SEC-0002" in html
    # severity stays Low (the tester's call), the CVSS chip shows 4.6 in the Medium colour
    assert 'cvss-chip cv-medium' in html and '>4.6</span><span class="cvss-chip-rating">Medium<' in html
    assert 'sev sev-low' in html
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    assert "### SEC-0002: Renamed" in md


def test_api_rejects_duplicate_external_id(client, api_headers, make_report):
    report_id = make_report()
    body = {"title": "x", "severity": "low", "external_id": "SEC-0001"}
    assert client.post(f"/api/v1/reports/{report_id}/findings", headers=api_headers, json=body).status_code == 201
    resp = client.post(f"/api/v1/reports/{report_id}/findings", headers=api_headers, json=body)
    assert resp.status_code == 422 and "external_id" in resp.get_json()["errors"]


def test_import_roundtrip_keeps_ids_and_severity(client, csrf, make_report, make_finding):
    from io import BytesIO
    report_id = make_report()
    make_finding(report_id, external_id="SEC-0011", cvss_version="3.1", cvss_vector=VECTOR_46, severity="low")
    exported = client.get(f"/reports/{report_id}/export/json").get_data()
    resp = client.post("/import", data={"_csrf": csrf, "file": (BytesIO(exported), "r.json")},
                       content_type="multipart/form-data")
    assert resp.status_code == 302
    new_id = int(resp.headers["Location"].rsplit("/", 1)[1])
    conn = connect(client.application.config["DATABASE"])
    f = repo.list_findings(conn, new_id)[0]
    conn.close()
    assert (f["external_id"], f["severity"], f["cvss_score"]) == ("SEC-0011", "low", 4.6)


def test_migration_upgrades_version_1_database(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(MIGRATIONS[0] + "\nPRAGMA user_version = 1;")
    conn.execute("INSERT INTO reports (title) VALUES ('old')")
    conn.execute("INSERT INTO findings (report_id, position, title, severity) VALUES (1, 1, 'f', 'low')")
    conn.commit()
    conn.close()
    conn = connect(path)
    assert migrate(conn) == len(MIGRATIONS)
    row = conn.execute("SELECT external_id, severity_manual FROM findings").fetchone()
    conn.close()
    assert (row["external_id"], row["severity_manual"]) == ("", 0)
