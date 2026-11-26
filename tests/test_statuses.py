import json

import pytest

from ptreport import latex, repo
from ptreport.db import connect
from ptreport.rendering import STATUS_LABELS
from ptreport.validation import FINDING_STATUSES, OPEN_STATUSES, validate_finding

NEW_STATUSES = ("partially_fixed", "not_fixed", "wont_fix", "not_a_bug", "cannot_verify")


def db(client):
    return connect(client.application.config["DATABASE"])


def test_new_statuses_are_valid_and_labelled_in_both_languages():
    for status in NEW_STATUSES:
        assert status in FINDING_STATUSES
        clean, errors = validate_finding({"title": "X", "severity": "low", "status": status})
        assert not errors and clean["status"] == status
    assert set(STATUS_LABELS["en"]) == set(STATUS_LABELS["pl"]) == set(FINDING_STATUSES)
    assert STATUS_LABELS["en"]["wont_fix"] == "Won't fix"
    assert STATUS_LABELS["pl"]["cannot_verify"] == "Nie można zweryfikować"


def test_unknown_status_is_rejected(client, csrf, make_report):
    report_id = make_report()
    resp = client.post(f"/reports/{report_id}/findings/new",
                       data={"_csrf": csrf, "title": "X", "severity": "low", "status": "kinda_fixed"})
    assert resp.status_code == 422
    _, errors = validate_finding({"title": "X", "severity": "low", "status": "kinda_fixed"})
    assert "status" in errors


def test_open_count_includes_partially_and_not_fixed(client, make_report, make_finding):
    report_id = make_report()
    for status in FINDING_STATUSES:
        make_finding(report_id, title=f"Finding {status}", status=status)
    conn = db(client)
    try:
        counts = repo.finding_counts_by_report(conn)[report_id]
    finally:
        conn.close()
    assert counts["open"] == len(OPEN_STATUSES) == 3
    assert sum(counts["severity"].values()) == len(FINDING_STATUSES)


def test_status_change_is_recorded_with_new_label(client, csrf, make_report, make_finding):
    report_id = make_report()
    finding_id = make_finding(report_id)
    page = client.get(f"/findings/{finding_id}/edit").get_data(as_text=True)
    for status in NEW_STATUSES:
        assert f'value="{status}"' in page
    data = {"_csrf": csrf, "title": "SQL injection", "severity": "critical", "status": "partially_fixed",
            "cvss_version": ""}
    assert client.post(f"/findings/{finding_id}/edit", data=data).status_code == 302
    page = client.get(f"/findings/{finding_id}/edit").get_data(as_text=True)
    assert "Partially fixed" in page
    detail = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert "status-partially_fixed" in detail


def test_exports_show_new_statuses(client, csrf, make_report, make_finding, api_headers):
    report_id = make_report(language="pl")
    for status in NEW_STATUSES:
        make_finding(report_id, title=f"Finding {status}", status=status)
    html = client.get(f"/reports/{report_id}/export/html").get_data(as_text=True)
    md = client.get(f"/reports/{report_id}/export/md").get_data(as_text=True)
    for status in NEW_STATUSES:
        assert STATUS_LABELS["pl"][status] in html
        assert STATUS_LABELS["pl"][status] in md
    doc = json.loads(client.get(f"/reports/{report_id}/export/json").data)
    assert sorted(f["status"] for f in doc["findings"]) == sorted(NEW_STATUSES)
    # JSON round trip keeps them
    resp = client.post("/import", data={"_csrf": csrf, "file": (
        __import__("io").BytesIO(json.dumps(doc).encode()), "backup.json")}, content_type="multipart/form-data")
    assert resp.status_code == 302
    api = client.get("/api/v1/reports", headers=api_headers).get_json()["reports"]
    new_id = max(r["id"] for r in api)
    statuses = sorted(f["status"] for f in client.get(f"/api/v1/reports/{new_id}/findings",
                                                       headers=api_headers).get_json()["findings"])
    assert statuses == sorted(NEW_STATUSES)


@pytest.mark.skipif(latex.find_engine() is None, reason="no LaTeX engine installed")
def test_pdf_with_every_status(client, make_report, make_finding):
    report_id = make_report()
    for status in FINDING_STATUSES:
        make_finding(report_id, title=f"Finding {status}", status=status)
    resp = client.get(f"/reports/{report_id}/export/pdf")
    assert resp.status_code == 200 and resp.data.startswith(b"%PDF")
