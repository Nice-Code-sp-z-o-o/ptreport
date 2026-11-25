from ptreport import repo
from ptreport.db import connect


def test_quick_target_from_finding_editor(client, csrf, make_report, make_finding):
    report_id = make_report()
    fid = make_finding(report_id)
    page = client.get(f"/findings/{fid}/edit").get_data(as_text=True)
    assert 'id="target-dialog"' in page and f"/reports/{report_id}/targets/quick" in page

    resp = client.post(f"/reports/{report_id}/targets/quick", headers={"X-CSRF-Token": csrf},
                       data={"name": "Admin panel", "kind": "web", "address": "https://admin.example"})
    assert resp.status_code == 201
    target = resp.get_json()["target"]
    assert target["name"] == "Admin panel" and isinstance(target["id"], int)
    conn = connect(client.application.config["DATABASE"])
    assert repo.get_target(conn, target["id"])["report_id"] == report_id
    conn.close()


def test_quick_target_validation_csrf_and_404(client, csrf, make_report):
    report_id = make_report()
    bad = client.post(f"/reports/{report_id}/targets/quick", headers={"X-CSRF-Token": csrf},
                      data={"name": "", "kind": "spaceship"})
    assert bad.status_code == 422 and {"name", "kind"} <= set(bad.get_json()["errors"])
    assert client.post(f"/reports/{report_id}/targets/quick", data={"name": "x"}).status_code == 400
    assert client.post("/reports/999/targets/quick", headers={"X-CSRF-Token": csrf},
                       data={"name": "x", "kind": "web"}).status_code == 404


def test_separate_page_returns_to_finding(client, csrf, make_report, make_finding):
    report_id = make_report()
    other_report = make_report()
    fid = make_finding(report_id)
    form = client.get(f"/reports/{report_id}/targets/new?return_to_finding={fid}").get_data(as_text=True)
    assert f'name="return_to_finding" value="{fid}"' in form
    resp = client.post(f"/reports/{report_id}/targets/new",
                       data={"_csrf": csrf, "name": "API", "kind": "api", "return_to_finding": str(fid)})
    assert resp.headers["Location"].endswith(f"/findings/{fid}/edit#targets")
    # a finding of another report is not a valid return target
    resp = client.post(f"/reports/{other_report}/targets/new",
                       data={"_csrf": csrf, "name": "API", "kind": "api", "return_to_finding": str(fid)})
    assert resp.headers["Location"].endswith(f"/reports/{other_report}#targets")
