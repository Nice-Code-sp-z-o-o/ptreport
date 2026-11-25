import pytest

from ptreport.cvss_service import METRIC_DEFINITIONS, CvssInvalid, score_vector, vector_strip


@pytest.mark.parametrize(
    "vector,version,score,severity",
    [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "4.0", 9.3, "critical"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "4.0", 0.0, "info"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "3.1", 9.8, "critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "3.1", 6.1, "medium"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "3.0", 10.0, "critical"),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "2.0", 7.5, "high"),
        ("(AV:N/AC:L/Au:N/C:P/I:P/A:P)", "2.0", 7.5, "high"),
        ("AV:L/AC:H/Au:M/C:N/I:N/A:N", "2.0", 0.0, "info"),
    ],
)
def test_score_vector(vector, version, score, severity):
    result = score_vector(vector)
    assert result.version == version
    assert result.score == score
    assert result.severity == severity


def test_temporal_metrics_change_effective_score_but_keep_base():
    result = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U")
    assert result.base_score == 9.8
    assert result.score == 9.0


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "garbage",
        "CVSS:3.1/AV:N",  # incomplete
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",  # duplicate metric
        "CVSS:4.0/AV:N/AC:L",
        "CVSS:3.1/" + "A" * 600,
    ],
)
def test_invalid_vectors_raise(vector):
    with pytest.raises(CvssInvalid):
        score_vector(vector)


def test_version_mismatch_is_rejected():
    with pytest.raises(CvssInvalid):
        score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", expected_version="4.0")


def test_ui_definitions_build_valid_vectors_for_every_version():
    """Picking the first value of every required metric must yield a vector the scorer accepts."""
    for version, definition in METRIC_DEFINITIONS.items():
        parts = [definition["prefix"]] if definition["prefix"] else []
        for group in definition["groups"]:
            if group["required"]:
                parts += [f"{m['key']}:{m['values'][0]['key']}" for m in group["metrics"]]
        assert score_vector("/".join(parts), expected_version=version).version == version


def test_endpoint_returns_score(client):
    data = client.get("/cvss/score", query_string={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}).get_json()
    assert data == {"valid": True, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "base_score": 9.8, "score": 9.8, "severity": "critical",
                    "rating": "critical"}
    bad = client.get("/cvss/score", query_string={"vector": "nope"}).get_json()
    assert bad["valid"] is False and bad["error"]


V31 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _flat(groups):
    return {c["key"]: (c["value"], c["tone"], c["group"]) for g in groups for c in g["cells"]}


def test_vector_strip_v31_groups_and_tones():
    groups = vector_strip(V31)
    assert [g["name"] for g in groups] == ["Exploitability", "Scope", "Impact"]
    cells = _flat(groups)
    assert cells["AV"] == ("N", 3, "Exploitability")
    assert cells["PR"] == ("L", 2, "Exploitability")
    assert cells["UI"] == ("R", 1, "Exploitability")
    assert cells["S"] == ("C", 2, "Scope")
    assert cells["C"] == ("L", 1, "Impact") and cells["A"] == ("N", 0, "Impact")


def test_vector_strip_v40_has_three_groups():
    groups = vector_strip(V40)
    assert [g["name"] for g in groups] == ["Exploitability", "Vulnerable system", "Subsequent system"]
    assert [len(g["cells"]) for g in groups] == [5, 3, 3]
    assert _flat(groups)["SC"] == ("N", 0, "Subsequent system")


def test_vector_strip_v2_and_not_defined_and_garbage():
    cells = _flat(vector_strip("AV:N/AC:L/Au:N/C:P/I:P/A:P/E:ND"))
    assert cells["Au"][1] == 3 and cells["C"][1] == 1 and "E" not in cells
    assert vector_strip("") == [] and vector_strip(None) == [] and vector_strip("nonsense") == []


def test_every_definition_value_has_tone_and_every_metric_a_strip_group():
    for definition in METRIC_DEFINITIONS.values():
        for group in definition["groups"]:
            for metric in group["metrics"]:
                assert metric["strip_group"]
                assert all(v["tone"] in (0, 1, 2, 3) for v in metric["values"])


def test_finding_page_renders_vector_strip(client, csrf, make_report):
    report_id = make_report()
    resp = client.post(f"/reports/{report_id}/findings/new", data={
        "_csrf": csrf, "title": "SQLi", "cvss_version": "4.0", "cvss_vector": V40, "status": "open",
        "severity": "critical"})
    assert resp.status_code == 302
    detail = client.get(f"/reports/{report_id}").get_data(as_text=True)
    assert 'class="vec"' not in detail and 'cvss-chip cv-critical' in detail  # list shows the score chip only
    edit = client.get("/findings/1/edit").get_data(as_text=True)
    assert "vec vec-lg" in edit and "cvss-chip cv-critical cvss-chip-lg" in edit


@pytest.mark.parametrize("vector,score", [
    # Scope:Changed - the environmental equation gives 8.5/8.1 here; the base score is 8.4/8.0
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", 8.4),
    ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.0),
    ("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H", 8.4),
])
def test_v3_score_is_base_score_without_environmental_metrics(vector, score):
    result = score_vector(vector)
    assert result.score == score == result.base_score


def test_v3_environmental_metrics_are_used_when_present():
    result = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L")
    assert result.base_score == 9.8 and result.score < 9.8
