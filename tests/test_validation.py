import pytest

from ptreport.validation import validate_evidence, validate_finding, validate_report, validate_target


def report(**kw):
    data = {"title": "T", "finding_prefix": "VULN", "language": "en"}
    data.update(kw)
    return validate_report(data)


def test_report_happy_path_normalizes_prefix():
    clean, errors = report(finding_prefix=" acme1 ", assessor="Jan Kowalski, Anna Nowak-Kos", start_date="2026-01-02")
    assert errors == {}
    assert clean["finding_prefix"] == "ACME1"
    assert clean["start_date"] == "2026-01-02"


@pytest.mark.parametrize(
    "field,value",
    [
        ("title", ""),
        ("title", "x" * 301),
        ("title", "line1\nline2"),
        ("assessor", "Jan Kowalski 2"),
        ("assessor", "<script>"),
        ("finding_prefix", "1ABC"),
        ("finding_prefix", "AB-C"),
        ("finding_prefix", "ABCDEFGHIJK"),
        ("language", "de"),
        ("start_date", "2026-13-01"),
        ("start_date", "1800-01-01"),
        ("title", 123),
    ],
)
def test_report_invalid_fields(field, value):
    _, errors = report(**{field: value})
    assert field in errors


def test_report_end_before_start():
    _, errors = report(start_date="2026-05-10", end_date="2026-05-01")
    assert "end_date" in errors


def test_unicode_names_are_allowed():
    _, errors = report(assessor="Łukasz Żółć, Zoë O'Brien")
    assert errors == {}


def test_target_validation():
    assert validate_target({"name": "API", "kind": "api"})[1] == {}
    assert "name" in validate_target({"name": "", "kind": "api"})[1]
    assert "kind" in validate_target({"name": "x", "kind": "spaceship"})[1]


def test_finding_severity_is_independent_of_cvss():
    clean, errors = validate_finding({
        "title": "RCE", "cvss_version": "3.1", "severity": "low",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    })
    assert errors == {}
    assert clean["severity"] == "low"  # the tester's assessment, not the CVSS rating
    assert clean["cvss_score"] == 9.8


def test_finding_with_cvss_still_requires_severity():
    _, errors = validate_finding({"title": "RCE", "cvss_version": "3.1",
                                  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert "severity" in errors


def test_finding_without_cvss_requires_manual_severity():
    _, errors = validate_finding({"title": "Info leak", "cvss_version": ""})
    assert "severity" in errors
    clean, errors = validate_finding({"title": "Info leak", "cvss_version": "", "severity": "low",
                                      "cvss_vector": "CVSS:3.1/AV:N"})
    assert errors == {}
    assert clean["cvss_vector"] == "" and clean["cvss_score"] is None


def test_finding_cvss_vector_must_match_version():
    _, errors = validate_finding({"title": "x", "cvss_version": "4.0",
                                  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert "cvss_vector" in errors


def test_finding_cvss_version_requires_vector():
    _, errors = validate_finding({"title": "x", "cvss_version": "3.1", "cvss_vector": ""})
    assert "cvss_vector" in errors


@pytest.mark.parametrize("raw,expected", [("79", "CWE-79"), ("cwe-89", "CWE-89"), (" CWE-1336 ", "CWE-1336")])
def test_cwe_normalization(raw, expected):
    clean, errors = validate_finding({"title": "x", "severity": "low", "cwe": raw})
    assert errors == {}
    assert clean["cwe"] == expected


@pytest.mark.parametrize("raw", ["CWE-", "XSS", "CWE-0", "CWE-123456", "79a"])
def test_invalid_cwe(raw):
    assert "cwe" in validate_finding({"title": "x", "severity": "low", "cwe": raw})[1]


@pytest.mark.parametrize("ids", [["a"], [True], "x", {"a": 1}])
def test_invalid_target_ids(ids):
    assert "target_ids" in validate_finding({"title": "x", "severity": "low", "target_ids": ids})[1]


def test_evidence_preserves_raw_message():
    raw = "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
    clean, errors = validate_evidence({"request": raw})
    assert errors == {}
    assert clean["request"] == "GET / HTTP/1.1\nHost: a\n\n"
    assert "request" in validate_evidence({"request": "   "})[1]
