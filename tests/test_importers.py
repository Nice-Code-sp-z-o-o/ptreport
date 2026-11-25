"""Scanner-file importers: detection, mapping, grouping, limits and hostile input."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from ptreport import importers
from ptreport.importers import TRUNCATED, ImportError_, detect_format, parse
from ptreport.validation import (
    CONFIDENCE_LEVELS,
    LONG,
    SEVERITIES,
    SHORT,
    TARGET_KINDS,
    validate_evidence,
    validate_finding,
    validate_target,
)

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"
SAMPLES = {
    "burp": "burp.xml",
    "nessus": "nessus.nessus",
    "nmap": "nmap.xml",
    "zap": "zap.xml",
    "openvas": "openvas.xml",
}


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def by_title(result: dict, title: str) -> dict:
    return next(f for f in result["findings"] if f["title"] == title)


def burp_xml(issues: str) -> bytes:
    return f'<?xml version="1.0"?><issues burpVersion="2024.9">{issues}</issues>'.encode()


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fmt,filename", SAMPLES.items())
def test_detect_format(fmt, filename):
    assert detect_format(load(filename)) == fmt


@pytest.mark.parametrize("filename", ["not_xml.txt", "wrong_root.xml"])
def test_detect_format_unknown(filename):
    assert detect_format(load(filename)) is None


def test_detect_format_handles_bom_comments_and_empty():
    assert detect_format(b"\xef\xbb\xbf<!-- c --><?pi x?>\n<OWASPZAPReport/>") == "zap"
    assert detect_format("<nmaprun/>".encode("utf-16")) == "nmap"
    assert detect_format(b"") is None


def test_explicit_format_must_match():
    with pytest.raises(ImportError_, match="looks like a burp"):
        parse(load("burp.xml"), fmt="nessus")
    with pytest.raises(ImportError_, match="Unknown format"):
        parse(load("burp.xml"), fmt="qualys")
    assert parse(load("burp.xml"), fmt="burp")["format"] == "burp"


# --------------------------------------------------------------------------- #
# Burp
# --------------------------------------------------------------------------- #

def test_burp_grouping_and_mapping():
    res = parse(load("burp.xml"))
    assert res["format"] == "burp"
    assert len(res["findings"]) == 2  # informational issue skipped
    assert [t["address"] for t in res["targets"]] == ["https://shop.example.com", "https://admin.example.com"]
    assert all(t["kind"] == "web" for t in res["targets"])

    xss = by_title(res, "Cross-site scripting (reflected)")
    assert xss["severity"] == "high"
    assert xss["confidence"] == "certain"  # Certain + Firm -> strongest
    assert xss["cwe"] == "CWE-79"
    assert xss["target_keys"] == ["t1", "t2"]
    assert xss["source"] == "burp"
    assert "- https://shop.example.com/search [q parameter]" in xss["description"]
    assert "- https://admin.example.com/users [filter parameter]" in xss["description"]
    assert "alert('x')" not in xss["description"]  # <script> dropped
    assert "<script>alert(1)</script>" in xss["description"]  # escaped text kept as text
    assert "- Input should be validated as strictly as possible.\n- User input" in xss["remediation"]
    assert "https://portswigger.net/web-security/cross-site-scripting/reflected" in xss["refs"].split("\n")
    assert "https://cwe.mitre.org/data/definitions/79.html" in xss["refs"].split("\n")

    assert len(xss["evidence"]) == 2
    b64, plain = xss["evidence"]
    assert b64["title"] == "/search [q parameter]"
    assert b64["request"].startswith("GET /search?q=%3Cscript%3E HTTP/1.1\nHost: shop.example.com\n")
    assert "\r" not in b64["request"] + b64["response"]
    assert "<script>alert(1)</script>" in b64["response"]
    assert plain["request"].startswith("GET /users?filter=")

    hsts = by_title(res, "Strict transport security not enforced")
    assert (hsts["severity"], hsts["confidence"], hsts["cwe"]) == ("low", "unknown", "CWE-523")
    assert hsts["evidence"] == []
    assert any("informational" in w for w in res["warnings"])


def test_burp_include_info_and_confidence_firm():
    res = parse(load("burp.xml"), include_info=True)
    info = by_title(res, "Email addresses disclosed")
    assert info["severity"] == "info"
    assert "sales@example.com" in info["description"]
    assert not any("informational" in w for w in res["warnings"])

    single = parse(burp_xml("<issue><type>1</type><name>X</name><host>https://h</host><path>/</path>"
                            "<severity>Medium</severity><confidence>Firm</confidence></issue>"))
    assert single["findings"][0]["confidence"] == "probable"
    assert single["findings"][0]["severity"] == "medium"


def test_burp_large_response_is_truncated():
    body = b"HTTP/1.1 200 OK\r\n\r\n" + b"A" * 300_000
    issue = ("<issue><type>1</type><name>Big</name><host>https://h</host><path>/</path><location>/</location>"
             "<severity>High</severity><requestresponse>"
             f'<request base64="true">{base64.b64encode(b"GET / HTTP/1.1").decode()}</request>'
             f'<response base64="true">{base64.b64encode(body).decode()}</response>'
             "</requestresponse></issue>")
    ev = parse(burp_xml(issue))["findings"][0]["evidence"][0]
    assert ev["response"].endswith(TRUNCATED)
    assert len(ev["response"]) < 201_000
    assert validate_evidence({**ev, "source": "import"})[1] == {}


def test_long_title_and_text_are_clipped():
    title = "T" * 500 + "\nsecond line"
    issue = (f"<issue><type>1</type><name>{title}</name><host>https://h</host><path>/</path>"
             f"<severity>High</severity><issueBackground>{'x' * (LONG + 50)}</issueBackground></issue>")
    finding = parse(burp_xml(issue))["findings"][0]
    assert len(finding["title"]) == SHORT and finding["title"].endswith("…")
    assert "\n" not in finding["title"]
    assert len(finding["description"]) <= LONG
    assert finding["description"].endswith(TRUNCATED)
    assert validate_finding(finding, target_ids_raw=[])[1] == {}


# --------------------------------------------------------------------------- #
# Nessus
# --------------------------------------------------------------------------- #

def test_nessus_mapping():
    res = parse(load("nessus.nessus"))
    assert res["format"] == "nessus"
    assert [(t["name"], t["address"], t["kind"]) for t in res["targets"]] == [
        ("web01.corp.example", "10.0.0.5", "host"), ("10.0.0.6", "10.0.0.6", "host")]
    assert len(res["findings"]) == 3  # "Nessus Scan Information" (severity 0) skipped

    cert = by_title(res, "SSL Certificate Cannot Be Trusted")
    assert cert["severity"] == "medium"
    assert cert["target_keys"] == ["t1", "t2"]
    assert (cert["cvss_version"], cert["cvss_vector"]) == ("3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N")
    assert cert["cwe"] == "CWE-295"
    assert cert["description"].startswith("The SSL certificate for this service cannot be trusted.")
    assert "- web01.corp.example:443/tcp" in cert["technical_details"]
    assert "- 10.0.0.6:8443/tcp" in cert["technical_details"]
    assert "```\n|-Subject : CN=10.0.0.6\n```" in cert["technical_details"]
    assert cert["refs"].split("\n") == ["https://www.itu.int/rec/T-REC-X.509/en", "https://en.wikipedia.org/wiki/X.509"]

    ssh = by_title(res, "OpenSSH < 9.8 RCE (regreSSHion)")
    assert ssh["severity"] == "critical"
    assert ssh["cvss_version"] == "3.1"
    assert "CVE-2024-6387" in ssh["refs"]

    snmp = by_title(res, "SNMP Agent Default Community Name (public)")
    assert snmp["severity"] == "high"
    # invalid v3 vector -> falls back to the valid v2 one
    assert (snmp["cvss_version"], snmp["cvss_vector"]) == ("2.0", "AV:N/AC:L/Au:N/C:P/I:N/A:N")
    assert snmp["cwe"] == ""  # "NVD-CWE-noinfo" is not a CWE id


def test_nessus_include_info_and_solution_na():
    res = parse(load("nessus.nessus"), include_info=True)
    info = by_title(res, "Nessus Scan Information")
    assert info["severity"] == "info"
    assert info["remediation"] == ""


def test_nessus_long_plugin_output_truncated():
    out = "line\n" * 10_000
    doc = (f'<NessusClientData_v2><Report><ReportHost name="h"><HostProperties/>'
           f'<ReportItem port="1" protocol="tcp" severity="1" pluginID="1" pluginName="P">'
           f"<plugin_output>{out}</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>")
    finding = parse(doc.encode())["findings"][0]
    assert TRUNCATED in finding["technical_details"]
    assert len(finding["technical_details"]) < len(out)


# --------------------------------------------------------------------------- #
# Nmap
# --------------------------------------------------------------------------- #

def test_nmap_targets_only():
    res = parse(load("nmap.xml"))
    assert res["findings"] == []
    assert res["warnings"] == []
    assert [(t["name"], t["address"]) for t in res["targets"]] == [
        ("web01.corp.example", "10.0.0.5"), ("fd00::7", "fd00::7")]
    desc = res["targets"][0]["description"]
    assert desc.startswith("| Port | State | Service | Version |\n|---|---|---|---|")
    assert "| 22/tcp | open | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 Ubuntu Linux; protocol 2.0 |" in desc
    assert "3306" not in desc  # filtered ports are not listed
    assert "open\\|filtered" in desc  # pipes escaped for the table renderer
    assert "Weird\\|Server" in res["targets"][1]["description"]


def test_nmap_no_hosts_up_warns():
    res = parse(load("nmap_down.xml"))
    assert res["targets"] == []
    assert any("No hosts" in w for w in res["warnings"])


# --------------------------------------------------------------------------- #
# ZAP
# --------------------------------------------------------------------------- #

def test_zap_mapping():
    res = parse(load("zap.xml"))
    assert [t["address"] for t in res["targets"]] == ["https://app.example.com", "https://api.example.com"]
    assert len(res["findings"]) == 2  # info skipped, false positive skipped
    assert any("false positive" in w for w in res["warnings"])

    csp = by_title(res, "Content Security Policy (CSP) Header Not Set")
    assert (csp["severity"], csp["confidence"], csp["cwe"]) == ("medium", "certain", "CWE-693")
    assert csp["target_keys"] == ["t1", "t2"]  # grouped across sites
    assert "&" in csp["description"] and "<p>" not in csp["description"]
    assert "- GET https://api.example.com/docs" in csp["technical_details"]
    assert "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP" in csp["refs"].split("\n")
    assert "https://owasp.org/www-community/controls/Content_Security_Policy" in csp["refs"].split("\n")

    xss = by_title(res, "Cross Site Scripting (Reflected)")
    assert (xss["severity"], xss["confidence"]) == ("high", "probable")
    assert "(param: q, attack: <script>alert(1);</script>" in xss["technical_details"]
    assert "- Use a vetted library.\n- Encode output." in xss["remediation"]


def test_zap_include_info_and_instance_cap():
    info = by_title(parse(load("zap.xml"), include_info=True), "Information Disclosure - Suspicious Comments")
    assert (info["severity"], info["confidence"]) == ("info", "unknown")

    instances = "".join(f"<instance><uri>https://h/{i}</uri><method>GET</method></instance>" for i in range(60))
    doc = (f'<OWASPZAPReport><site name="https://h"><alerts><alertitem><pluginid>1</pluginid><alert>A</alert>'
           f"<riskcode>1</riskcode><confidence>2</confidence><instances>{instances}</instances>"
           f"<count>75</count><cweid>-1</cweid></alertitem></alerts></site></OWASPZAPReport>")
    finding = parse(doc.encode())["findings"][0]
    assert finding["technical_details"].count("- GET ") == 50
    assert finding["technical_details"].endswith("- and 25 more")
    assert finding["cwe"] == ""


# --------------------------------------------------------------------------- #
# OpenVAS
# --------------------------------------------------------------------------- #

def test_openvas_mapping():
    res = parse(load("openvas.xml"))
    assert [(t["name"], t["address"]) for t in res["targets"]] == [("srv1.lan", "192.168.10.5"),
                                                                    ("192.168.10.6", "192.168.10.6")]
    assert len(res["findings"]) == 3  # Log result skipped

    tls = by_title(res, "SSL/TLS: Report Vulnerable Cipher Suites for HTTPS")
    assert tls["severity"] == "high"
    assert tls["target_keys"] == ["t1", "t2"]
    assert tls["cvss_version"] == "3.1"
    assert tls["impact"] == "An attacker might decrypt traffic."
    assert tls["remediation"].startswith("The configuration of this services")
    assert "Affected software:" in tls["description"]
    assert "- srv1.lan:443/tcp" in tls["technical_details"] and "```\nTLS_RSA" in tls["technical_details"]
    assert tls["refs"].split("\n") == ["CVE-2016-2183", "https://sweet32.info/", "CB-K17/1750"]

    http = by_title(res, "Cleartext Transmission of Sensitive Information via HTTP")
    assert (http["severity"], http["cvss_version"], http["cvss_vector"]) == ("medium", "2.0",
                                                                          "AV:A/AC:L/Au:N/C:P/I:P/A:N")
    assert http["remediation"].startswith("Enforce the transmission")  # from the tag

    ftp = by_title(res, "FTP Unencrypted Cleartext Login")
    assert (ftp["severity"], ftp["cvss_version"], ftp["cvss_vector"]) == ("low", "", "")
    assert any("CVSS vector ignored" in w for w in res["warnings"])


def test_openvas_include_info():
    res = parse(load("openvas.xml"), include_info=True)
    assert by_title(res, "OS Detection Consolidation and Reporting")["severity"] == "info"


# --------------------------------------------------------------------------- #
# Hostile / invalid input
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("filename", ["billion_laughs.xml", "xxe.xml"])
def test_entities_rejected(filename):
    with pytest.raises(ImportError_, match="entities"):
        parse(load(filename))


def test_entities_rejected_in_utf16():
    data = load("billion_laughs.xml").decode().replace('<?xml version="1.0"?>', "").encode("utf-16")
    with pytest.raises(ImportError_, match="entities"):
        parse(data)


def test_exotic_encoding_rejected():
    with pytest.raises(ImportError_, match="encoding"):
        parse(b'<?xml version="1.0" encoding="UTF-7"?><issues/>')


def test_not_xml_rejected():
    with pytest.raises(ImportError_, match="not valid XML"):
        parse(load("not_xml.txt"))
    with pytest.raises(ImportError_, match="empty"):
        parse(b"   ")


def test_wrong_root_rejected():
    with pytest.raises(ImportError_, match="Unrecognised"):
        parse(load("wrong_root.xml"))


def test_oversize_rejected(monkeypatch):
    monkeypatch.setattr(importers, "MAX_BYTES", 100)
    with pytest.raises(ImportError_, match="too large"):
        parse(b"<issues>" + b" " * 200 + b"</issues>")


def test_old_expat_rejected(monkeypatch):
    monkeypatch.setattr(importers.pyexpat, "version_info", (2, 4, 0))
    with pytest.raises(ImportError_, match="expat"):
        parse(load("burp.xml"))


def test_html_to_text():
    text, links = importers.html_to_text(
        '<p>Intro &amp; more</p><style>x{}</style><ul><li>one</li><li><a href="https://e.x/a">two</a></li></ul>'
        "<pre>  keep\n  spacing</pre>a<br>b")
    assert text == "Intro & more\n\n- one\n- two\n\n```\n  keep\n  spacing\n```\n\na\nb"
    assert links == ["https://e.x/a"]


# --------------------------------------------------------------------------- #
# Everything produced must pass the regular validators
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("include_info", [False, True])
@pytest.mark.parametrize("filename", [*SAMPLES.values(), "nmap_down.xml"])
def test_every_item_passes_validators(filename, include_info):
    res = parse(load(filename), include_info=include_info)
    assert set(res) == {"format", "targets", "findings", "warnings"}
    target_keys = {t["key"] for t in res["targets"]}
    for target in res["targets"]:
        assert target["kind"] in TARGET_KINDS
        _clean, errors = validate_target(target)
        assert errors == {}, (target, errors)
    for finding in res["findings"]:
        assert finding["severity"] in SEVERITIES
        assert finding["confidence"] in ("",) + CONFIDENCE_LEVELS
        assert finding["source"] == res["format"]
        assert set(finding["target_keys"]) <= target_keys
        clean, errors = validate_finding(finding, target_ids_raw=[])
        assert errors == {}, (finding["title"], errors)
        if finding["cvss_version"]:
            assert clean["cvss_score"] is not None
        for ev in finding["evidence"]:
            _clean, errors = validate_evidence({**ev, "source": "import"})
            assert errors == {}, (ev["title"], errors)
