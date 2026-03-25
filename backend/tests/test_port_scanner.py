from app.port_scanner import _parse_nmap_xml_output
from app.vuln_lookup import build_risk_summary, cvss_to_severity


def test_parse_nmap_xml_output_extracts_service_metadata():
    xml_output = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open" />
            <service name="http" product="nginx" version="1.28.2" method="probed" conf="10" />
          </port>
          <port protocol="tcp" portid="22">
            <state state="closed" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    result = _parse_nmap_xml_output(xml_output, [80, 22])

    assert result["ports"] == {80: True, 22: False}
    assert len(result["items"]) == 1
    assert result["items"][0]["port"] == 80
    assert result["items"][0]["service"]["product"] == "nginx"
    assert result["items"][0]["service"]["version"] == "1.28.2"


def test_cvss_to_severity_uses_expected_bands():
    assert cvss_to_severity(9.8) == "Critical"
    assert cvss_to_severity(7.5) == "High"
    assert cvss_to_severity(5.4) == "Medium"
    assert cvss_to_severity(2.1) == "Low"


def test_build_risk_summary_picks_highest_score():
    summary = build_risk_summary(
        [
            {"id": "CVE-1", "cvss": 5.3},
            {"id": "CVE-2", "cvss": 9.8},
        ]
    )

    assert summary["cve_count"] == 2
    assert summary["highest_cvss"] == 9.8
    assert summary["severity"] == "Critical"
