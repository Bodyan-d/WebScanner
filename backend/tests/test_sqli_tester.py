from app.sqli_tester import SQLiTester


def test_parse_sqlmap_output_extracts_findings():
    tester = SQLiTester(fetcher=None)
    raw = """
    [INFO] testing connection
    [CRITICAL] parameter 'id' is vulnerable. Do not trust this input.
    payload: id=1 AND 1=1
    [INFO] fetched data logged to text files
    """

    findings = tester._parse_sqlmap_output(raw)

    assert len(findings) == 1
    assert findings[0]["level"] == "CRITICAL"
    assert "parameter 'id' is vulnerable" in findings[0]["detail"]


def test_parse_sqlmap_output_ignores_noise_only_logs():
    tester = SQLiTester(fetcher=None)
    raw = """
    [INFO] testing headers
    [INFO] starting
    [WARNING] all tested parameters do not appear to be injectable
    """

    assert tester._parse_sqlmap_output(raw) == []
