from app.main import _build_summary, sanitize_sqlmap_args


def test_sanitize_sqlmap_args_keeps_only_safe_values():
    args = [
        "--level=5",
        "--risk=3",
        "--threads=10",
        "--crawl=1",
        "--tamper=space2comment,between",
        "--batch",
        "--random-agent",
        "--os-shell",
        "--tamper=../../bad",
        "--threads=200",
    ]

    assert sanitize_sqlmap_args(args) == [
        "--level=5",
        "--risk=3",
        "--threads=10",
        "--crawl=1",
        "--tamper=space2comment,between",
        "--batch",
        "--random-agent",
    ]


def test_build_summary_counts_ports_and_findings():
    summary = _build_summary(
        {
            "ports": {"ports": {"80": True, "443": True, "22": False}},
            "crawl": {"urls": ["https://example.com", "https://example.com/login"], "forms": [["https://example.com/login", {"method": "post", "inputs": {"user": ""}}]]},
            "xss": [{"url": "https://example.com?q=test"}],
            "sqli": [{"url": "https://example.com?id=1"}],
            "sqlmap": {"findings": [{"url": "https://example.com?id=1", "message": "vulnerable"}]},
        }
    )

    assert summary["open_ports"] == [80, 443]
    assert summary["open_port_count"] == 2
    assert summary["url_count"] == 2
    assert summary["form_count"] == 1
    assert summary["xss_count"] == 1
    assert summary["sqli_count"] == 1
    assert summary["sqlmap_count"] == 1
