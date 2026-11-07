import pytest
from app.services.vuln_scanner import SECURITY_HEADERS_POLICY, VERSION_PATTERN


def test_security_headers_policy():
    assert "Strict-Transport-Security" in SECURITY_HEADERS_POLICY
    assert "Content-Security-Policy" in SECURITY_HEADERS_POLICY
    assert "X-Frame-Options" in SECURITY_HEADERS_POLICY
    assert "X-Content-Type-Options" in SECURITY_HEADERS_POLICY

    assert SECURITY_HEADERS_POLICY["Strict-Transport-Security"]["severity"] == "HIGH"
    assert SECURITY_HEADERS_POLICY["Content-Security-Policy"]["severity"] == "HIGH"


def test_version_pattern_regex():
    matches = VERSION_PATTERN.findall("Apache/2.4.52 (Ubuntu)")
    assert len(matches) > 0
    assert matches[0][0] == "Apache"
    assert matches[0][1] == "2.4.52"

    php_matches = VERSION_PATTERN.findall("PHP/8.1.2-1ubuntu2.14")
    assert len(php_matches) > 0
    assert php_matches[0][0] == "PHP"


def test_scan_headers_invalid_host():
    from app.services.vuln_scanner import scan_headers
    result = scan_headers("http://invalid-nonexistent-domain-test12345.xyz", timeout=1.0)
    assert result["success"] is False
    assert result["vulnerability_score"] == 1.0
    assert "Strict-Transport-Security" in result["missing_headers"]
    assert len(result["findings"]) > 0

