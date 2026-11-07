import pytest
from app.services.cert_validator import (
    FLAGGED_CERTIFICATE_AUTHORITIES,
    extract_host_port,
    validate_certificate,
)


def test_extract_host_port():
    assert extract_host_port("https://example.com") == ("example.com", 443)
    assert extract_host_port("http://example.com") == ("example.com", 80)
    assert extract_host_port("example.com:8443") == ("example.com", 8443)
    assert extract_host_port("example.com") == ("example.com", 443)


def test_emudhra_compromised_ca_detection():
    # Verify that eMudhra is explicitly cataloged as a critical flagged CA
    assert "emudhra" in FLAGGED_CERTIFICATE_AUTHORITIES
    emudhra_entry = FLAGGED_CERTIFICATE_AUTHORITIES["emudhra"]
    assert emudhra_entry["name"] == "eMudhra"
    assert emudhra_entry["severity"] == "CRITICAL"
    assert "eMudhra TLS Compliance" in emudhra_entry["incident"]


def test_validate_certificate_invalid_host():
    result = validate_certificate("invalid-non-existent-domain-12345.xyz", timeout=2.0)
    assert result["connection_success"] is False
    assert result["risk_score"] >= 0.7

