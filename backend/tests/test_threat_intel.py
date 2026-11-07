import pytest
from app.services.threat_intel import (
    calculate_base_trust_score,
    generate_digital_trust_report,
    publish_threat_on_chain,
)


def test_calculate_base_trust_score_clean():
    # 0 risk across all three dimensions
    score = calculate_base_trust_score(
        phishing_risk=0.0,
        cert_risk=0.0,
        vuln_risk=0.0,
    )
    assert score["digital_trust_score"] == 100
    assert score["trust_grade"] == "A"
    assert score["verdict"] == "TRUSTED"
    assert score["component_breakdown"]["phishing_hygiene_score"] == 100


def test_calculate_base_trust_score_critical_phishing():
    # Phishing high risk
    score = calculate_base_trust_score(
        phishing_risk=0.95,
        cert_risk=0.50,
        vuln_risk=0.60,
    )
    assert score["digital_trust_score"] <= 35
    assert score["trust_grade"] == "F"
    assert score["verdict"] in ["MALICIOUS", "DANGEROUS"]


def test_publish_threat_on_chain():
    result = publish_threat_on_chain(
        url="https://phishing-paypal-portal.xyz/login",
        threat_score=85,
        ipfs_hash="QmSampleCID1234567890abcdef1234567890abcdef12",
    )

    assert result["published"] is True
    assert "tx_hash" in result
    assert result["tx_hash"].startswith("0x")
    assert len(result["tx_hash"]) == 66


def test_generate_digital_trust_report_includes_tx_hash_for_critical_threat():
    # Simulate a critical phishing attack
    phishing_data = {
        "url": "http://microsoft-login-fake.top/login",
        "verdict": "PHISHING",
        "phishing_risk_score": 0.98,
        "credential_harvesting": {"detected": True},
        "brand_impersonation": {"detected": True, "brands": [{"brand": "Microsoft"}]},
        "red_flags": ["Critical Phishing Kit"],
    }
    cert_data = {
        "verdict": "DANGEROUS",
        "cert_risk_score": 0.85,
        "compromised_ca_alerts": [{"ca_name": "eMudhra"}],
        "all_flags": ["Compromised CA detected"],
    }
    vuln_data = {
        "verdict": "POOR",
        "vulnerability_risk_score": 0.70,
        "missing_headers": [{"header": "Strict-Transport-Security", "severity": "HIGH"}],
        "exposed_technologies": [],
    }

    report = generate_digital_trust_report(
        url="http://microsoft-login-fake.top/login",
        phishing_data=phishing_data,
        cert_data=cert_data,
        vuln_data=vuln_data,
    )

    assert report["digital_trust_score"] < 30
    assert report["blockchain_tx_hash"] is not None
    assert report["blockchain_tx_hash"].startswith("0x")
    assert report["on_chain_record"]["published"] is True
