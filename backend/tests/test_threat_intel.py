import pytest
from app.services.threat_intel import calculate_base_trust_score


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
    # Weighted risk = (0.95*0.5) + (0.50*0.3) + (0.60*0.2) = 0.475 + 0.15 + 0.12 = 0.745
    # Trust score ~ 25/100 -> Grade F
    assert score["digital_trust_score"] <= 35
    assert score["trust_grade"] == "F"
    assert score["verdict"] in ["MALICIOUS", "DANGEROUS"]

