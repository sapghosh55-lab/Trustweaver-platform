"""Threat Intelligence Aggregator & Digital Trust Score Generator.

Aggregates findings from:
1. phishing_analyzer.py (Credential harvesting & Brand impersonation)
2. cert_validator.py (Weak crypto & Compromised CAs / eMudhra incident)
3. vuln_scanner.py (Missing security headers & Exposed service versions)

Passes the aggregated multi-source security telemetry through the Semantic Router
to the Groq LLM (Llama 3.3 70B) to produce a unified JSON "Digital Trust Score" report.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from app.ai.semantic_router import SemanticRouter

logger = logging.getLogger(__name__)


def calculate_base_trust_score(
    phishing_risk: float,
    cert_risk: float,
    vuln_risk: float,
) -> Dict[str, Any]:
    """Calculate composite mathematical digital trust score (0 - 100)."""
    # Weighted risk deduction:
    # Phishing carries 50% weight (immediate user harm)
    # SSL/Cert carries 30% weight (transport integrity & trust store compliance)
    # Header/Vuln carries 20% weight (surface hardening & information disclosure)
    weighted_risk = (phishing_risk * 0.50) + (cert_risk * 0.30) + (vuln_risk * 0.20)
    trust_score = max(0, min(100, int(round((1.0 - weighted_risk) * 100))))

    # Assign Trust Grade
    if trust_score >= 90:
        grade = "A"
        verdict = "TRUSTED"
    elif trust_score >= 75:
        grade = "B"
        verdict = "GENERALLY_SAFE"
    elif trust_score >= 60:
        grade = "C"
        verdict = "SUSPICIOUS"
    elif trust_score >= 40:
        grade = "D"
        verdict = "HIGH_RISK"
    else:
        grade = "F"
        verdict = "MALICIOUS" if phishing_risk > 0.6 or cert_risk > 0.6 else "DANGEROUS"

    return {
        "digital_trust_score": trust_score,
        "trust_grade": grade,
        "verdict": verdict,
        "component_breakdown": {
            "phishing_hygiene_score": int(round((1.0 - phishing_risk) * 100)),
            "ssl_tls_security_score": int(round((1.0 - cert_risk) * 100)),
            "header_hardening_score": int(round((1.0 - vuln_risk) * 100)),
        },
    }


def generate_digital_trust_report(
    url: str,
    phishing_data: Dict[str, Any],
    cert_data: Dict[str, Any],
    vuln_data: Dict[str, Any],
    router: Optional[SemanticRouter] = None,
) -> Dict[str, Any]:
    """Aggregate security modules and generate unified Digital Trust Score report via Groq LLM.

    Args:
        url: The analyzed URL.
        phishing_data: Output dictionary from phishing_analyzer.
        cert_data: Output dictionary from cert_validator.
        vuln_data: Output dictionary from vuln_scanner.
        router: Optional SemanticRouter instance.

    Returns:
        Unified Digital Trust Score report with executive synthesis, MITRE tactics,
        and prioritized recommendations.
    """
    router = router or SemanticRouter()

    # 1. Extract risk scores
    phishing_risk = float(phishing_data.get("phishing_risk_score", 0.0))
    cert_risk = float(cert_data.get("cert_risk_score", 0.0))
    vuln_risk = float(vuln_data.get("vulnerability_risk_score", 0.0))

    score_meta = calculate_base_trust_score(phishing_risk, cert_risk, vuln_risk)

    # 2. Compile Critical Red Flags
    critical_flags: List[str] = []
    critical_flags.extend(phishing_data.get("red_flags", []))
    critical_flags.extend(cert_data.get("all_flags", []))

    for m in vuln_data.get("missing_headers", []):
        if m.get("severity") == "HIGH":
            critical_flags.append(f"Missing Critical Security Header: {m.get('header')} ({m.get('alias')})")

    for tech in vuln_data.get("exposed_technologies", []):
        if tech.get("exact_version_disclosed"):
            critical_flags.append(f"Exposed Server/Software Version: {', '.join(tech.get('disclosed_versions', []))}")

    # 3. Construct telemetry package for semantic routing to Groq LLM
    telemetry_package = {
        "url": url,
        "base_trust_score": score_meta["digital_trust_score"],
        "base_grade": score_meta["trust_grade"],
        "phishing_findings": {
            "verdict": phishing_data.get("verdict"),
            "risk_score": phishing_risk,
            "credential_harvesting": phishing_data.get("credential_harvesting", {}).get("detected"),
            "brand_impersonation": phishing_data.get("brand_impersonation", {}).get("detected"),
            "impersonated_brands": [b.get("brand") for b in phishing_data.get("brand_impersonation", {}).get("brands", [])],
        },
        "ssl_tls_findings": {
            "verdict": cert_data.get("verdict"),
            "risk_score": cert_risk,
            "issuer": cert_data.get("issuer"),
            "compromised_ca_alerts": cert_data.get("compromised_ca_alerts", []),
            "weak_cryptography": cert_data.get("weak_cryptography_flags", []),
        },
        "vulnerability_findings": {
            "verdict": vuln_data.get("verdict"),
            "risk_score": vuln_risk,
            "missing_headers": [h.get("header") for h in vuln_data.get("missing_headers", [])],
            "exposed_technologies": [t.get("raw_value") for t in vuln_data.get("exposed_technologies", [])],
        },
        "red_flags": critical_flags,
    }

    prompt_for_llm = (
        f"Synthesize comprehensive cyber threat intelligence report and Digital Trust Score for {url}.\n"
        f"Telemetry:\n{json.dumps(telemetry_package, indent=2)}"
    )

    # 4. Route through SemanticRouter to Groq LLM
    # Synthesizing threat intelligence reports matches complex security benchmarks, routing to Cloud Llama 3.3 70B
    routing_decision = router.route(prompt_for_llm)
    ai_execution = router.execute(
        text=prompt_for_llm,
        task_hint="threat_report",
    )

    # 5. Extract or merge LLM threat synthesis
    llm_report = ai_execution if isinstance(ai_execution, dict) else {}
    executive_summary = (
        llm_report.get("executive_summary")
        or llm_report.get("response")
        or "Analysis completed based on real-time DOM, TLS certificate, and HTTP header auditing."
    )
    mitre_tactics = llm_report.get("mitre_attack_tactics", [])
    recommendations = llm_report.get("recommended_actions", [])

    # Default fallback recommendations if LLM returned unstructured response
    if not recommendations:
        if phishing_data.get("brand_impersonation", {}).get("detected"):
            recommendations.append("Block domain immediately; alert users regarding credential phishing impersonation.")
        if cert_data.get("compromised_ca_alerts"):
            recommendations.append("Revoke and re-issue certificate through a trusted browser-compliant Root Certificate Authority.")
        if any(h.get("header") == "Strict-Transport-Security" for h in vuln_data.get("missing_headers", [])):
            recommendations.append("Enable HTTP Strict Transport Security (HSTS) with 'max-age=31536000; includeSubDomains'.")
        if any(h.get("header") == "Content-Security-Policy" for h in vuln_data.get("missing_headers", [])):
            recommendations.append("Deploy a restrictive Content-Security-Policy (CSP) to neutralize cross-site scripting vectors.")

    return {
        "report_id": f"DTS-{hash(url) & 0xffffffff:08x}",
        "target_url": url,
        "digital_trust_score": score_meta["digital_trust_score"],
        "trust_grade": score_meta["trust_grade"],
        "overall_verdict": score_meta["verdict"],
        "component_scores": score_meta["component_breakdown"],
        "executive_summary": executive_summary,
        "critical_red_flags": critical_flags,
        "mitre_attack_tactics": mitre_tactics,
        "recommendations": recommendations,
        "routing_intelligence": {
            "tier_selected": routing_decision.target.value,
            "complexity_score": round(routing_decision.complexity_score, 4),
            "matched_prototype": routing_decision.matched_prototype,
            "ai_success": llm_report.get("success", True),
        },
        "raw_telemetry": {
            "phishing_analysis": phishing_data,
            "certificate_validation": cert_data,
            "vulnerability_scan": vuln_data,
        },
    }

