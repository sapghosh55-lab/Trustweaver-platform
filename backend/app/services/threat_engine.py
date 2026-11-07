"""Threat Engine Service.

Coordinates URL heuristic evaluation, DOM script inspection, payload hashing,
and semantic LLM routing between Local Gemma 2 and Cloud Llama 3.3 70B.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.ai.cloud_llama import CloudLlamaClient
from app.ai.local_gemma import LocalGemmaClient
from app.ai.semantic_router import RouteTarget, SemanticRouter
from app.services.crypto_service import CryptoService
from app.services.url_service import URLService

logger = logging.getLogger(__name__)


class ThreatEngine:
    """Unified threat evaluation engine."""

    def __init__(
        self,
        url_service: Optional[URLService] = None,
        crypto_service: Optional[CryptoService] = None,
        semantic_router: Optional[SemanticRouter] = None,
    ) -> None:
        self.url_service = url_service or URLService()
        self.crypto_service = crypto_service or CryptoService()
        self.router = semantic_router or SemanticRouter()

    def evaluate_url_comprehensive(
        self,
        url: str,
        deep_scan_dom: bool = True,
    ) -> Dict[str, Any]:
        """Perform end-to-end evaluation of a URL.

        1. Computes cryptographic payload hash
        2. Evaluates static URL heuristics
        3. If deep_scan_dom is enabled, fetches DOM and extracts scripts
        4. Semantically evaluates scripts/threat and routes to Local Gemma or Cloud Llama
        """
        url_hash = self.crypto_service.hash_payload(url)

        # 1. Static URL analysis
        static_analysis = self.url_service.analyze_url_structure(url)
        heuristic_score = static_analysis["heuristic_risk_score"]

        # 2. Heuristic classification via Local Gemma (Fast & Privacy-preserving)
        local_classification = self.router.local_client.classify_url(
            url=url,
            context=f"Static flags: {', '.join(static_analysis['flags'])}",
        )

        result: Dict[str, Any] = {
            "url": url,
            "url_hash_sha256": url_hash,
            "static_heuristics": static_analysis,
            "local_gemma_verdict": local_classification,
            "deep_analysis": None,
            "overall_verdict": local_classification.get("verdict", "SUSPICIOUS"),
            "risk_score": max(heuristic_score, local_classification.get("risk_score", 0.0)),
        }

        # 3. If deep scan is enabled and high risk or scripts present, analyze DOM
        if deep_scan_dom:
            dom_data = self.url_service.fetch_and_extract_dom(url)
            result["dom_metrics"] = {
                "success": dom_data["success"],
                "total_scripts": dom_data.get("total_scripts", 0),
                "forms_count": len(dom_data.get("forms", [])),
                "iframes_count": len(dom_data.get("iframes", [])),
            }

            # Find potentially obfuscated inline scripts
            suspicious_scripts = []
            for s in dom_data.get("scripts", []):
                code = s.get("full_code") or ""
                if any(ind in code for ind in ["eval(", "unescape(", "fromCharCode", "\\x", "\\u"]):
                    suspicious_scripts.append(code)

            if suspicious_scripts:
                # Obfuscated code found -> deep reasoning needed -> Cloud Llama 3.3 70B
                logger.info("Suspicious JavaScript patterns detected in DOM. Triggering Cloud Llama analysis.")
                combined_code = "\n/* --- SCRIPT --- */\n".join(suspicious_scripts[:3])
                deep_reasoning = self.router.cloud_client.analyze_obfuscated_javascript(
                    code=combined_code,
                    context=f"Target URL: {url}",
                )
                result["deep_analysis"] = deep_reasoning
                if deep_reasoning.get("is_malicious"):
                    result["overall_verdict"] = "MALICIOUS"
                    result["risk_score"] = 0.95

        return result

    def scan_custom_payload(self, text_or_code: str) -> Dict[str, Any]:
        """Automatically route and inspect arbitrary payloads via Semantic Router."""
        payload_hash = self.crypto_service.hash_payload(text_or_code)
        decision = self.router.route(text_or_code)
        execution = self.router.execute(text_or_code)

        return {
            "payload_sha256": payload_hash,
            "routing": {
                "target": decision.target.value,
                "complexity_score": decision.complexity_score,
                "threshold": decision.threshold,
                "is_complex": decision.is_complex,
                "rationale": decision.rationale,
            },
            "execution": execution,
        }

