"""Local Gemma 2 Client for Fast, Privacy-Preserving Heuristics.

Interfaces with a local Ollama instance running Gemma 2.
Ideal for quick evaluations such as basic URL classification,
initial telemetry filtering, and lightweight heuristics without cloud exposure.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional
import requests

logger = logging.getLogger(__name__)


class LocalGemmaClient:
    """Client for querying Gemma 2 via a local Ollama instance."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        """Initialize Local Gemma client.

        Args:
            base_url: Ollama API base URL (defaults to env OLLAMA_BASE_URL or http://localhost:11434)
            model: Model name in Ollama (defaults to env OLLAMA_MODEL_GEMMA or 'gemma2')
            timeout: HTTP request timeout in seconds
        """
        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        ).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL_GEMMA", "gemma2")
        self.timeout = timeout

    def is_available(self) -> bool:
        """Check if local Ollama daemon is reachable and responding."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3.0)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        format_json: bool = False,
    ) -> Dict[str, Any]:
        """Generate a response from the local Gemma 2 model.

        Args:
            prompt: User prompt to send to the model.
            system_prompt: Optional system instruction.
            temperature: Sampling temperature (lower = more deterministic).
            format_json: If True, instructs Ollama to format output as valid JSON.

        Returns:
            Dict containing response text and execution metadata.
        """
        endpoint = f"{self.base_url}/api/generate"
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        if system_prompt:
            payload["system"] = system_prompt

        if format_json:
            payload["format"] = "json"

        try:
            response = requests.post(
                endpoint,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "success": True,
                "model": self.model,
                "tier": "local_gemma",
                "response": data.get("response", "").strip(),
                "total_duration_ns": data.get("total_duration", 0),
                "eval_count": data.get("eval_count", 0),
            }
        except requests.ConnectionError as err:
            logger.warning("Local Ollama service unreachable at %s: %s", self.base_url, err)
            return {
                "success": False,
                "model": self.model,
                "tier": "local_gemma",
                "error": f"Ollama connection refused at {self.base_url}. Ensure Ollama is running.",
                "response": "",
            }
        except requests.RequestException as err:
            logger.error("Error communicating with Ollama: %s", err)
            return {
                "success": False,
                "model": self.model,
                "tier": "local_gemma",
                "error": str(err),
                "response": "",
            }

    def classify_url(
        self,
        url: str,
        context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform rapid, privacy-preserving heuristic classification of a URL.

        Args:
            url: The URL string to inspect.
            context: Optional context such as source email domain or anchor text.

        Returns:
            Structured dictionary with risk rating, verdict, and explanation.
        """
        system_instruction = (
            "You are a fast cybersecurity heuristics analyzer. "
            "Analyze the given URL for indicators of phishing, spoofing, malicious redirects, "
            "typosquatting, or benign behavior. Always respond with valid JSON containing: "
            "'verdict' (one of: 'SAFE', 'SUSPICIOUS', 'PHISHING', 'MALICIOUS'), "
            "'risk_score' (0.0 to 1.0), 'reasons' (list of strings), and 'confidence' (0.0 to 1.0)."
        )

        user_content = f"Target URL: {url}"
        if context:
            user_content += f"\nAdditional Context: {context}"

        result = self.generate(
            prompt=user_content,
            system_prompt=system_instruction,
            temperature=0.1,
            format_json=True,
        )

        if not result.get("success"):
            return {
                "url": url,
                "verdict": "UNKNOWN",
                "risk_score": 0.5,
                "confidence": 0.0,
                "error": result.get("error"),
                "raw_response": "",
            }

        raw_text = result.get("response", "")
        try:
            parsed = json.loads(raw_text)
            return {
                "url": url,
                "verdict": parsed.get("verdict", "SUSPICIOUS"),
                "risk_score": float(parsed.get("risk_score", 0.5)),
                "reasons": parsed.get("reasons", []),
                "confidence": float(parsed.get("confidence", 0.8)),
                "raw_response": raw_text,
                "tier": "local_gemma",
            }
        except json.JSONDecodeError:
            # Fallback if model returned text without strict JSON formatting
            verdict = "SUSPICIOUS"
            upper = raw_text.upper()
            if "SAFE" in upper and "PHISHING" not in upper and "MALICIOUS" not in upper:
                verdict = "SAFE"
            elif "PHISHING" in upper:
                verdict = "PHISHING"
            elif "MALICIOUS" in upper:
                verdict = "MALICIOUS"

            return {
                "url": url,
                "verdict": verdict,
                "risk_score": 0.5,
                "reasons": [raw_text],
                "confidence": 0.6,
                "raw_response": raw_text,
                "tier": "local_gemma",
            }

