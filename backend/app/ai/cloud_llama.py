"""Cloud Llama 3.3 70B Client (via Groq API).

Interfaces with the Groq API running Llama 3.3 70B for high-throughput,
deep reasoning tasks such as:
- Analyzing obfuscated and weaponized JavaScript
- Synthesizing full threat intelligence reports from disparate telemetry
- Multi-step forensic deduction and code deobfuscation
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# Official Groq Model ID for Llama 3.3 70B
DEFAULT_LLAMA_MODEL = "llama-3.3-70b-versatile"


class CloudLlamaClient:
    """Client for high-performance deep reasoning using Llama 3.3 70B on Groq."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        """Initialize the Cloud Llama client.

        Args:
            api_key: Groq API key (defaults to env GROQ_API_KEY).
            model: Model identifier on Groq (defaults to 'llama-3.3-70b-versatile').
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = model or os.getenv("GROQ_LLAMA_MODEL", DEFAULT_LLAMA_MODEL)
        self.timeout = timeout
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazily initialize and return the Groq SDK client."""
        if self._client is not None:
            return self._client

        if not self.api_key:
            raise ValueError(
                "GROQ_API_KEY is not set. Please provide it or set the GROQ_API_KEY environment variable."
            )

        try:
            from groq import Groq

            self._client = Groq(api_key=self.api_key, timeout=self.timeout)
            return self._client
        except ImportError as exc:
            raise ImportError(
                "The 'groq' package is required. Install it using 'pip install groq'."
            ) from exc

    def is_configured(self) -> bool:
        """Check if an API key is available for Groq."""
        return bool(self.api_key or os.getenv("GROQ_API_KEY"))

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        response_format: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Send a completion prompt to Llama 3.3 70B on Groq.

        Args:
            prompt: User query / code / payload.
            system_prompt: Optional system instructions guiding reasoning.
            temperature: Sampling temperature (0.0 to 1.0).
            max_tokens: Maximum tokens in completion.
            response_format: Optional dict, e.g. {"type": "json_object"}.

        Returns:
            Dict containing response text and execution metadata.
        """
        if not self.is_configured():
            return {
                "success": False,
                "model": self.model,
                "tier": "cloud_llama",
                "error": "GROQ_API_KEY is missing. Configure GROQ_API_KEY to enable cloud reasoning.",
                "response": "",
            }

        try:
            client = self._get_client()

            messages: List[Dict[str, str]] = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs: Dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if response_format:
                kwargs["response_format"] = response_format

            chat_completion = client.chat.completions.create(**kwargs)
            choice = chat_completion.choices[0]
            usage = chat_completion.usage

            return {
                "success": True,
                "model": self.model,
                "tier": "cloud_llama",
                "response": choice.message.content or "",
                "finish_reason": choice.finish_reason,
                "prompt_tokens": getattr(usage, "prompt_tokens", None) if usage else None,
                "completion_tokens": getattr(usage, "completion_tokens", None) if usage else None,
                "total_tokens": getattr(usage, "total_tokens", None) if usage else None,
            }
        except Exception as err:
            logger.error("Failed to query Groq Llama 3.3 70B: %s", err)
            return {
                "success": False,
                "model": self.model,
                "tier": "cloud_llama",
                "error": str(err),
                "response": "",
            }

    def analyze_obfuscated_javascript(
        self,
        code: str,
        context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform deep security reasoning on potentially malicious, obfuscated JavaScript.

        Args:
            code: Obfuscated JavaScript snippet or payload.
            context: Additional context (e.g. source page URL, injection point, DOM state).

        Returns:
            Detailed breakdown including identified obfuscation layers, decoded logic,
            threat severity, and indicators.
        """
        system_instruction = (
            "You are a Tier-3 Cybersecurity Reverse Engineer and Code Forensics Expert. "
            "Your objective is to deconstruct obfuscated JavaScript code, decode hidden strings, "
            "identify anti-analysis and evasion tricks, unpack payload logic, and assess potential harm. "
            "Output your findings as valid JSON with the following structure:\n"
            "{\n"
            '  "is_malicious": boolean,\n'
            '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN",\n'
            '  "obfuscation_techniques": ["e.g., String array rotation", "Eval unpacking"],\n'
            '  "decoded_intent": "clear explanation of what the script attempts to do",\n'
            '  "suspicious_apis_used": ["e.g., document.cookie", "fetch", "WebSocket"],\n'
            '  "indicators_of_compromise": ["domains", "IPs", "signatures"],\n'
            '  "deobfuscated_code_sample": "reconstructed pseudo-code or clean representation",\n'
            '  "mitigation_advice": "recommended defensive response"\n'
            "}"
        )

        user_content = f"### OBFUSCATED JAVASCRIPT PAYLOAD:\n```javascript\n{code}\n```"
        if context:
            user_content += f"\n\n### CONTEXT:\n{context}"

        result = self.generate(
            prompt=user_content,
            system_prompt=system_instruction,
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        if not result.get("success"):
            return {
                "success": False,
                "tier": "cloud_llama",
                "error": result.get("error"),
                "raw_response": "",
            }

        raw_text = result.get("response", "")
        try:
            parsed = json.loads(raw_text)
            parsed["tier"] = "cloud_llama"
            parsed["model"] = self.model
            parsed["success"] = True
            return parsed
        except json.JSONDecodeError:
            return {
                "success": True,
                "tier": "cloud_llama",
                "model": self.model,
                "raw_response": raw_text,
                "is_malicious": True,
                "severity": "HIGH",
                "decoded_intent": raw_text,
            }

    def synthesize_threat_report(
        self,
        raw_signals: Union[Dict[str, Any], str],
        context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synthesize multiple forensic signals into a cohesive Threat Intelligence Report.

        Args:
            raw_signals: Telemetry data, heuristic verdicts, network traces, or raw text.
            context: Optional asset or campaign context.

        Returns:
            Comprehensive threat report with executive summary, MITRE ATT&CK mapping,
            IOC list, and actionable remediations.
        """
        system_instruction = (
            "You are a Lead Threat Intelligence Analyst. Synthesize the provided multi-source "
            "security signals into a structured Threat Report. "
            "Provide your response formatted strictly as valid JSON with the following keys:\n"
            "{\n"
            '  "report_title": string,\n'
            '  "executive_summary": string,\n'
            '  "threat_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n'
            '  "attack_vectors": [string],\n'
            '  "mitre_attack_tactics": [{"tactic": string, "technique_id": string, "name": string}],\n'
            '  "indicators_of_compromise": [{"type": "URL|IP|DOMAIN|HASH|STRING", "value": string, "description": string}],\n'
            '  "incident_timeline": [string],\n'
            '  "recommended_actions": [string]\n'
            "}"
        )

        if isinstance(raw_signals, dict):
            signals_str = json.dumps(raw_signals, indent=2)
        else:
            signals_str = str(raw_signals)

        prompt = f"### RAW SECURITY SIGNALS & TELEMETRY:\n{signals_str}"
        if context:
            prompt += f"\n\n### INVESTIGATION CONTEXT:\n{context}"

        result = self.generate(
            prompt=prompt,
            system_prompt=system_instruction,
            temperature=0.2,
            response_format={"type": "json_object"},
        )

        if not result.get("success"):
            return {
                "success": False,
                "tier": "cloud_llama",
                "error": result.get("error"),
                "raw_response": "",
            }

        raw_text = result.get("response", "")
        try:
            parsed = json.loads(raw_text)
            parsed["tier"] = "cloud_llama"
            parsed["model"] = self.model
            parsed["success"] = True
            return parsed
        except json.JSONDecodeError:
            return {
                "success": True,
                "tier": "cloud_llama",
                "model": self.model,
                "raw_response": raw_text,
                "report_title": "Automated Security Assessment",
                "executive_summary": raw_text,
            }

