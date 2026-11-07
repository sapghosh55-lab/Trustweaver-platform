"""Semantic Router for Dual-Tier LLM Architecture.

Uses Sentence Transformers to compute cosine similarity between incoming requests
and reference prototypes.

Routing Policy:
- If similarity to complex reasoning tasks is BELOW the threshold:
    -> Classified as SIMPLE -> Route to local_gemma.py (Local Ollama Gemma 2)
- If similarity to complex reasoning tasks meets or exceeds threshold:
    -> Classified as COMPLEX -> Route to cloud_llama.py (Groq Llama 3.3 70B)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from app.ai.cloud_llama import CloudLlamaClient
from app.ai.local_gemma import LocalGemmaClient

logger = logging.getLogger(__name__)

# Default model for sentence embeddings
DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Default similarity threshold for classifying a task as complex
DEFAULT_COMPLEXITY_THRESHOLD = 0.55

# Representative benchmarks for complex security reasoning tasks
DEFAULT_COMPLEX_PROTOTYPES: List[str] = [
    "Analyze obfuscated JavaScript code, decode packed eval routines and unpack payload logic",
    "Reverse engineer malicious scripts, deobfuscate hex strings, base64 payloads, and dynamic DOM injection",
    "Synthesize comprehensive cyber threat intelligence report from multi-source telemetry and IOCs",
    "Perform deep root cause forensics on zero-day exploit and multi-stage attack vectors",
    "Identify advanced persistent threat (APT) campaign indicators, C2 infrastructure, and kill chain tactics",
    "Deep reasoning on cryptographic vulnerability, bypass logic, and weaponized exploit chains",
    "Explain complex memory corruption, buffer overflow, or prototype pollution in source code",
    "Correlate disparate security event logs and generate executive incident response briefing",
]

# Representative benchmarks for simple, fast heuristic tasks (for similarity contrast)
DEFAULT_SIMPLE_PROTOTYPES: List[str] = [
    "Classify whether this URL is safe or phishing",
    "Quick domain categorization and reputation lookup",
    "Fast regex check or simple security header validation",
    "Check if link contains suspicious TLD or IP address",
    "Trivial text categorization and keyword extraction",
    "Simple status check or basic ping response",
]


class RouteTarget(str, Enum):
    """Routing targets for the dual-tier architecture."""

    LOCAL_GEMMA = "local_gemma"
    CLOUD_LLAMA = "cloud_llama"


@dataclass
class RouteDecision:
    """Represents a semantic routing decision."""

    target: RouteTarget
    complexity_score: float
    threshold: float
    is_complex: bool
    matched_prototype: str
    rationale: str
    routing_latency_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class SemanticRouter:
    """Semantic router computing cosine similarity against complexity prototypes."""

    def __init__(
        self,
        model_name: Optional[str] = None,
        threshold: Optional[float] = None,
        complex_prototypes: Optional[List[str]] = None,
        local_client: Optional[LocalGemmaClient] = None,
        cloud_client: Optional[CloudLlamaClient] = None,
    ) -> None:
        """Initialize the Semantic Router.

        Args:
            model_name: Name of SentenceTransformer model (defaults to env or 'all-MiniLM-L6-v2').
            threshold: Similarity threshold to qualify as complex (default: 0.55).
            complex_prototypes: List of complex task descriptions to match against.
            local_client: Pre-configured LocalGemmaClient instance.
            cloud_client: Pre-configured CloudLlamaClient instance.
        """
        self.model_name = (
            model_name
            or os.getenv("SENTENCE_TRANSFORMER_MODEL", DEFAULT_EMBEDDING_MODEL)
        )
        self.threshold = (
            threshold
            if threshold is not None
            else float(os.getenv("AI_ROUTING_THRESHOLD", str(DEFAULT_COMPLEXITY_THRESHOLD)))
        )
        self.complex_prototypes = complex_prototypes or DEFAULT_COMPLEX_PROTOTYPES
        self.local_client = local_client or LocalGemmaClient()
        self.cloud_client = cloud_client or CloudLlamaClient()

        # Lazy-loaded model and cached embeddings
        self._embedder: Any = None
        self._prototype_embeddings: Any = None

    def _get_embedder(self) -> Any:
        """Lazily load SentenceTransformer model."""
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer

                logger.info("Loading SentenceTransformer model: %s", self.model_name)
                self._embedder = SentenceTransformer(self.model_name)
            except ImportError as err:
                raise ImportError(
                    "sentence-transformers is required for semantic routing. "
                    "Install it via: pip install sentence-transformers"
                ) from err
        return self._embedder

    def _get_prototype_embeddings(self) -> Any:
        """Precompute and cache normalized embeddings for complex task prototypes."""
        if self._prototype_embeddings is None:
            embedder = self._get_embedder()
            self._prototype_embeddings = embedder.encode(
                self.complex_prototypes,
                convert_to_tensor=True,
                normalize_embeddings=True,
            )
        return self._prototype_embeddings

    def compute_similarity(self, text: str) -> Tuple[float, str]:
        """Compute highest cosine similarity of incoming text against complex prototypes.

        Args:
            text: Query or code snippet to evaluate.

        Returns:
            Tuple of (highest_similarity_score, best_matching_prototype).
        """
        embedder = self._get_embedder()
        from sentence_transformers import util

        query_embedding = embedder.encode(
            text,
            convert_to_tensor=True,
            normalize_embeddings=True,
        )
        proto_embeddings = self._get_prototype_embeddings()

        # Compute cosine similarity matrix
        cos_scores = util.cos_sim(query_embedding, proto_embeddings)[0]

        best_idx = int(cos_scores.argmax().item())
        best_score = float(cos_scores[best_idx].item())
        matched_proto = self.complex_prototypes[best_idx]

        return best_score, matched_proto

    def route(self, text: str) -> RouteDecision:
        """Determine whether the task is simple or complex based on cosine similarity.

        Args:
            text: Incoming text, prompt, code snippet, or forensic telemetry.

        Returns:
            RouteDecision detailing target tier, score, and decision rationale.
        """
        start_time = time.perf_counter()

        try:
            score, matched_proto = self.compute_similarity(text)
        except Exception as err:
            logger.warning("Failed computing semantic similarity (%s). Defaulting to heuristic fallback.", err)
            # Lightweight heuristic fallback if sentence-transformers is not yet installed or fails
            score = self._heuristic_complexity_score(text)
            matched_proto = "Heuristic fallback evaluation"

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        is_complex = score >= self.threshold

        if is_complex:
            target = RouteTarget.CLOUD_LLAMA
            rationale = (
                f"Task complexity score ({score:.3f}) >= threshold ({self.threshold:.3f}). "
                f"Requires deep reasoning; routing to Cloud Llama 3.3 70B."
            )
        else:
            target = RouteTarget.LOCAL_GEMMA
            rationale = (
                f"Task complexity score ({score:.3f}) < threshold ({self.threshold:.3f}). "
                f"Classified as simple/heuristic; routing to Local Gemma 2 for privacy & speed."
            )

        return RouteDecision(
            target=target,
            complexity_score=score,
            threshold=self.threshold,
            is_complex=is_complex,
            matched_prototype=matched_proto,
            rationale=rationale,
            routing_latency_ms=elapsed_ms,
            metadata={
                "model": self.model_name,
                "input_length": len(text),
            },
        )

    def _heuristic_complexity_score(self, text: str) -> float:
        """Fast keyword/syntax fallback when neural embedder is unavailable."""
        complex_signals = [
            "eval(",
            "unescape(",
            "fromcharcode",
            "atob(",
            "btoa(",
            "document.write",
            "threat report",
            "ioc",
            "mitre attack",
            "deobfuscat",
            "reverse engineer",
            "exploit",
            "payload",
            "shellcode",
        ]
        lower = text.lower()
        matches = sum(1 for signal in complex_signals if signal in lower)
        return min(0.4 + (matches * 0.15), 0.95) if matches > 0 else 0.25

    def execute(
        self,
        text: str,
        system_prompt: Optional[str] = None,
        task_hint: Optional[str] = None,
        fallback_on_error: bool = True,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Route and execute the request against the selected LLM tier.

        Args:
            text: The user text, payload, or URL.
            system_prompt: Optional system instruction.
            task_hint: Optional hint: 'url', 'javascript', 'threat_report', 'general'.
            fallback_on_error: If True, failover to the other tier when primary tier fails.
            **kwargs: Extra parameters passed to the target model.

        Returns:
            Dictionary containing routing metadata and model execution response.
        """
        decision = self.route(text)
        routing_info = {
            "target": decision.target.value,
            "complexity_score": decision.complexity_score,
            "threshold": decision.threshold,
            "is_complex": decision.is_complex,
            "matched_prototype": decision.matched_prototype,
            "rationale": decision.rationale,
            "routing_latency_ms": decision.routing_latency_ms,
        }

        # 1. Route to Local Gemma (Simple tier)
        if decision.target == RouteTarget.LOCAL_GEMMA:
            if task_hint == "url" or (len(text.split()) == 1 and text.startswith(("http://", "https://"))):
                res = self.local_client.classify_url(url=text.strip(), **kwargs)
            else:
                res = self.local_client.generate(prompt=text, system_prompt=system_prompt, **kwargs)

            # Check if local failed and fallback is requested
            if not res.get("success") and fallback_on_error and self.cloud_client.is_configured():
                logger.info("Local Gemma failed; falling back to Cloud Llama 3.3 70B.")
                fallback_res = self.cloud_client.generate(
                    prompt=text,
                    system_prompt=system_prompt,
                    **kwargs,
                )
                fallback_res["fallback_used"] = True
                fallback_res["routing"] = routing_info
                return fallback_res

            res["routing"] = routing_info
            return res

        # 2. Route to Cloud Llama (Complex tier)
        else:
            if task_hint == "javascript" or ("eval(" in text or "function" in text and len(text) > 80):
                res = self.cloud_llama_analysis(text, **kwargs)
            elif task_hint == "threat_report":
                res = self.cloud_client.synthesize_threat_report(raw_signals=text, **kwargs)
            else:
                res = self.cloud_client.generate(prompt=text, system_prompt=system_prompt, **kwargs)

            # Check if cloud failed and fallback is requested
            if not res.get("success") and fallback_on_error and self.local_client.is_available():
                logger.info("Cloud Llama failed; falling back to Local Gemma 2.")
                fallback_res = self.local_client.generate(
                    prompt=text,
                    system_prompt=system_prompt,
                    **kwargs,
                )
                fallback_res["fallback_used"] = True
                fallback_res["routing"] = routing_info
                return fallback_res

            res["routing"] = routing_info
            return res

    def cloud_llama_analysis(self, code: str, **kwargs: Any) -> Dict[str, Any]:
        """Dispatch code payload to Cloud Llama for JavaScript analysis."""
        return self.cloud_client.analyze_obfuscated_javascript(code=code, **kwargs)

