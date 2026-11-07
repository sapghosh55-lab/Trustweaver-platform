"""AI Module for TrustWeaver Platform.

Provides a dual-tier LLM routing architecture:
- Local Tier: Gemma 2 via Ollama for fast, privacy-preserving heuristics (URL classification, quick checks).
- Cloud Tier: Llama 3.3 70B via Groq for deep reasoning (obfuscated JavaScript analysis, threat report synthesis).
- Semantic Router: Sentence Transformers computing cosine similarity to route requests based on task complexity.
"""

from app.ai.cloud_llama import CloudLlamaClient
from app.ai.local_gemma import LocalGemmaClient
from app.ai.semantic_router import (
    RouteDecision,
    RouteTarget,
    SemanticRouter,
)

__all__ = [
    "LocalGemmaClient",
    "CloudLlamaClient",
    "SemanticRouter",
    "RouteDecision",
    "RouteTarget",
]
