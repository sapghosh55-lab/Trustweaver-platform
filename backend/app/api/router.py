from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ai.cloud_llama import CloudLlamaClient
from app.ai.local_gemma import LocalGemmaClient
from app.ai.semantic_router import SemanticRouter
from app.services.threat_engine import ThreatEngine

api_router = APIRouter()

router_instance = SemanticRouter()
local_gemma = LocalGemmaClient()
cloud_llama = CloudLlamaClient()
threat_engine = ThreatEngine(semantic_router=router_instance)


class RouteRequest(BaseModel):
    text: str = Field(..., description="Query, URL, or code payload to route")
    threshold: Optional[float] = Field(None, description="Optional override for complexity threshold")


class AnalyzeRequest(BaseModel):
    text: str = Field(..., description="Text, URL, code, or payload to analyze")
    task_hint: Optional[str] = Field(None, description="'url', 'javascript', 'threat_report', or 'general'")
    system_prompt: Optional[str] = Field(None, description="Optional custom system prompt")


class URLClassifyRequest(BaseModel):
    url: str = Field(..., description="URL to check")
    context: Optional[str] = Field(None, description="Context, anchor text, or referring domain")


class JSAnalyzeRequest(BaseModel):
    code: str = Field(..., description="Obfuscated JavaScript code")
    context: Optional[str] = Field(None, description="Context, origin URL, or DOM position")


class ThreatReportRequest(BaseModel):
    signals: Dict[str, Any] = Field(..., description="Telemetry, observables, or heuristic flags")
    context: Optional[str] = Field(None, description="Investigation scope or target environment")


class ComprehensiveScanRequest(BaseModel):
    url: str = Field(..., description="Target URL for comprehensive scan")
    deep_scan_dom: bool = Field(True, description="Whether to extract and inspect inline scripts and forms")


@api_router.get("/status")
async def get_status():
    return {
        "status": "operational",
        "tiers": {
            "local_gemma": {
                "available": local_gemma.is_available(),
                "base_url": local_gemma.base_url,
                "model": local_gemma.model,
            },
            "cloud_llama": {
                "configured": cloud_llama.is_configured(),
                "model": cloud_llama.model,
            },
        },
    }


@api_router.post("/route")
async def route_task(req: RouteRequest):
    """Determine whether a task is routed to Local Gemma or Cloud Llama."""
    custom_router = router_instance
    if req.threshold is not None:
        custom_router = SemanticRouter(threshold=req.threshold)

    decision = custom_router.route(req.text)
    return {
        "target": decision.target.value,
        "complexity_score": round(decision.complexity_score, 4),
        "threshold": decision.threshold,
        "is_complex": decision.is_complex,
        "matched_prototype": decision.matched_prototype,
        "rationale": decision.rationale,
        "routing_latency_ms": round(decision.routing_latency_ms, 2),
    }


@api_router.post("/analyze")
async def analyze_task(req: AnalyzeRequest):
    """Dynamically route and execute the task against the appropriate LLM tier."""
    result = router_instance.execute(
        text=req.text,
        system_prompt=req.system_prompt,
        task_hint=req.task_hint,
    )
    return result


@api_router.post("/classify-url")
async def classify_url(req: URLClassifyRequest):
    """Direct heuristic URL classification using Local Gemma 2."""
    result = local_gemma.classify_url(url=req.url, context=req.context)
    return result


@api_router.post("/analyze-javascript")
async def analyze_javascript(req: JSAnalyzeRequest):
    """Direct deep reasoning on obfuscated JavaScript using Cloud Llama 3.3 70B."""
    result = cloud_llama.analyze_obfuscated_javascript(code=req.code, context=req.context)
    return result


@api_router.post("/threat-report")
async def generate_threat_report(req: ThreatReportRequest):
    """Direct threat intelligence report synthesis using Cloud Llama 3.3 70B."""
    result = cloud_llama.synthesize_threat_report(raw_signals=req.signals, context=req.context)
    return result


@api_router.post("/scan-url")
async def scan_url_comprehensive(req: ComprehensiveScanRequest):
    """End-to-end URL and DOM analysis coordinated by the ThreatEngine."""
    result = threat_engine.evaluate_url_comprehensive(
        url=req.url,
        deep_scan_dom=req.deep_scan_dom,
    )
    return result
