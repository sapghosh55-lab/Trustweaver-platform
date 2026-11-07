import pytest
from app.ai.semantic_router import RouteTarget, SemanticRouter


def test_semantic_router_heuristics_fallback():
    router = SemanticRouter(threshold=0.55)

    # Simple task test
    simple_query = "Classify whether this URL is safe or phishing: https://google.com"
    decision = router.route(simple_query)

    assert decision is not None
    assert decision.target in [RouteTarget.LOCAL_GEMMA, RouteTarget.CLOUD_LLAMA]
    assert decision.threshold == 0.55

    # Highly complex task test
    complex_query = (
        "Analyze obfuscated JavaScript code with packed eval(unescape(...)) and fromCharCode, "
        "and deobfuscate payload logic to detect dynamic DOM injection and C2 beaconing."
    )
    complex_decision = router.route(complex_query)

    assert complex_decision is not None
    assert complex_decision.is_complex is True
    assert complex_decision.target == RouteTarget.CLOUD_LLAMA

