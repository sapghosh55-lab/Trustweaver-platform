"""API Routes for Hackmatrix Platform.

Exposes the POST /scan endpoint orchestrating:
1. phishing_analyzer.py
2. cert_validator.py
3. vuln_scanner.py
concurrently, then aggregates results through threat_intel.py via Groq LLM,
and persists historical audit logs in SQLite.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.db.history_db import HistoryDB
from app.services.cert_validator import validate_certificate
from app.services.phishing_analyzer import analyze_phishing
from app.services.threat_intel import generate_digital_trust_report
from app.services.vuln_scanner import scan_vulnerabilities

logger = logging.getLogger(__name__)

routes = APIRouter()
db = HistoryDB()


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to audit, validate, and compute Digital Trust Score for")
    deep_analysis: Optional[bool] = Field(True, description="Whether to include Groq LLM threat intelligence synthesis")


@routes.post("/scan", response_model=Dict[str, Any], summary="Comprehensive Concurrent Security Scan")
@routes.post("/scan/", response_model=Dict[str, Any], include_in_schema=False)
async def scan_endpoint(req: ScanRequest) -> Dict[str, Any]:
    """Orchestrate phishing, SSL/TLS certificate, and vulnerability scans concurrently,

    then synthesize a unified Digital Trust Score report via the Semantic Router and Groq LLM.
    """
    target_url = req.url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    logger.info("Initiating concurrent Hackmatrix scan for: %s", target_url)

    try:
        # Run the three security scanning modules concurrently using asyncio.to_thread
        phishing_task = asyncio.to_thread(analyze_phishing, target_url)
        cert_task = asyncio.to_thread(validate_certificate, target_url)
        vuln_task = asyncio.to_thread(scan_vulnerabilities, target_url)

        try:
            phishing_res, cert_res, vuln_res = await asyncio.wait_for(
                asyncio.gather(
                    phishing_task,
                    cert_task,
                    vuln_task,
                    return_exceptions=True,
                ),
                timeout=12.0,
            )
        except asyncio.TimeoutError:
            logger.warning("Concurrent scan tasks timed out after 12s for %s", target_url)
            phishing_res = {"error": "Scan timed out", "phishing_risk_score": 0.3, "verdict": "TIMEOUT"}
            cert_res = {"error": "Cert scan timed out", "cert_risk_score": 0.3, "verdict": "TIMEOUT"}
            vuln_res = {"error": "Vuln scan timed out", "vulnerability_risk_score": 0.3, "verdict": "TIMEOUT"}

        # Handle any uncaught exceptions in tasks safely
        if isinstance(phishing_res, Exception):
            logger.error("Phishing analyzer exception: %s", phishing_res)
            phishing_res = {"error": str(phishing_res), "phishing_risk_score": 0.5, "verdict": "ERROR"}

        if isinstance(cert_res, Exception):
            logger.error("Cert validator exception: %s", cert_res)
            cert_res = {"error": str(cert_res), "cert_risk_score": 0.5, "verdict": "ERROR"}

        if isinstance(vuln_res, Exception):
            logger.error("Vuln scanner exception: %s", vuln_res)
            vuln_res = {"error": str(vuln_res), "vulnerability_risk_score": 0.5, "verdict": "ERROR"}

        # Aggregate data and route through the Groq LLM for the Digital Trust Report
        report = await asyncio.to_thread(
            generate_digital_trust_report,
            target_url,
            phishing_res,
            cert_res,
            vuln_res,
        )

        # Persist report in database asynchronously
        try:
            db.save_scan(report)
        except Exception as db_err:
            logger.warning("Could not persist scan to database: %s", db_err)

        return report

    except Exception as exc:
        logger.exception("Failed executing /scan endpoint: %s", exc)
        raise HTTPException(status_code=500, detail=f"Scan orchestration failed: {str(exc)}")


@routes.get("/scans/recent", summary="Retrieve Recent Audit Histories")
@routes.get("/scans/recent/", include_in_schema=False)
async def get_recent_scans(limit: int = 15) -> List[Dict[str, Any]]:
    """Fetch the latest website audits and their Digital Trust Scores."""
    return db.get_recent_scans(limit=limit)


@routes.get("/scans/{report_id}", summary="Retrieve Specific Forensic Report")
async def get_scan_report(report_id: str) -> Dict[str, Any]:
    """Retrieve full audit report by report ID."""
    report = db.get_scan_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan report not found")
    return report


@routes.post("/scan/phishing", summary="Phishing and Brand Impersonation Scan")
async def scan_phishing_only(req: ScanRequest) -> Dict[str, Any]:
    """Execute phishing and brand impersonation analysis alone."""
    return await asyncio.to_thread(analyze_phishing, req.url.strip())


@routes.post("/scan/cert", summary="SSL/TLS Certificate Chain & CA Audit")
async def scan_cert_only(req: ScanRequest) -> Dict[str, Any]:
    """Execute SSL/TLS certificate validation and compromised CA check alone."""
    return await asyncio.to_thread(validate_certificate, req.url.strip())


@routes.post("/scan/vuln", summary="HTTP Security Headers & Version Disclosure Scan")
async def scan_vuln_only(req: ScanRequest) -> Dict[str, Any]:
    """Execute security header and service version disclosure scan alone."""
    return await asyncio.to_thread(scan_vulnerabilities, req.url.strip())
