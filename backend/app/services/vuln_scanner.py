"""Vulnerability and Security Header Scanner for Hackmatrix / TrustWeaver Platform.

Inspects HTTP response headers and DOM metadata for:
1. Missing or weakly configured security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.)
2. Exposed service, server, framework, and language versions aiding attacker reconnaissance.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests

logger = logging.getLogger(__name__)

# Core security headers with severity and rationale
SECURITY_HEADERS_POLICY: Dict[str, Dict[str, Any]] = {
    "Strict-Transport-Security": {
        "alias": "HSTS",
        "severity": "HIGH",
        "description": "Enforces secure HTTPS transport; prevents SSL-stripping and man-in-the-middle attacks.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "alias": "CSP",
        "severity": "HIGH",
        "description": "Restricts sources of executable scripts, objects, and styles; primary defense against Cross-Site Scripting (XSS).",
        "recommended": "default-src 'self'; script-src 'self'; object-src 'none';",
    },
    "X-Frame-Options": {
        "alias": "XFO",
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks by forbidding the page from being rendered inside an iframe.",
        "recommended": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "alias": "XCTO",
        "severity": "MEDIUM",
        "description": "Prevents MIME-sniffing attacks where browsers misinterpret files as executable scripts.",
        "recommended": "nosniff",
    },
    "Referrer-Policy": {
        "alias": "RP",
        "severity": "LOW",
        "description": "Controls how much referrer information is sent with outbound requests to avoid token leakage.",
        "recommended": "strict-origin-when-cross-origin or no-referrer",
    },
    "Permissions-Policy": {
        "alias": "PP",
        "severity": "LOW",
        "description": "Controls browser features and APIs (e.g., camera, microphone, geolocation).",
        "recommended": "camera=(), microphone=(), geolocation=()",
    },
}

# Informational headers revealing internal server technologies
VERSION_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-varnish",
    "x-drupal-cache",
    "x-version",
]

# Regex pattern to match exact version numbers (e.g. "Apache/2.4.52", "PHP/8.1.2")
VERSION_PATTERN = re.compile(r"([a-zA-Z\-_]+)[\s/:]+(\d+(\.\d+)+[a-zA-Z0-9\-_]*)")


def scan_vulnerabilities(url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Scan an HTTP response for missing security headers and exposed versions.

    Args:
        url: Target web page URL.
        timeout: Request timeout in seconds.

    Returns:
        Structured vulnerability audit detailing missing headers, exposed services,
        and header security score.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    hostname = parsed.hostname or url

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36 HackmatrixScanner/1.0"
                )
            },
            allow_redirects=True,
            verify=False,  # Allow header auditing on non-trusted cert targets
        )
        headers = resp.headers
        raw_html = resp.text[:50000]  # Examine first 50KB for meta generators
        status_code = resp.status_code
    except Exception as exc:
        logger.warning("Vulnerability header scan failed for %s: %s", url, exc)
        return {
            "target": url,
            "success": False,
            "error": str(exc),
            "vulnerability_score": 0.8,
            "vulnerability_risk_score": 0.8,
            "verdict": "ERROR",
        }

    # 1. Evaluate Security Headers
    missing_headers: List[Dict[str, Any]] = []
    present_headers: List[Dict[str, Any]] = []
    header_penalty = 0.0

    # Case-insensitive header lookup dict
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for h_name, h_policy in SECURITY_HEADERS_POLICY.items():
        h_lower = h_name.lower()
        if h_lower in lower_headers:
            val = lower_headers[h_lower]
            warning = None

            # Check for weak configurations
            if h_name == "Strict-Transport-Security":
                if "max-age" in val:
                    try:
                        max_age = int(re.search(r"max-age=(\d+)", val).group(1))
                        if max_age < 10368000:  # Less than ~120 days
                            warning = f"HSTS max-age is short ({max_age}s); recommend >= 31536000s (1 year)"
                            header_penalty += 0.10
                    except (AttributeError, ValueError):
                        pass
                else:
                    warning = "HSTS header missing max-age directive"
                    header_penalty += 0.15

            elif h_name == "Content-Security-Policy":
                if "'unsafe-inline'" in val or "'unsafe-eval'" in val or "*" in val:
                    warning = "CSP contains permissive directives ('unsafe-inline', 'unsafe-eval', or wildcards '*')"
                    header_penalty += 0.15

            present_headers.append({
                "header": h_name,
                "alias": h_policy["alias"],
                "value": val,
                "is_weak": warning is not None,
                "warning": warning,
            })
        else:
            sev = h_policy["severity"]
            missing_headers.append({
                "header": h_name,
                "alias": h_policy["alias"],
                "severity": sev,
                "description": h_policy["description"],
                "recommended": h_policy["recommended"],
            })
            if sev == "HIGH":
                header_penalty += 0.25
            elif sev == "MEDIUM":
                header_penalty += 0.15
            else:
                header_penalty += 0.05

    # 2. Check for Exposed Service & Technology Versions
    exposed_technologies: List[Dict[str, Any]] = []
    version_penalty = 0.0

    for h_name in VERSION_DISCLOSURE_HEADERS:
        if h_name in lower_headers:
            header_val = lower_headers[h_name]
            # Match version numbers
            matches = VERSION_PATTERN.findall(header_val)
            disclosed_versions = [f"{m[0]}/{m[1]}" for m in matches]

            is_version_exposed = bool(disclosed_versions)
            if is_version_exposed:
                version_penalty += 0.20

            exposed_technologies.append({
                "source": f"Header: {h_name}",
                "raw_value": header_val,
                "exact_version_disclosed": is_version_exposed,
                "disclosed_versions": disclosed_versions,
                "risk": "Allows attackers to cross-reference known CVE databases against your exact software version",
            })

    # Also inspect HTML meta generator tag
    soup = BeautifulSoup(raw_html, "html.parser")
    generator_meta = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    if generator_meta and generator_meta.get("content"):
        gen_content = generator_meta["content"]
        gen_matches = VERSION_PATTERN.findall(gen_content)
        exposed_technologies.append({
            "source": "HTML <meta name='generator'>",
            "raw_value": gen_content,
            "exact_version_disclosed": bool(gen_matches),
            "disclosed_versions": [f"{m[0]}/{m[1]}" for m in gen_matches],
            "risk": "Publicly advertises CMS or framework version",
        })
        version_penalty += 0.15

    # Calculate overall vulnerability score (0.0 = hardened, 1.0 = highly vulnerable)
    raw_score = min(round(header_penalty + version_penalty, 2), 1.0)

    verdict = "HARDENED"
    if raw_score >= 0.70:
        verdict = "POOR"
    elif raw_score >= 0.35:
        verdict = "MODERATE"

    return {
        "target": url,
        "scanned_domain": hostname,
        "http_status_code": status_code,
        "success": True,
        "verdict": verdict,
        "vulnerability_risk_score": raw_score,
        "vulnerability_score": raw_score,
        "missing_headers": missing_headers,
        "present_headers": present_headers,
        "missing_count": len(missing_headers),
        "present_count": len(present_headers),
        "exposed_technologies": exposed_technologies,
        "has_version_disclosure": any(tech["exact_version_disclosed"] for tech in exposed_technologies),
    }

