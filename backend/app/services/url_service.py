"""URL and Web Content Extraction Service.

Extracts security heuristics from URLs and utilizes BeautifulSoup4 to parse
DOM structure, extract inline JavaScript, forms, iframes, and outbound links.
"""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests

# Common high-risk or frequently abused TLDs in phishing/malware campaigns
HIGH_RISK_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "buzz", "country", "stream", "live", "link"
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random/encoded)."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


class URLService:
    """Performs static URL heuristic evaluation and DOM extraction."""

    def __init__(self, timeout: float = 10.0, max_content_length: int = 1_000_000) -> None:
        self.timeout = timeout
        self.max_content_length = max_content_length
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36 TrustWeaverScanner/1.0"
            )
        })

    def analyze_url_structure(self, url: str) -> Dict[str, Any]:
        """Perform static heuristic checks on URL components."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # 1. IP address hostname check
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        # 2. Punycode check (homograph attack detection)
        is_punycode = "xn--" in hostname.lower()

        # 3. TLD evaluation
        parts = hostname.split(".")
        tld = parts[-1].lower() if len(parts) > 1 else ""
        has_risky_tld = tld in HIGH_RISK_TLDS

        # 4. Entropy calculation
        entropy = calculate_entropy(url)
        high_entropy = entropy > 4.5

        # 5. Suspicious keywords in path/query
        suspicious_keywords = ["login", "verify", "secure", "banking", "update", "account", "signin", "wallet", "admin"]
        found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]

        # Heuristic risk score (0.0 to 1.0)
        risk_score = 0.0
        flags = []
        if is_ip:
            risk_score += 0.35
            flags.append("Host is a bare IP address")
        if is_punycode:
            risk_score += 0.40
            flags.append("Punycode detected (potential homograph attack)")
        if has_risky_tld:
            risk_score += 0.20
            flags.append(f"High-risk TLD detected (. {tld})")
        if high_entropy:
            risk_score += 0.20
            flags.append(f"High Shannon entropy ({entropy:.2f}) indicates encoded payload or DGA")
        if len(parts) > 4:
            risk_score += 0.15
            flags.append(f"Excessive subdomain depth ({len(parts)} segments)")
        if found_keywords:
            risk_score += 0.10 * len(found_keywords)
            flags.append(f"Sensitive keywords in URL: {', '.join(found_keywords)}")

        risk_score = min(round(risk_score, 2), 1.0)

        return {
            "url": url,
            "hostname": hostname,
            "tld": tld,
            "is_ip": is_ip,
            "is_punycode": is_punycode,
            "entropy": round(entropy, 2),
            "heuristic_risk_score": risk_score,
            "flags": flags,
            "found_keywords": found_keywords,
        }

    def fetch_and_extract_dom(self, url: str) -> Dict[str, Any]:
        """Fetch URL content and extract scripts, forms, and outbound connections."""
        structure = self.analyze_url_structure(url)
        normalized_url = structure["url"]

        try:
            resp = self.session.get(
                normalized_url,
                timeout=self.timeout,
                stream=True,
                allow_redirects=True,
            )
            # Guard against oversized downloads
            content = resp.raw.read(self.max_content_length, decode_content=True).decode(
                resp.encoding or "utf-8", errors="ignore"
            )
            final_url = resp.url
            redirected = final_url != normalized_url

            soup = BeautifulSoup(content, "html.parser")

            # Extract title
            title = soup.title.string.strip() if soup.title and soup.title.string else ""

            # Extract scripts (both inline text and src links)
            scripts = []
            script_tags = soup.find_all("script")
            for idx, tag in enumerate(script_tags):
                src = tag.get("src")
                code = tag.get_text() or ""
                scripts.append({
                    "index": idx,
                    "src": src,
                    "is_inline": not bool(src),
                    "length": len(code),
                    "code_snippet": code[:500] if code else None,
                    "full_code": code if code else None,
                })

            # Extract login / password forms
            forms = []
            for form in soup.find_all("form"):
                action = form.get("action", "")
                inputs = [
                    {"name": inp.get("name"), "type": inp.get("type", "text")}
                    for inp in form.find_all("input")
                ]
                has_password = any(inp["type"] == "password" for inp in inputs)
                forms.append({
                    "action": action,
                    "method": form.get("method", "get").upper(),
                    "has_password_field": has_password,
                    "inputs": inputs,
                })

            # Extract iframes
            iframes = [iframe.get("src") for iframe in soup.find_all("iframe") if iframe.get("src")]

            return {
                "success": True,
                "url": normalized_url,
                "final_url": final_url,
                "status_code": resp.status_code,
                "redirected": redirected,
                "title": title,
                "structure": structure,
                "total_scripts": len(scripts),
                "scripts": scripts,
                "forms": forms,
                "iframes": iframes,
            }
        except requests.RequestException as err:
            return {
                "success": False,
                "url": normalized_url,
                "error": str(err),
                "structure": structure,
                "scripts": [],
                "forms": [],
                "iframes": [],
            }

