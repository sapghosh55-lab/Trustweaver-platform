"""Phishing Analyzer Module for Hackmatrix / TrustWeaver Platform.

Accepts a URL, scrapes the DOM using BeautifulSoup, and analyzes:
1. Credential-harvesting forms (password fields, external form actions, exfiltration endpoints)
2. Brand impersonation (targeting Microsoft, Google, PayPal, Apple, etc. on unauthorized domains)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests

logger = logging.getLogger(__name__)

# High-value targets frequently spoofed in credential-harvesting phishing kits
MONITORED_BRANDS: Dict[str, Dict[str, Any]] = {
    "microsoft": {
        "name": "Microsoft",
        "official_domains": {"microsoft.com", "live.com", "office.com", "outlook.com", "office365.com", "azure.com"},
        "keywords": ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "sign in to your account"],
    },
    "google": {
        "name": "Google",
        "official_domains": {"google.com", "gmail.com", "accounts.google.com"},
        "keywords": ["google", "gmail", "sign in with google", "google workspace"],
    },
    "apple": {
        "name": "Apple",
        "official_domains": {"apple.com", "icloud.com"},
        "keywords": ["apple id", "icloud", "apple inc", "sign in with apple"],
    },
    "paypal": {
        "name": "PayPal",
        "official_domains": {"paypal.com", "paypal-objects.com"},
        "keywords": ["paypal", "log in to paypal", "send money, pay online"],
    },
    "amazon": {
        "name": "Amazon",
        "official_domains": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"},
        "keywords": ["amazon sign in", "amazon.com", "amazon prime"],
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": {"netflix.com"},
        "keywords": ["netflix", "watch tv shows online", "netflix member sign in"],
    },
    "meta": {
        "name": "Meta / Facebook",
        "official_domains": {"facebook.com", "meta.com", "instagram.com"},
        "keywords": ["facebook", "log into facebook", "instagram", "meta platforms"],
    },
    "chase": {
        "name": "Chase Bank",
        "official_domains": {"chase.com"},
        "keywords": ["chase online", "chase bank", "jpmorgan chase"],
    },
    "bank_of_america": {
        "name": "Bank of America",
        "official_domains": {"bankofamerica.com"},
        "keywords": ["bank of america", "bofa", "sign in to online banking"],
    },
    "wells_fargo": {
        "name": "Wells Fargo",
        "official_domains": {"wellsfargo.com"},
        "keywords": ["wells fargo", "wells fargo online"],
    },
    "coinbase": {
        "name": "Coinbase",
        "official_domains": {"coinbase.com"},
        "keywords": ["coinbase", "buy and sell crypto", "coinbase sign in"],
    },
}

# Suspicious exfiltration endpoints often used by disposable phishing kits
EXFIL_PATTERNS = [
    r"api\.telegram\.org",
    r"discord(app)?\.com/api/webhooks",
    r"formspree\.io",
    r"submit-form\.com",
    r"formsubmit\.co",
    r"formkeep\.com",
    r"getform\.io",
]


def extract_registered_domain(hostname: str) -> str:
    """Extract standard base domain (e.g., 'login.paypal.com' -> 'paypal.com')."""
    hostname = hostname.lower().strip()
    parts = hostname.split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return hostname


def analyze_phishing(url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
    """Scrape and inspect DOM for credential-harvesting forms and brand impersonation.

    Args:
        url: Target web page URL.
        html_content: Optional pre-fetched HTML markup. If None, scrapes live page.

    Returns:
        Structured dictionary detailing credential harvesting indicators, brand spoofing,
        extracted forms, and risk scoring.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    current_reg_domain = extract_registered_domain(hostname)

    scrape_error = None
    if html_content is None:
        try:
            resp = requests.get(
                url,
                timeout=12.0,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/125.0.0.0 Safari/537.36 HackmatrixScanner/1.0"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                allow_redirects=True,
                verify=False,  # Still inspect pages with untrusted/expired certs
            )
            html_content = resp.text
            # Update to final URL after redirects if any
            parsed_final = urlparse(resp.url)
            if parsed_final.hostname:
                hostname = parsed_final.hostname
                current_reg_domain = extract_registered_domain(hostname)
        except Exception as exc:
            scrape_error = str(exc)
            logger.warning("Failed to scrape URL %s: %s", url, exc)
            html_content = ""

    soup = BeautifulSoup(html_content, "html.parser")

    # 1. Inspect forms for credential harvesting
    forms_found: List[Dict[str, Any]] = []
    has_password_input = False
    has_suspicious_action = False
    has_exfil_endpoint = False
    harvesting_score = 0.0
    red_flags: List[str] = []

    for idx, form in enumerate(soup.find_all("form")):
        action = form.get("action", "") or ""
        resolved_action = urljoin(url, action) if action else ""
        parsed_action = urlparse(resolved_action)
        action_host = parsed_action.hostname or ""

        inputs: List[Dict[str, str]] = []
        form_has_password = False
        form_has_user_or_email = False

        for inp in form.find_all(["input", "textarea"]):
            input_type = (inp.get("type") or "text").lower()
            input_name = (inp.get("name") or inp.get("id") or "").lower()
            autocomplete = (inp.get("autocomplete") or "").lower()

            if input_type == "password" or "password" in input_name:
                form_has_password = True
                has_password_input = True

            if any(term in input_name for term in ["user", "email", "login", "account", "phone", "identifier"]):
                form_has_user_or_email = True
            if autocomplete in ["username", "email"]:
                form_has_user_or_email = True

            inputs.append({
                "name": inp.get("name") or inp.get("id") or "",
                "type": input_type,
            })

        # Check for external or suspicious form actions
        is_external_action = False
        if action_host and current_reg_domain:
            if extract_registered_domain(action_host) != current_reg_domain:
                is_external_action = True
                has_suspicious_action = True
                red_flags.append(f"Form #{idx+1} submits credentials to foreign domain: {action_host}")

        # Check for webhook / known exfiltration endpoint submission
        is_exfil = any(re.search(pat, resolved_action, re.IGNORECASE) for pat in EXFIL_PATTERNS)
        if is_exfil:
            has_exfil_endpoint = True
            red_flags.append(f"Form #{idx+1} posts to known exfiltration/webhook endpoint: {resolved_action}")

        # Insecure HTTP submission from HTTPS
        if parsed_url.scheme == "https" and parsed_action.scheme == "http":
            red_flags.append(f"Form #{idx+1} degrades transport security: posts to insecure http://")

        forms_found.append({
            "index": idx + 1,
            "action": action,
            "resolved_action": resolved_action,
            "method": (form.get("method") or "get").upper(),
            "has_password": form_has_password,
            "has_user_or_email": form_has_user_or_email,
            "is_external_action": is_external_action,
            "is_exfil_webhook": is_exfil,
            "inputs_count": len(inputs),
            "inputs": inputs,
        })

    if has_password_input:
        harvesting_score += 0.45
        red_flags.append("Password input field detected in DOM")
    if has_suspicious_action:
        harvesting_score += 0.35
    if has_exfil_endpoint:
        harvesting_score += 0.50

    # 2. Inspect Brand Impersonation
    page_title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    meta_tags = " ".join([tag.get("content", "") for tag in soup.find_all("meta") if tag.get("content")])
    body_text = soup.get_text(separator=" ", strip=True).lower()
    img_alts = " ".join([img.get("alt", "") for img in soup.find_all("img") if img.get("alt")]).lower()

    full_dom_text = f"{page_title} {meta_tags} {body_text[:5000]} {img_alts}".lower()

    detected_brands: List[Dict[str, Any]] = []
    brand_impersonation_detected = False
    impersonation_score = 0.0

    for brand_key, brand_info in MONITORED_BRANDS.items():
        matched_keywords = [kw for kw in brand_info["keywords"] if kw in full_dom_text]
        if not matched_keywords:
            continue

        # Check if the current website is an official domain for this brand
        is_legitimate = any(
            hostname == official or hostname.endswith(f".{official}")
            for official in brand_info["official_domains"]
        )

        if not is_legitimate:
            brand_impersonation_detected = True
            impersonation_score = max(impersonation_score, 0.85)
            detected_brands.append({
                "brand": brand_info["name"],
                "is_authorized_domain": False,
                "current_domain": hostname,
                "official_domains": list(brand_info["official_domains"]),
                "matched_keywords": matched_keywords,
            })
            red_flags.append(
                f"Unauthorized Brand Impersonation: Page mimics {brand_info['name']} "
                f"(matched terms: {', '.join(matched_keywords[:3])}) but is hosted on '{hostname}'!"
            )
        else:
            detected_brands.append({
                "brand": brand_info["name"],
                "is_authorized_domain": True,
                "current_domain": hostname,
                "official_domains": list(brand_info["official_domains"]),
                "matched_keywords": matched_keywords,
            })

    # 3. Overall Phishing Calculation
    total_risk = max(harvesting_score, impersonation_score)
    if brand_impersonation_detected and has_password_input:
        total_risk = 0.98  # High confidence phishing kit
        red_flags.append("CRITICAL: Unofficial brand login page with password harvesting form detected!")
    elif brand_impersonation_detected:
        total_risk = max(total_risk, 0.85)
    elif has_password_input and has_suspicious_action:
        total_risk = max(total_risk, 0.80)

    total_risk = min(round(total_risk, 2), 1.0)

    if total_risk >= 0.75:
        verdict = "PHISHING"
    elif total_risk >= 0.40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "url": url,
        "scanned_domain": hostname,
        "page_title": page_title,
        "verdict": verdict,
        "phishing_risk_score": total_risk,
        "credential_harvesting": {
            "detected": has_password_input,
            "has_external_submission": has_suspicious_action,
            "has_exfil_webhook": has_exfil_endpoint,
            "forms_count": len(forms_found),
            "forms": forms_found,
        },
        "brand_impersonation": {
            "detected": brand_impersonation_detected,
            "brands": detected_brands,
        },
        "red_flags": red_flags,
        "scrape_error": scrape_error,
    }

