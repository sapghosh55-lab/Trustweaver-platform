"""SSL/TLS Certificate Validator for Hackmatrix / TrustWeaver Platform.

Fetches a URL's SSL/TLS certificate chain using Python `ssl` and `cryptography`.
Inspects for:
1. Weak cryptographic implementations (SHA-1/MD5, RSA < 2048 bits, expired certs, weak TLS/ciphers)
2. Compromised, distrusted, or flagged Certificate Authorities (specifically addressing vulnerabilities
   such as the eMudhra TLS incident and other major CA compliance distrusts).
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x448, x25519

logger = logging.getLogger(__name__)

# Compromised, distrusted, or heavily scrutinized Certificate Authorities
# Includes the eMudhra TLS incident where compliance violations and domain validation failures
# prompted browser root store distrust/deprecation motions, alongside historic CA failures.
FLAGGED_CERTIFICATE_AUTHORITIES: Dict[str, Dict[str, str]] = {
    "emudhra": {
        "name": "eMudhra",
        "incident": "eMudhra TLS Compliance & Distrust Incident",
        "severity": "CRITICAL",
        "description": (
            "eMudhra root and intermediate CAs faced browser root store distrust and restriction "
            "actions (Chrome Root Program / Mozilla) following recurring compliance failures, "
            "unverified domain validation, and unauthorized subordinate certificate issuance."
        ),
    },
    "wosign": {
        "name": "WoSign",
        "incident": "WoSign & StartCom Distrust",
        "severity": "CRITICAL",
        "description": "Distrusted globally due to backdating SHA-1 certificates, arbitrary domain issuance, and hidden ownership.",
    },
    "startcom": {
        "name": "StartCom (StartSSL)",
        "incident": "StartCom Distrust",
        "severity": "CRITICAL",
        "description": "Distrusted by major browsers due to backdated certificates and unvetted subordinate CA issuance.",
    },
    "diginotar": {
        "name": "DigiNotar",
        "incident": "DigiNotar Total Breach",
        "severity": "CRITICAL",
        "description": "Compromised CA used to forge wildcard certificates (e.g. *.google.com) for state-sponsored MITM attacks.",
    },
    "cnnic": {
        "name": "CNNIC",
        "incident": "CNNIC MITM Intermediate Issuance",
        "severity": "HIGH",
        "description": "Issued unauthorized MITM intermediate certificates used to intercept secure web traffic.",
    },
    "camerfirma": {
        "name": "Camerfirma",
        "incident": "Camerfirma Compliance Distrust",
        "severity": "HIGH",
        "description": "Distrusted by Mozilla and Google due to systemic audit failures and non-compliant issuance.",
    },
    "darkmatter": {
        "name": "DarkMatter",
        "incident": "DarkMatter Surveillance Concerns",
        "severity": "CRITICAL",
        "description": "Root request rejected and blacklisted due to offensive cyber espionage activities.",
    },
}

# Weak signature hash algorithms
WEAK_HASH_ALGORITHMS = {"md5", "md2", "sha1", "sha"}


def extract_host_port(url_or_host: str) -> Tuple[str, int]:
    """Parse hostname and port from URL or raw hostname."""
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        if ":" in url_or_host:
            parts = url_or_host.split(":")
            host = parts[0]
            port = int(parts[1])
        else:
            host = url_or_host
            port = 443
    return host, port


def validate_certificate(url_or_host: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Fetch and validate a website's SSL/TLS certificate and chain.

    Args:
        url_or_host: URL (e.g. 'https://example.com') or hostname ('example.com').
        timeout: Network timeout in seconds.

    Returns:
        Structured certificate audit with cryptographic strength ratings, validity,
        and detection of compromised/distrusted CAs.
    """
    host, port = extract_host_port(url_or_host)
    if not host:
        return {
            "target": f"{host}:{port}",
            "connection_success": False,
            "error": "Invalid target host",
            "cert_risk_score": 1.0,
            "risk_score": 1.0,
            "verdict": "FAILED",
        }

    flags: List[str] = []
    ca_incident_alerts: List[Dict[str, Any]] = []
    crypto_weaknesses: List[str] = []
    risk_score = 0.0

    # 1. Establish TLS connection and fetch peer certificates
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Fetch even if invalid/self-signed to audit weaknesses

    negotiated_protocol = None
    negotiated_cipher = None
    der_cert = None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated_protocol = ssock.version()
                negotiated_cipher = ssock.cipher()
                der_cert = ssock.getpeercert(binary_form=True)
    except Exception as exc:
        logger.warning("TLS handshake failed for %s:%d: %s", host, port, exc)
        return {
            "target": f"{host}:{port}",
            "connection_success": False,
            "error": f"TLS Handshake failed: {exc}",
            "cert_risk_score": 0.90,
            "risk_score": 0.90,
            "verdict": "FAILED",
        }

    if not der_cert:
        return {
            "target": f"{host}:{port}",
            "connection_success": False,
            "error": "No certificate presented by peer",
            "cert_risk_score": 1.0,
            "risk_score": 1.0,
            "verdict": "CRITICAL",
        }

    # 2. Parse Certificate using Cryptography library
    cert = x509.load_der_x509_certificate(der_cert)

    # Extract Subject & Issuer fields
    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()

    # Validity Period
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    is_expired = now > not_after
    is_not_yet_valid = now < not_before
    days_to_expiry = (not_after - now).days

    if is_expired:
        crypto_weaknesses.append(f"Certificate expired {abs(days_to_expiry)} days ago ({not_after.isoformat()})")
        risk_score += 0.50
    elif days_to_expiry < 14:
        crypto_weaknesses.append(f"Certificate expires soon in {days_to_expiry} days")
        risk_score += 0.15

    if is_not_yet_valid:
        crypto_weaknesses.append("Certificate not yet valid (future start date)")
        risk_score += 0.40

    # 3. Check for Weak Cryptographic Implementation
    # Signature Hash Algorithm
    sig_hash = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else "unknown"
    if sig_hash in WEAK_HASH_ALGORITHMS:
        msg = f"Weak and cryptographically broken signature hash: {sig_hash.upper()} (vulnerable to collision forgery)"
        crypto_weaknesses.append(msg)
        flags.append(msg)
        risk_score += 0.60

    # Public Key Type and Size
    pub_key = cert.public_key()
    key_type = "Unknown"
    key_size = 0

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = pub_key.key_size
        if key_size < 2048:
            msg = f"Insecure RSA key size: {key_size} bits (minimum recommended is 2048 bits; factorable)"
            crypto_weaknesses.append(msg)
            flags.append(msg)
            risk_score += 0.55
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = "ECC"
        key_size = pub_key.key_size
        curve_name = pub_key.curve.name
        if key_size < 256:
            msg = f"Weak ECC key size: {key_size} bits on curve {curve_name}"
            crypto_weaknesses.append(msg)
            risk_score += 0.45
    elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_type = "Edwards Curve"
        key_size = 256
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_type = "DSA"
        key_size = pub_key.key_size
        crypto_weaknesses.append("Deprecated DSA public key algorithm")
        risk_score += 0.40

    # Negotiated TLS Protocol & Cipher Suite Checks
    if negotiated_protocol in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
        msg = f"Insecure deprecated TLS protocol negotiated: {negotiated_protocol} (RFC 8996 violation)"
        crypto_weaknesses.append(msg)
        flags.append(msg)
        risk_score += 0.45

    if negotiated_cipher:
        cipher_name = negotiated_cipher[0]
        if any(weak in cipher_name.upper() for weak in ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]):
            msg = f"Insecure legacy cipher suite negotiated: {cipher_name}"
            crypto_weaknesses.append(msg)
            flags.append(msg)
            risk_score += 0.50

    # Self-signed certificate check
    is_self_signed = cert.issuer == cert.subject
    if is_self_signed:
        flags.append("Self-signed certificate: Issuer matches Subject (no third-party CA chain validation)")
        risk_score += 0.35

    # 4. Check for Compromised / Flagged CAs (eMudhra incident & known rogue CAs)
    issuer_lower = issuer_str.lower()
    for ca_key, ca_meta in FLAGGED_CERTIFICATE_AUTHORITIES.items():
        if ca_key in issuer_lower:
            incident_alert = {
                "ca_name": ca_meta["name"],
                "incident": ca_meta["incident"],
                "severity": ca_meta["severity"],
                "description": ca_meta["description"],
                "issuer_dn": issuer_str,
            }
            ca_incident_alerts.append(incident_alert)
            flags.append(
                f"FLAGGED CA ALERT [{ca_meta['severity']}]: Certificate issued by '{ca_meta['name']}' "
                f"associated with '{ca_meta['incident']}'. Risk: {ca_meta['description']}"
            )
            risk_score += 0.70

    # 5. Extract Subject Alternative Names (SANs)
    sans: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        flags.append("Missing Subject Alternative Name (SAN) extension")

    # Hostname match check
    hostname_matched = False
    if sans:
        for san in sans:
            if san.startswith("*."):
                domain_part = san[2:].lower()
                if host.lower().endswith(domain_part) and host.lower().count(".") == san.count("."):
                    hostname_matched = True
                    break
            elif san.lower() == host.lower():
                hostname_matched = True
                break
    if not hostname_matched and sans:
        flags.append(f"Hostname mismatch: '{host}' does not match SANs: {', '.join(sans[:5])}")
        risk_score += 0.40

    risk_score = min(round(risk_score, 2), 1.0)
    verdict = "TRUSTED"
    if risk_score >= 0.70 or ca_incident_alerts:
        verdict = "DANGEROUS"
    elif risk_score >= 0.35:
        verdict = "WEAK"

    return {
        "target": f"{host}:{port}",
        "connection_success": True,
        "verdict": verdict,
        "cert_risk_score": risk_score,
        "risk_score": risk_score,
        "subject": subject_str,
        "issuer": issuer_str,
        "serial_number": str(cert.serial_number),
        "validity": {
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_to_expiry": days_to_expiry,
            "is_expired": is_expired,
        },
        "cryptographic_details": {
            "key_type": key_type,
            "key_size_bits": key_size,
            "signature_hash": sig_hash.upper(),
            "negotiated_tls_version": negotiated_protocol,
            "negotiated_cipher": negotiated_cipher[0] if negotiated_cipher else None,
        },
        "weak_cryptography_flags": crypto_weaknesses,
        "compromised_ca_alerts": ca_incident_alerts,
        "subject_alternative_names": sans[:20],
        "hostname_matched": hostname_matched,
        "all_flags": flags,
    }

