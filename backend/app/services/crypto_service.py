"""Cryptographic utilities for TrustWeaver platform.

Uses cryptography primitives to:
- Generate cryptographically secure hashes for IOCs and payloads (SHA-256, SHA-512)
- Validate HMAC authentication signatures between browser extensions and backend API
- Provide Fernet symmetric encryption for sensitive local credentials or session tokens
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoService:
    """Cryptographic utility service."""

    def __init__(self, secret_key: Optional[str] = None) -> None:
        raw_key = secret_key or os.getenv("APP_SECRET_KEY", "trustweaver-dev-secret-key-32bytes!")
        self.secret_bytes = raw_key.encode("utf-8")
        self._fernet = self._init_fernet(self.secret_bytes)

    def _init_fernet(self, secret: bytes) -> Fernet:
        """Derive a URL-safe 32-byte key for Fernet encryption."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"trustweaver_salt_fixed",
            iterations=100_000,
        )
        derived = base64.urlsafe_b64encode(kdf.derive(secret))
        return Fernet(derived)

    def hash_payload(self, content: str | bytes) -> str:
        """Compute SHA-256 hash of a code snippet, URL, or IOC payload."""
        data = content.encode("utf-8") if isinstance(content, str) else content
        return hashlib.sha256(data).hexdigest()

    def generate_hmac_signature(self, message: str) -> str:
        """Generate an HMAC-SHA256 signature for API message verification."""
        return hmac.new(self.secret_bytes, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_hmac_signature(self, message: str, signature: str) -> bool:
        """Verify an HMAC-SHA256 signature securely against timing attacks."""
        expected = self.generate_hmac_signature(message)
        return hmac.compare_digest(expected, signature)

    def encrypt_data(self, plaintext: str) -> str:
        """Encrypt sensitive plaintext (e.g. cached credentials or tokens)."""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt_data(self, ciphertext: str) -> str:
        """Decrypt ciphertext back to plaintext."""
        return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")

