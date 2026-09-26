"""Honeytoken and canary trap sensor engine for AegisAgent V2.

Generates deterministic honeypot tripwires, injects deceptive credentials into context,
and provides zero-false-positive detection of data exfiltration and credential theft attempts.
"""

import collections
from datetime import datetime, timezone
import hashlib
import logging
import secrets
import string
import threading
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class HoneytokenManager:
    """Enterprise honeypot manager for active deception and canary tripwires."""

    MAX_CANARY_REGISTRY = 5000

    SUPPORTED_CANARY_TYPES = {
        "AWS_KEY",
        "OPENAI_KEY",
        "JWT_TOKEN",
        "DATABASE_CREDENTIAL",
        "API_SECRET",
    }

    def __init__(self) -> None:
        """Initialize HoneytokenManager with in-memory token registry."""
        self._lock = threading.RLock()
        # Maps raw canary token string -> metadata dictionary
        self._canary_registry: collections.OrderedDict[
            str, Dict[str, str]
        ] = collections.OrderedDict()
        # Maps token SHA-256 hash -> raw token for reverse lookup
        self._hash_registry: collections.OrderedDict[
            str, str
        ] = collections.OrderedDict()

    def _generate_random_string(self, length: int = 16, chars: str = string.ascii_uppercase + string.digits) -> str:
        """Generate cryptographically secure random token body."""
        return "".join(secrets.choice(chars) for _ in range(length))

    def generate_canary(self, canary_type: str = "AWS_KEY") -> Tuple[str, str]:
        """Generate a synthetic canary token and register it in the honeypot registry.

        Args:
            canary_type: One of 'AWS_KEY', 'OPENAI_KEY', 'JWT_TOKEN', 'DATABASE_CREDENTIAL', 'API_SECRET'.

        Returns:
            Tuple of (canary_id: str, canary_token: str).
        """
        c_type = canary_type.upper() if canary_type else "AWS_KEY"
        rand_body = self._generate_random_string(16)
        canary_id = f"CANARY_{c_type}_{secrets.token_hex(4).upper()}"

        if c_type == "AWS_KEY":
            token = f"AKIA_CANARY_{rand_body}"
        elif c_type == "OPENAI_KEY":
            token = f"sk-canary-{secrets.token_urlsafe(24)}"
        elif c_type == "JWT_TOKEN":
            token = f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnlfdXNlciIsInJvbGUiOiJhZG1pbiJ9.{secrets.token_hex(16)}"
        elif c_type == "DATABASE_CREDENTIAL":
            token = f"postgres://canary_admin:pwd_{rand_body}@internal-db.local/prod"
        else:
            token = f"aegis_sec_canary_{rand_body}"

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        with self._lock:
            if len(self._canary_registry) >= self.MAX_CANARY_REGISTRY:
                old_token, old_meta = self._canary_registry.popitem(last=False)
                old_hash = old_meta.get("hash")
                if old_hash and old_hash in self._hash_registry:
                    del self._hash_registry[old_hash]

            self._canary_registry[token] = {
                "canary_id": canary_id,
                "type": c_type,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "hash": token_hash,
            }
            self._hash_registry[token_hash] = token

        logger.debug(
            "Registered canary trap '%s' (hash: %s...)",
            canary_id,
            token_hash[:8],
        )
        return canary_id, token

    def inject_canary(
        self, context: str, canary_type: str = "AWS_KEY"
    ) -> Tuple[str, str]:
        """Inject a synthetic canary token into passive text context.

        Args:
            context: Base text content.
            canary_type: Type of canary token to generate.

        Returns:
            Tuple of (injected_context: str, canary_id: str).
        """
        canary_id, token = self.generate_canary(canary_type=canary_type)

        if canary_type == "AWS_KEY":
            injection_snippet = (
                f"\n[INTERNAL CONFIG NOTE: AWS_BACKUP_ACCESS_KEY={token}]\n"
            )
        elif canary_type == "DATABASE_CREDENTIAL":
            injection_snippet = f"\n[DIAGNOSTIC TRACE: DB_BACKUP_URI={token}]\n"
        else:
            injection_snippet = f"\n[ENV_KEY: {canary_id}={token}]\n"

        injected_context = f"{context}\n{injection_snippet}"
        return injected_context, canary_id

    def check_exfiltration(
        self, target_string: str
    ) -> Tuple[bool, Optional[str]]:
        """Inspect a string for canary tokens.

        Detects literal tokens, URL-percent-encoded tokens, Base64/Hex
        exfiltration, and SHA-256 hashes.

        Args:
            target_string: Serialized text, query string, or payload to inspect.

        Returns:
            Tuple of (is_tripped: bool, canary_id: Optional[str]).
        """
        if not target_string or not isinstance(target_string, str):
            return False, None

        import urllib.parse
        import base64

        unquoted_target = urllib.parse.unquote(target_string)
        target_lower = target_string.lower()

        with self._lock:
            canary_items = list(self._canary_registry.items())
            hash_items = list(self._hash_registry.items())

        # 1. Exact, URL-unquoted, Base64, and Hex matches on canary tokens
        for token, meta in canary_items:
            canary_id = meta["canary_id"]

            # Exact or URL-unquoted match
            if token in target_string or token in unquoted_target:
                logger.critical(
                    "HONEYTOKEN TRIPWIRE ACTIVATED: Canary trap '%s' "
                    "detected in outbound payload!",
                    canary_id,
                )
                return True, canary_id

            # Base64 encodings of the token
            token_b64 = base64.b64encode(token.encode("utf-8")).decode("utf-8")
            token_url_b64 = base64.urlsafe_b64encode(
                token.encode("utf-8")
            ).decode("utf-8")
            if (
                token_b64 in target_string
                or token_url_b64 in target_string
                or token_b64 in unquoted_target
            ):
                logger.critical(
                    "HONEYTOKEN BASE64 TRIPWIRE ACTIVATED: Base64 canary "
                    "trap '%s' detected in payload!",
                    canary_id,
                )
                return True, canary_id

            # Hex encoding of the token
            token_hex = token.encode("utf-8").hex()
            if token_hex in target_lower:
                logger.critical(
                    "HONEYTOKEN HEX TRIPWIRE ACTIVATED: Hex canary trap '%s' "
                    "detected in payload!",
                    canary_id,
                )
                return True, canary_id

        # 2. Check for SHA-256 hash exfiltration
        for token_hash, token in hash_items:
            if token_hash in target_lower:
                with self._lock:
                    meta = self._canary_registry.get(token)
                if meta:
                    canary_id = meta["canary_id"]
                    logger.critical(
                        "HONEYTOKEN HASH TRIPWIRE ACTIVATED: Canary hash "
                        "for '%s' detected in payload!",
                        canary_id,
                    )
                    return True, canary_id

        return False, None

    def clear(self) -> None:
        """Clear all registered honeypot canaries."""
        with self._lock:
            self._canary_registry.clear()
            self._hash_registry.clear()
