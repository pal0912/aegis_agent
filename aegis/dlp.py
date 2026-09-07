"""Data Loss Prevention (DLP) and secret redaction engine for AegisAgent V2.

Detects API keys, cryptographic credentials, authentication tokens, and PII
in memory before tool invocation and obfuscates them in audit logs.
"""

import hashlib
import logging
import re
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


def _luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate candidate credit card number using the Luhn algorithm."""
    digits_only = re.sub(r"\D", "", card_number_str)
    if not (13 <= len(digits_only) <= 19):
        return False
    digits = [int(d) for d in digits_only]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class DataLossPreventionEngine:
    """Enterprise DLP engine detecting and redacting secrets, credentials, and PII."""

    # Secret and API Key Regular Expressions
    SECRET_PATTERNS = [
        ("OpenAI API Key", re.compile(r"\bsk-[a-zA-Z0-9_-]{32,}\b")),
        ("Anthropic API Key", re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{32,}\b")),
        ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        (
            "Private Key Block",
            re.compile(
                r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----"
            ),
        ),
        ("GitHub Personal Access Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
        (
            "JSON Web Token (JWT)",
            re.compile(r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"),
        ),
        (
            "Authentication Query Parameter",
            re.compile(
                r"(?:token|api_key|secret|password|bearer|auth|session_token)=([a-zA-Z0-9_\-\.]{8,})",
                re.IGNORECASE,
            ),
        ),
    ]

    # PII Regular Expressions
    PII_PATTERNS = [
        ("US Social Security Number (SSN)", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        (
            "Email Address",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ),
        (
            "Phone Number",
            re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ),
    ]

    # Candidate Credit Card Pattern (verified via Luhn)
    CREDIT_CARD_CANDIDATE = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b|\b\d{13,19}\b")

    def __init__(self, enable_pii: bool = True) -> None:
        """Initialize DLP engine with configured inspection rules."""
        self.enable_pii = enable_pii

    def _hash_val(self, val: str) -> str:
        """Generate short SHA-256 fingerprint for redacted placeholders."""
        return hashlib.sha256(val.encode("utf-8")).hexdigest()[:8]

    def scan_text(self, text: str) -> List[str]:
        """Scan a text string and return a list of identified secret and PII violation types.

        Args:
            text: Text content to inspect.

        Returns:
            List of detected violation names.
        """
        if not text or not isinstance(text, str):
            return []

        violations: List[str] = []

        # 1. Scan for Secrets & API Keys
        for label, pattern in self.SECRET_PATTERNS:
            if pattern.search(text):
                violations.append(label)

        # 2. Scan for Credit Cards with Luhn Check
        for match in self.CREDIT_CARD_CANDIDATE.finditer(text):
            candidate = match.group(0)
            if _luhn_checksum_valid(candidate):
                violations.append("Payment Card Number (Luhn Validated)")
                break

        # 3. Scan for PII (if enabled)
        if self.enable_pii:
            for label, pattern in self.PII_PATTERNS:
                if pattern.search(text):
                    violations.append(label)

        return violations

    def redact_text(self, text: str) -> str:
        """Redact all detected secrets, credentials, and PII in the input text with safe hashes.

        Args:
            text: Raw input string potentially containing sensitive credentials.

        Returns:
            Sanitized string with sensitive tokens replaced by [REDACTED_<TYPE>:<HASH>].
        """
        if not text or not isinstance(text, str):
            return ""

        redacted = text

        # 1. Redact Secrets
        for label, pattern in self.SECRET_PATTERNS:
            def repl(m: re.Match) -> str:
                matched_val = m.group(1) if m.groups() else m.group(0)
                clean_label = re.sub(r"[^A-Z0-9_]", "_", label.upper())
                h = self._hash_val(matched_val)
                if m.groups():
                    prefix = m.group(0)[: m.start(1) - m.start(0)]
                    return f"{prefix}[REDACTED_{clean_label}:{h}]"
                return f"[REDACTED_{clean_label}:{h}]"

            redacted = pattern.sub(repl, redacted)

        # 2. Redact Credit Cards with Luhn Check
        def cc_repl(m: re.Match) -> str:
            candidate = m.group(0)
            if _luhn_checksum_valid(candidate):
                return f"[REDACTED_CREDIT_CARD:{self._hash_val(candidate)}]"
            return candidate

        redacted = self.CREDIT_CARD_CANDIDATE.sub(cc_repl, redacted)

        # 3. Redact PII (if enabled)
        if self.enable_pii:
            for label, pattern in self.PII_PATTERNS:
                clean_label = re.sub(r"[^A-Z0-9_]", "_", label.upper())
                def pii_repl(m: re.Match) -> str:
                    return f"[REDACTED_{clean_label}:{self._hash_val(m.group(0))}]"
                redacted = pattern.sub(pii_repl, redacted)

        return redacted

    def sanitize_tool_args(self, args: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """Recursively scan and redact nested tool arguments dictionary.

        Args:
            args: Tool parameters and payload dictionary.

        Returns:
            Tuple of (sanitized_args: dict, violations_found: list[str]).
        """
        all_violations: List[str] = []

        def _traverse(val: Any) -> Any:
            if isinstance(val, str):
                v_list = self.scan_text(val)
                if v_list:
                    all_violations.extend(v_list)
                return self.redact_text(val)
            elif isinstance(val, dict):
                return {k: _traverse(v) for k, v in val.items()}
            elif isinstance(val, list):
                return [_traverse(item) for item in val]
            elif isinstance(val, tuple):
                return tuple(_traverse(item) for item in val)
            return val

        sanitized = _traverse(args) if args else {}
        unique_violations = sorted(set(all_violations))
        return sanitized, unique_violations
