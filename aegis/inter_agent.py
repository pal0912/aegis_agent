"""Inter-agent communication guard for AegisAgent.

Enforces cryptographic Ed25519 identity verification, scoped delegation
tokens (passports), anti-replay tracking with freshness windows,
and taint propagation across distributed multi-agent workflows.
"""

import collections
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple

from pydantic import BaseModel, Field

from aegis.identity import AgentIdentityManager
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.types import Capability

logger = logging.getLogger(__name__)


class InterAgentSecurityError(Exception):
    """Raised when an inter-agent security violation occurs."""


class InterAgentMessage(BaseModel):
    """Cryptographically signed inter-agent communication envelope."""

    message_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique message ID",
    )
    sender_id: str = Field(
        ..., description="Agent ID of the sending agent"
    )
    receiver_id: str = Field(
        ..., description="Agent ID of the target recipient agent"
    )
    payload: str = Field(
        ..., description="Message payload or task directive"
    )
    delegation_token: str = Field(
        default="", description="Optional signed task delegation passport"
    )
    signature: str = Field(
        ..., description="Ed25519 signature of the payload/envelope"
    )
    taint_context: bool = Field(
        default=False,
        description="Taint status inherited from sender's session context",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC creation timestamp",
    )


class InterAgentChannelGuard:
    """Enforces cryptographic message integrity, token verification,

    anti-replay, and taint propagation across agent boundaries.
    """

    MAX_TRACKED_NONCES = 50000

    def __init__(
        self,
        identity_manager: Optional[AgentIdentityManager] = None,
        sanitizer: Optional[ContextSanitizer] = None,
    ) -> None:
        """Initialize channel guard with identity keystore and anti-replay."""
        self._lock = threading.RLock()
        self.identity_manager = identity_manager or AgentIdentityManager()
        self.sanitizer = sanitizer or ContextSanitizer()
        self._processed_message_ids: collections.OrderedDict[str, float] = (
            collections.OrderedDict()
        )

    def build_canonical_payload(
        self,
        sender_id: str,
        receiver_id: str,
        payload: str,
        delegation_token: str = "",
        taint_context: bool = False,
        message_id: str = "",
        timestamp: str = "",
    ) -> bytes:
        """Construct deterministic canonical bytes for signature checks."""
        canonical_str = (
            f"{message_id}:{sender_id}:{receiver_id}:{timestamp}:"
            f"{payload}:{delegation_token}:{taint_context}"
        )
        return canonical_str.encode("utf-8")

    def create_signed_message(
        self,
        sender_id: str,
        receiver_id: str,
        payload: str,
        delegation_token: str = "",
        taint_context: bool = False,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> InterAgentMessage:
        """Construct and sign an InterAgentMessage using sender's key."""
        msg_id = message_id or str(uuid.uuid4())
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        canonical_bytes = self.build_canonical_payload(
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload,
            delegation_token=delegation_token,
            taint_context=taint_context,
            message_id=msg_id,
            timestamp=ts,
        )
        sig = self.identity_manager.sign_payload(sender_id, canonical_bytes)
        return InterAgentMessage(
            message_id=msg_id,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload,
            delegation_token=delegation_token,
            taint_context=taint_context,
            signature=sig,
            timestamp=ts,
        )

    def verify_and_ingest(
        self,
        message: InterAgentMessage,
        expected_receiver_id: Optional[str] = None,
        parent_session: Optional[SessionContext] = None,
        required_capability: Optional[Capability] = None,
    ) -> Tuple[bool, str, SessionContext]:
        """Validate an inbound signed inter-agent message envelope."""
        # 0. Audience / Target Recipient Validation
        if expected_receiver_id is not None:
            if message.receiver_id != expected_receiver_id:
                logger.warning(
                    "InterAgentChannelGuard: Audience mismatch. Intended for "
                    "'%s', received by '%s'",
                    message.receiver_id,
                    expected_receiver_id,
                )
                tainted_ctx = SessionContext(
                    session_id=f"session-{message.receiver_id}",
                    user_root_intent=(
                        parent_session.user_root_intent
                        if parent_session
                        else message.payload
                    ),
                    is_tainted=True,
                    trust_level="UNTRUSTED",
                )
                return (
                    False,
                    f"AUDIENCE_MISMATCH: Target '{message.receiver_id}' != "
                    f"expected '{expected_receiver_id}'",
                    tainted_ctx,
                )

        # 1. Timestamp Freshness and Expiration Check (Anti-Replay Window)
        try:
            ts_clean = message.timestamp.replace("Z", "+00:00")
            msg_dt = datetime.fromisoformat(ts_clean)
            now_dt = datetime.now(timezone.utc)
            age_sec = (now_dt - msg_dt).total_seconds()
            max_age_sec = 300.0  # 5 minutes
            max_future_skew_sec = 60.0  # 1 minute clock skew
            if age_sec > max_age_sec:
                logger.warning(
                    "InterAgentChannelGuard: Message '%s' expired (age %.1fs)",
                    message.message_id,
                    age_sec,
                )
                tainted_ctx = SessionContext(
                    session_id=f"session-{message.receiver_id}",
                    user_root_intent=(
                        parent_session.user_root_intent
                        if parent_session
                        else message.payload
                    ),
                    is_tainted=True,
                    trust_level="UNTRUSTED",
                )
                return (
                    False,
                    f"MESSAGE_EXPIRED: Timestamp is {age_sec:.1f}s old "
                    f"(max {max_age_sec}s allowed)",
                    tainted_ctx,
                )
            if age_sec < -max_future_skew_sec:
                logger.warning(
                    "InterAgentChannelGuard: Future timestamp on message '%s'",
                    message.message_id,
                )
                tainted_ctx = SessionContext(
                    session_id=f"session-{message.receiver_id}",
                    user_root_intent=(
                        parent_session.user_root_intent
                        if parent_session
                        else message.payload
                    ),
                    is_tainted=True,
                    trust_level="UNTRUSTED",
                )
                return (
                    False,
                    f"CLOCK_SKEW_EXCEEDED: Timestamp is in the future "
                    f"by {-age_sec:.1f}s",
                    tainted_ctx,
                )
        except Exception as exc:
            tainted_ctx = SessionContext(
                session_id=f"session-{message.receiver_id}",
                user_root_intent=(
                    parent_session.user_root_intent
                    if parent_session
                    else message.payload
                ),
                is_tainted=True,
                trust_level="UNTRUSTED",
            )
            return False, f"INVALID_TIMESTAMP_FORMAT: {exc}", tainted_ctx

        # 2. Verify Ed25519 message signature
        canonical_bytes = self.build_canonical_payload(
            sender_id=message.sender_id,
            receiver_id=message.receiver_id,
            payload=message.payload,
            delegation_token=message.delegation_token,
            taint_context=message.taint_context,
            message_id=message.message_id,
            timestamp=message.timestamp,
        )

        sig_valid = self.identity_manager.verify_signature(
            message.sender_id, canonical_bytes, message.signature
        )

        # Backward-compatible fallback for messages without id/ts
        if not sig_valid:
            legacy_canonical = (
                f"{message.sender_id}:{message.receiver_id}:{message.payload}:"
                f"{message.delegation_token}:{message.taint_context}".encode(
                    "utf-8"
                )
            )
            sig_valid = self.identity_manager.verify_signature(
                message.sender_id, legacy_canonical, message.signature
            )

        if not sig_valid:
            logger.warning(
                "InterAgentChannelGuard: Forged/tampered message rejected "
                "from '%s' to '%s'",
                message.sender_id,
                message.receiver_id,
            )
            tainted_ctx = SessionContext(
                session_id=f"session-{message.receiver_id}",
                user_root_intent=(
                    parent_session.user_root_intent
                    if parent_session
                    else message.payload
                ),
                is_tainted=True,
                trust_level="UNTRUSTED",
            )
            return (
                False,
                f"SIGNATURE_VERIFICATION_FAILED_FOR_{message.sender_id}",
                tainted_ctx,
            )

        # 3. Anti-Replay Nonce & Session Check
        tracking_key = (
            f"{message.sender_id}:{message.receiver_id}:{message.message_id}"
        )
        with self._lock:
            if (
                message.message_id in self._processed_message_ids
                or tracking_key in self._processed_message_ids
            ):
                is_replay = True
            else:
                is_replay = False
                while (
                    len(self._processed_message_ids) >= self.MAX_TRACKED_NONCES
                ):
                    self._processed_message_ids.popitem(last=False)
                now_ts = time.time()
                self._processed_message_ids[message.message_id] = now_ts
                self._processed_message_ids[tracking_key] = now_ts

        if is_replay:
            logger.warning(
                "InterAgentChannelGuard: Replay attack detected for message "
                "'%s'",
                message.message_id,
            )
            tainted_ctx = SessionContext(
                session_id=f"session-{message.receiver_id}",
                user_root_intent=(
                    parent_session.user_root_intent
                    if parent_session
                    else message.payload
                ),
                is_tainted=True,
                trust_level="UNTRUSTED",
            )
            return (
                False,
                f"REPLAY_ATTACK_DETECTED: Message '{message.message_id}' "
                f"already consumed",
                tainted_ctx,
            )

        # 4. Verify delegation token if required or present
        if required_capability is not None or message.delegation_token:
            if not message.delegation_token:
                logger.warning(
                    "InterAgentChannelGuard: Missing delegation token for "
                    "capability '%s'",
                    required_capability,
                )
                tainted_ctx = SessionContext(
                    session_id=f"session-{message.receiver_id}",
                    user_root_intent=(
                        parent_session.user_root_intent
                        if parent_session
                        else message.payload
                    ),
                    is_tainted=True,
                    trust_level="UNTRUSTED",
                )
                return False, "MISSING_DELEGATION_TOKEN", tainted_ctx

            if required_capability is not None:
                token_valid, reason, _ = (
                    self.identity_manager.verify_delegation_token(
                        message.delegation_token, required_capability
                    )
                )
                if not token_valid:
                    logger.warning(
                        "InterAgentChannelGuard: Invalid delegation token "
                        "from '%s': %s",
                        message.sender_id,
                        reason,
                    )
                    tainted_ctx = SessionContext(
                        session_id=f"session-{message.receiver_id}",
                        user_root_intent=(
                            parent_session.user_root_intent
                            if parent_session
                            else message.payload
                        ),
                        is_tainted=True,
                        trust_level="UNTRUSTED",
                    )
                    return (
                        False,
                        f"DELEGATION_TOKEN_INVALID: {reason}",
                        tainted_ctx,
                    )

        # 5. Context Sanitization
        sanitized_payload = self.sanitizer.escape_boundary_breakouts(
            message.payload
        )

        # 6. Taint Propagation
        combined_taint = (
            message.taint_context or
            (parent_session.is_session_tainted() if parent_session else False)
        )
        receiver_session = SessionContext(
            session_id=f"session-{message.receiver_id}",
            user_root_intent=(
                parent_session.user_root_intent
                if parent_session
                else sanitized_payload
            ),
            is_tainted=combined_taint,
            trust_level="UNTRUSTED" if combined_taint else "TRUSTED",
        )

        logger.info(
            "InterAgentChannelGuard: Ingested from '%s' to '%s' (Taint: %s)",
            message.sender_id,
            message.receiver_id,
            combined_taint,
        )
        return True, "INGEST_SUCCESS", receiver_session
