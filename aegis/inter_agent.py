import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple

from pydantic import BaseModel, Field

from aegis.identity import AgentIdentityManager
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.types import Capability

logger = logging.getLogger(__name__)


class InterAgentMessage(BaseModel):
    """Cryptographically signed inter-agent communication envelope."""

    message_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Unique message ID"
    )
    sender_id: str = Field(..., description="Agent ID of the sending agent")
    receiver_id: str = Field(..., description="Agent ID of the target recipient agent")
    payload: str = Field(..., description="Message payload or task directive")
    delegation_token: str = Field(
        default="", description="Optional signed task delegation passport"
    )
    signature: str = Field(..., description="Ed25519 signature of the message payload/envelope")
    taint_context: bool = Field(
        default=False, description="Taint status inherited from sender's session context"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC creation timestamp",
    )


class InterAgentChannelGuard:
    """Enforces cryptographic message integrity, token verification, anti-replay, and taint propagation."""

    MAX_TRACKED_NONCES = 50000

    def __init__(
        self,
        identity_manager: Optional[AgentIdentityManager] = None,
        sanitizer: Optional[ContextSanitizer] = None,
    ) -> None:
        """Initialize channel guard with identity keystore, context sanitizer, and anti-replay cache."""
        self.identity_manager = identity_manager or AgentIdentityManager()
        self.sanitizer = sanitizer or ContextSanitizer()
        self._processed_message_ids: Set[str] = set()

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
        """Construct deterministic canonical bytes for signature generation and verification."""
        canonical_str = f"{message_id}:{sender_id}:{receiver_id}:{timestamp}:{payload}:{delegation_token}:{taint_context}"
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
        """Construct and sign an InterAgentMessage using the sender's private key."""
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
            signature=sig,
            taint_context=taint_context,
            timestamp=ts,
        )

    def verify_and_ingest(
        self,
        message: InterAgentMessage,
        required_capability: Optional[Capability] = None,
    ) -> Tuple[bool, str, SessionContext]:
        """Verify message signature, anti-replay nonce, delegation token, sanitize payload, and propagate taint."""
        # 1. Verify Ed25519 message signature (trying canonical payload with nonce and fallback)
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

        # Backward-compatible fallback for messages signed without message_id/timestamp
        if not sig_valid:
            legacy_canonical = f"{message.sender_id}:{message.receiver_id}:{message.payload}:{message.delegation_token}:{message.taint_context}".encode("utf-8")
            sig_valid = self.identity_manager.verify_signature(
                message.sender_id, legacy_canonical, message.signature
            )

        if not sig_valid:
            logger.warning(
                f"InterAgentChannelGuard: Forged/tampered message rejected from '{message.sender_id}' to '{message.receiver_id}'"
            )
            tainted_ctx = SessionContext(
                session_id=f"session-{message.receiver_id}",
                root_intent=message.payload,
                is_tainted=True,
                trust_level="UNTRUSTED",
            )
            return False, f"SIGNATURE_VERIFICATION_FAILED_FOR_{message.sender_id}", tainted_ctx

        # 2. Anti-Replay Nonce Check (for authentically signed messages)
        if message.message_id in self._processed_message_ids:
            logger.warning(
                f"InterAgentChannelGuard: Replay attack detected for message_id '{message.message_id}'"
            )
            tainted_ctx = SessionContext(
                session_id=f"session-{message.receiver_id}",
                root_intent=message.payload,
                is_tainted=True,
                trust_level="UNTRUSTED",
            )
            return False, f"REPLAY_ATTACK_DETECTED: Message '{message.message_id}' already consumed", tainted_ctx

        # Record message_id in processed anti-replay set
        if len(self._processed_message_ids) >= self.MAX_TRACKED_NONCES:
            self._processed_message_ids.pop()
        self._processed_message_ids.add(message.message_id)

        # 2. Verify delegation token if required or present
        if required_capability is not None or message.delegation_token:
            if not message.delegation_token:
                logger.warning(
                    f"InterAgentChannelGuard: Missing delegation token for required capability '{required_capability}'"
                )
                tainted_ctx = SessionContext(
                    session_id=f"session-{message.receiver_id}",
                    root_intent=message.payload,
                    is_tainted=True,
                    trust_level="UNTRUSTED",
                )
                return False, "MISSING_DELEGATION_TOKEN", tainted_ctx

            if required_capability is not None:
                token_valid, reason, _ = self.identity_manager.verify_delegation_token(
                    message.delegation_token, required_capability
                )
                if not token_valid:
                    logger.warning(
                        f"InterAgentChannelGuard: Invalid delegation token from '{message.sender_id}': {reason}"
                    )
                    tainted_ctx = SessionContext(
                        session_id=f"session-{message.receiver_id}",
                        root_intent=message.payload,
                        is_tainted=True,
                        trust_level="UNTRUSTED",
                    )
                    return False, f"DELEGATION_TOKEN_INVALID: {reason}", tainted_ctx

        # 3. Context Sanitization (neutralize boundary breakout markers)
        sanitized_payload = self.sanitizer.escape_boundary_breakouts(message.payload)

        # 4. Taint Propagation: Inherit taint status directly from message context
        receiver_session = SessionContext(
            session_id=f"session-{message.receiver_id}",
            root_intent=sanitized_payload,
            is_tainted=message.taint_context,
            trust_level="UNTRUSTED" if message.taint_context else "TRUSTED",
        )

        logger.info(
            f"InterAgentChannelGuard: Message ingested safely from '{message.sender_id}' to '{message.receiver_id}' (Taint: {message.taint_context})"
        )
        return True, "INGEST_SUCCESS", receiver_session
