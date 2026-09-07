"""Secure Inter-Agent Communication Guard for AegisAgent V2.

Implements cryptographically signed message envelopes, taint context propagation,
and boundary breakout sanitization between autonomous peer agents in compliance with OWASP ASI07.
"""

import hashlib
import logging
import uuid
from typing import Any, Dict, Optional, Tuple

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


class InterAgentChannelGuard:
    """Enforces cryptographic message integrity, token verification, and taint propagation across agents."""

    def __init__(
        self,
        identity_manager: Optional[AgentIdentityManager] = None,
        sanitizer: Optional[ContextSanitizer] = None,
    ) -> None:
        """Initialize channel guard with identity keystore and context sanitizer."""
        self.identity_manager = identity_manager or AgentIdentityManager()
        self.sanitizer = sanitizer or ContextSanitizer()

    def build_canonical_payload(
        self, sender_id: str, receiver_id: str, payload: str, delegation_token: str, taint_context: bool
    ) -> bytes:
        """Construct deterministic canonical bytes for signature generation and verification."""
        canonical_str = f"{sender_id}:{receiver_id}:{payload}:{delegation_token}:{taint_context}"
        return canonical_str.encode("utf-8")

    def create_signed_message(
        self,
        sender_id: str,
        receiver_id: str,
        payload: str,
        delegation_token: str = "",
        taint_context: bool = False,
    ) -> InterAgentMessage:
        """Construct and sign an InterAgentMessage using the sender's private key."""
        canonical_bytes = self.build_canonical_payload(
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload,
            delegation_token=delegation_token,
            taint_context=taint_context,
        )
        sig = self.identity_manager.sign_payload(sender_id, canonical_bytes)
        return InterAgentMessage(
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload=payload,
            delegation_token=delegation_token,
            signature=sig,
            taint_context=taint_context,
        )

    def verify_and_ingest(
        self,
        message: InterAgentMessage,
        required_capability: Optional[Capability] = None,
    ) -> Tuple[bool, str, SessionContext]:
        """Verify message signature, delegation token, sanitize payload, and propagate taint."""
        # 1. Verify Ed25519 message signature
        canonical_bytes = self.build_canonical_payload(
            sender_id=message.sender_id,
            receiver_id=message.receiver_id,
            payload=message.payload,
            delegation_token=message.delegation_token,
            taint_context=message.taint_context,
        )

        sig_valid = self.identity_manager.verify_signature(
            message.sender_id, canonical_bytes, message.signature
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
