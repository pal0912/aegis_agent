"""Provenance tracking and runtime taint analysis for AegisAgent.

Maintains session execution lineage and marks execution contexts as TAINTED
upon ingesting third-party or untrusted external inputs.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from aegis.types import AuditEvent, TrustLevel


class SessionContext:
    """Tracks session taint state, trust transitions, and input provenance history."""

    def __init__(
        self,
        user_root_intent: str,
        session_id: Optional[str] = None,
    ) -> None:
        """Initialize new agent session context with root verified intent.

        Args:
            user_root_intent: Direct prompt/intent authorized by verified user.
            session_id: Optional unique session identifier; generates UUID4 if None.
        """
        self.session_id: str = session_id or str(uuid.uuid4())
        self.user_root_intent: str = user_root_intent
        self.is_tainted: bool = False
        self.trust_level: TrustLevel = TrustLevel.TRUSTED
        self.provenance_history: List[Dict[str, Any]] = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "SESSION_INITIALIZED",
                "source": "USER_DIRECT",
                "content_sha256": AuditEvent.hash_payload(user_root_intent),
                "trust_level": self.trust_level.value,
            }
        ]

    def ingest_untrusted_data(self, source_name: str, raw_text: str) -> None:
        """Ingest untrusted third-party payload, permanently tainting the session context.

        Args:
            source_name: Identifier for the ingested data source (e.g. 'web_search', 'pdf_reader', 'email_body').
            raw_text: Content ingested from the untrusted external source.
        """
        self.is_tainted = True
        self.trust_level = TrustLevel.UNTRUSTED

        content_sha256 = AuditEvent.hash_payload(raw_text if raw_text is not None else "")
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "INGEST_UNTRUSTED_DATA",
            "source": source_name,
            "content_sha256": content_sha256,
            "trust_level": self.trust_level.value,
        }
        self.provenance_history.append(record)

    def is_session_tainted(self) -> bool:
        """Check if the session context has ingested any untrusted external inputs.

        Returns:
            True if tainted, False otherwise.
        """
        return self.is_tainted

    def quarantine_session(self, reason: str) -> None:
        """Elevate session context to QUARANTINED when an active exploit or injection is confirmed.

        Args:
            reason: Explanation of the exploit or safety violation.
        """
        self.is_tainted = True
        self.trust_level = TrustLevel.QUARANTINED
        self.provenance_history.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "SESSION_QUARANTINED",
                "reason": reason,
                "trust_level": self.trust_level.value,
            }
        )
