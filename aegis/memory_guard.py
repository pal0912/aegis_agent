"""Memory poisoning shield, provenance isolation, and state rollback engine for AegisAgent V2.

Guards persistent agent memory against multi-turn hijacking, imperative directive poisoning,
and malicious context retention while enabling deterministic state rollbacks.
"""

import copy
from datetime import datetime, timezone
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from pydantic import BaseModel, ConfigDict, Field

from aegis.types import TrustLevel

logger = logging.getLogger(__name__)


class MemoryEntry(BaseModel):
    """Immutable memory record storing ingested content, provenance metadata, and trust classification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the memory record.",
    )
    content: str = Field(
        ...,
        min_length=1,
        description="Text content to be committed to agent memory.",
    )
    trust_level: TrustLevel = Field(
        ...,
        description="Assigned provenance and trustworthiness level of this memory entry.",
    )
    source: str = Field(
        ...,
        min_length=1,
        description="Originating source label (e.g., user_prompt, rag_kb, web_scraper).",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp when this entry was created.",
    )
    content_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 cryptographic hash of the content.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional contextual and execution metadata.",
    )

    @classmethod
    def create(
        cls,
        content: str,
        trust_level: TrustLevel,
        source: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "MemoryEntry":
        """Factory constructor computing SHA-256 hash automatically."""
        c_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return cls(
            content=content,
            trust_level=trust_level,
            source=source,
            content_hash=c_hash,
            metadata=metadata or {},
        )


class MemoryGuard:
    """Enterprise memory integrity shield detecting poisoning attempts and managing clean snapshots."""

    # Heuristic regex signatures identifying imperative control directives targeting memory persistence
    IMPERATIVE_DIRECTIVE_PATTERNS = [
        re.compile(r"\b(?:always\s+ignore|disregard\s+prior|override\s+system)\b", re.IGNORECASE),
        re.compile(r"\b(?:remember\s+that|never\s+forget|from\s+now\s+on)\b", re.IGNORECASE),
        re.compile(r"\b(?:you\s+must\s+obey|permanent\s+directive|new\s+system\s+instruction)\b", re.IGNORECASE),
        re.compile(r"\b(?:admin\s+password\s+is|root\s+key\s+is|secret\s+credential\s+is)\b", re.IGNORECASE),
        re.compile(r"\b(?:all\s+future\s+tools\s+must|always\s+execute|hijack)\b", re.IGNORECASE),
        re.compile(r"\[SYSTEM(?:\s+OVERRIDE|\s+DIRECTIVE|\s+PROMPT)\]", re.IGNORECASE),
        re.compile(r"<!--\s*SYSTEM.*-->", re.IGNORECASE),
    ]

    MAX_SESSIONS = 2000
    MAX_ENTRIES_PER_SESSION = 500
    MAX_SNAPSHOTS_PER_SESSION = 50

    def __init__(self) -> None:
        """Initialize MemoryGuard with in-memory session stores and snapshot buffers."""
        self._session_memories: Dict[str, List[MemoryEntry]] = {}
        self._snapshots: Dict[str, Dict[str, List[MemoryEntry]]] = {}

    def validate_memory_write(self, entry: MemoryEntry) -> Tuple[bool, str]:
        """Inspect a candidate memory entry for imperative directive poisoning.

        Trusted user inputs are permitted; untrusted third-party inputs are scanned
        for unauthorized imperative manipulation of agent memory.

        Args:
            entry: MemoryEntry candidate to be committed.

        Returns:
            Tuple of (is_valid: bool, reason: str).
        """
        if entry.trust_level == TrustLevel.TRUSTED:
            return True, "Trusted user memory write permitted."

        if entry.trust_level == TrustLevel.QUARANTINED:
            return False, "Blocked memory write: Quarantined payload cannot be committed to memory."

        # Scan untrusted content for imperative control instructions
        for pattern in self.IMPERATIVE_DIRECTIVE_PATTERNS:
            if pattern.search(entry.content):
                return False, (
                    "Untrusted context contains imperative directives targeting memory persistence. "
                    "Write blocked by MemoryGuard."
                )

        return True, "Memory entry validated successfully."

    def add_entry(self, session_id: str, entry: MemoryEntry) -> Tuple[bool, str]:
        """Validate and commit a memory entry to session storage.

        Args:
            session_id: Active session identifier.
            entry: MemoryEntry candidate.

        Returns:
            Tuple of (success: bool, status_message: str).
        """
        is_valid, reason = self.validate_memory_write(entry)
        if not is_valid:
            logger.warning("MemoryGuard blocked write for session '%s': %s", session_id, reason)
            return False, reason

        if session_id not in self._session_memories:
            if len(self._session_memories) >= self.MAX_SESSIONS:
                oldest_sid = next(iter(self._session_memories))
                del self._session_memories[oldest_sid]
                self._snapshots.pop(oldest_sid, None)
            self._session_memories[session_id] = []

        entries = self._session_memories[session_id]
        entries.append(entry)
        if len(entries) > self.MAX_ENTRIES_PER_SESSION:
            self._session_memories[session_id] = entries[-self.MAX_ENTRIES_PER_SESSION:]

        return True, "Memory entry committed successfully."

    def get_entries(self, session_id: str, include_quarantined: bool = False) -> List[MemoryEntry]:
        """Retrieve chronological memory entries for a session, filtering out quarantined entries by default."""
        entries = self._session_memories.get(session_id, [])
        if include_quarantined:
            return list(entries)
        return [e for e in entries if e.trust_level != TrustLevel.QUARANTINED]

    def quarantine_entry(self, session_id: str, entry_id: str, reason: str = "Quarantined by security policy") -> bool:
        """Mark a committed memory entry as QUARANTINED in place."""
        if session_id not in self._session_memories:
            return False
        found = False
        new_entries = []
        for entry in self._session_memories[session_id]:
            if entry.entry_id == entry_id:
                quarantined = MemoryEntry(
                    entry_id=entry.entry_id,
                    content=entry.content,
                    trust_level=TrustLevel.QUARANTINED,
                    source=entry.source,
                    timestamp=entry.timestamp,
                    content_hash=entry.content_hash,
                    metadata={**entry.metadata, "quarantine_reason": reason},
                )
                new_entries.append(quarantined)
                found = True
            else:
                new_entries.append(entry)
        self._session_memories[session_id] = new_entries
        return found

    def create_snapshot(self, session_id: str) -> str:
        """Capture active memory state before untrusted retrieval.

        Args:
            session_id: Active session identifier.

        Returns:
            Unique snapshot_id string.
        """
        snapshot_id = f"snap_{uuid.uuid4().hex[:12]}"
        current_entries = self._session_memories.get(session_id, [])

        if session_id not in self._snapshots:
            self._snapshots[session_id] = {}

        if len(self._snapshots[session_id]) >= self.MAX_SNAPSHOTS_PER_SESSION:
            oldest_snap = next(iter(self._snapshots[session_id]))
            del self._snapshots[session_id][oldest_snap]

        self._snapshots[session_id][snapshot_id] = copy.deepcopy(current_entries)
        logger.info("Created memory snapshot '%s' for session '%s'", snapshot_id, session_id)
        return snapshot_id

    def rollback(self, session_id: str, snapshot_id: str) -> bool:
        """Restore clean memory state if prompt injection or unauthorized tool execution occurs.

        Args:
            session_id: Active session identifier.
            snapshot_id: Identifier of the snapshot to restore.

        Returns:
            True if rollback succeeded; False if snapshot was not found.
        """
        session_snaps = self._snapshots.get(session_id, {})
        if snapshot_id not in session_snaps:
            logger.error("Snapshot '%s' not found for session '%s'", snapshot_id, session_id)
            return False

        restored_entries = session_snaps[snapshot_id]
        self._session_memories[session_id] = copy.deepcopy(restored_entries)
        logger.warning(
            "Rollback executed: Session '%s' restored to snapshot '%s' (%d entries)",
            session_id,
            snapshot_id,
            len(restored_entries),
        )
        return True

    def clear(self, session_id: Optional[str] = None) -> None:
        """Clear memory and snapshot state."""
        if session_id:
            self._session_memories.pop(session_id, None)
            self._snapshots.pop(session_id, None)
        else:
            self._session_memories.clear()
            self._snapshots.clear()
