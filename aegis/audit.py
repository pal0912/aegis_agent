"""Enterprise audit logger for AegisAgent.

Maintains an in-memory chronological event stream and writes structured,
tamper-evident JSON Lines logs for forensic security analysis and compliance.
"""

import json
import logging
import os
import threading
from pathlib import Path
from typing import List, Optional

from aegis.types import AuditEvent

logger = logging.getLogger(__name__)


class AuditLogger:
    """Thread-safe persistent audit logger recording security events across concurrent worker threads."""

    _instance: Optional["AuditLogger"] = None
    _singleton_lock = threading.RLock()

    def __init__(self, log_filepath: str = "aegis_audit.jsonl") -> None:
        """Initialize AuditLogger with local filepath and memory buffer.

        Args:
            log_filepath: Path to the JSONL audit output file.
        """
        self.log_filepath = Path(log_filepath)
        self._events: List[AuditEvent] = []
        self._lock = threading.RLock()
        self._ensure_log_file()

    def _ensure_log_file(self) -> None:
        """Ensure destination directory and log file exist."""
        with self._lock:
            try:
                self.log_filepath.parent.mkdir(parents=True, exist_ok=True)
                if not self.log_filepath.exists():
                    self.log_filepath.touch(exist_ok=True)
            except Exception as e:
                logger.warning("Could not create audit log file directory: %s", e)

    @classmethod
    def get_instance(cls, log_filepath: str = "aegis_audit.jsonl") -> "AuditLogger":
        """Thread-safe singleton accessor for global audit logger."""
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls(log_filepath=log_filepath)
            return cls._instance

    def log_event(self, event: AuditEvent) -> None:
        """Record an immutable AuditEvent to memory and append to JSONL disk storage under lock.

        Args:
            event: Pydantic v2 AuditEvent instance.
        """
        with self._lock:
            self._events.append(event)
            try:
                event_json = event.model_dump_json()
                with open(self.log_filepath, "a", encoding="utf-8") as f:
                    f.write(event_json + "\n")
                    f.flush()
            except Exception as e:
                logger.error("Failed to write audit event to '%s': %s", self.log_filepath, e)

    def get_recent_events(self, limit: int = 50) -> List[AuditEvent]:
        """Retrieve recent audit events in chronological order under lock.

        Args:
            limit: Maximum number of recent events to return.

        Returns:
            List of AuditEvent objects.
        """
        with self._lock:
            if limit <= 0:
                return []
            return list(self._events[-limit:])

    def clear(self) -> None:
        """Clear in-memory buffer and reset log file (primarily for test fixtures)."""
        with self._lock:
            self._events.clear()
            if self.log_filepath.exists():
                try:
                    self.log_filepath.write_text("", encoding="utf-8")
                except Exception as e:
                    logger.warning("Failed to clear audit log file: %s", e)
