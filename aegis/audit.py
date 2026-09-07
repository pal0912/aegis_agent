"""Enterprise audit logger for AegisAgent V2.

Maintains an in-memory chronological event stream and writes structured,
tamper-evident, DLP-redacted JSON Lines logs for forensic security analysis and compliance.
"""

import json
import logging
import os
import threading
from pathlib import Path
from typing import List, Optional

from aegis.dlp import DataLossPreventionEngine
from aegis.types import AuditEvent

logger = logging.getLogger(__name__)


class AuditLogger:
    """Thread-safe persistent audit logger recording security events with DLP redaction."""

    _instance: Optional["AuditLogger"] = None
    _singleton_lock = threading.RLock()

    def __init__(
        self,
        log_filepath: str = "aegis_audit.jsonl",
        dlp_engine: Optional[DataLossPreventionEngine] = None,
    ) -> None:
        """Initialize AuditLogger with local filepath, memory buffer, and DLP engine.

        Args:
            log_filepath: Path to the JSONL audit output file.
            dlp_engine: Optional DataLossPreventionEngine for secret and credential redaction.
        """
        self.log_filepath = Path(log_filepath)
        self.dlp = dlp_engine or DataLossPreventionEngine()
        from aegis.ledger import CryptographicLedger
        self.ledger = CryptographicLedger(log_filepath=str(self.log_filepath))
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

    def log_event(self, event: AuditEvent) -> AuditEvent:
        """Record an immutable AuditEvent to memory, assign MITRE ATLAS tags, sign via CryptographicLedger, and append to disk.

        Args:
            event: Pydantic v2 AuditEvent instance.

        Returns:
            The final cryptographically signed and enriched AuditEvent.
        """
        from aegis.tracer import SecurityTracer

        # Automatically enrich MITRE ATLAS tags and OTLP format if not already populated
        if not event.mitre_atlas_tags:
            tracer = SecurityTracer(dlp_engine=self.dlp)
            mapped_tags = tracer.map_mitre_atlas_techniques(
                scan_result=event.scan_result,
                policy_decision=event.policy_decision,
            )
            event = event.model_copy(update={
                "mitre_atlas_tags": mapped_tags,
                "otlp_export": tracer.export_otlp_log(event),
            })

        with self._lock:
            try:
                # 1. First get DLP-redacted JSON dictionary
                raw_json = event.model_dump_json()
                sanitized_json_str = self.dlp.redact_text(raw_json)
                event_dict = json.loads(sanitized_json_str)

                # 2. Cryptographically sign event via Ledger
                ledger_sig = self.ledger.sign_event(event_dict, event.timestamp)
                event = event.model_copy(update=ledger_sig)
                self._events.append(event)

                # 3. Add ledger signature to disk payload and write
                event_dict.update(ledger_sig)
                final_disk_json = json.dumps(event_dict)

                with open(self.log_filepath, "a", encoding="utf-8") as f:
                    f.write(final_disk_json + "\n")
                    f.flush()
            except Exception as e:
                logger.error("Failed to write audit event to '%s': %s", self.log_filepath, e)

            return event

    def verify_ledger(self) -> Tuple[bool, int, Optional[str]]:
        """Verify the integrity of the audit log using the cryptographic ledger."""
        return self.ledger.verify_ledger_integrity(str(self.log_filepath))

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
            self.ledger.reset()
            if self.log_filepath.exists():
                try:
                    self.log_filepath.write_text("", encoding="utf-8")
                except Exception as e:
                    logger.warning("Failed to clear audit log file: %s", e)

