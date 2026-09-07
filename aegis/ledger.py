"""Cryptographic Tamper-Evident Audit Ledger for AegisAgent V2.

Implements SHA-256 hash chaining (Merkle-style sequential verification) and HMAC-SHA256
signatures for tamper-evident security audit trails across distributed enterprise environments.
"""

import hashlib
import hmac
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default genesis block hash (64 hex zeros)
GENESIS_PREV_HASH: str = "0" * 64


class CryptographicLedger:
    """Thread-safe cryptographic ledger maintaining a tamper-evident hash-chained audit trail."""

    _instance: Optional["CryptographicLedger"] = None
    _singleton_lock = threading.RLock()

    def __init__(
        self,
        secret_key: Optional[str] = None,
        log_filepath: str = "aegis_audit.jsonl",
    ) -> None:
        """Initialize CryptographicLedger.

        Args:
            secret_key: Secret key for HMAC-SHA256 signatures. Defaults to env var or secure fallback.
            log_filepath: Path to the JSONL log file containing chained audit entries.
        """
        self.secret_key = (
            secret_key
            or os.environ.get("AEGIS_LEDGER_SECRET")
            or "aegis_enterprise_cryptographic_master_key_v2"
        ).encode("utf-8")
        self.log_filepath = Path(log_filepath)
        self._lock = threading.RLock()
        self._current_sequence_id: int = 0
        self._last_entry_hash: str = GENESIS_PREV_HASH
        self._initialize_chain_state()

    def _initialize_chain_state(self) -> None:
        """Scan existing log file to synchronize sequence counter and latest chain head hash."""
        with self._lock:
            if not self.log_filepath.exists() or self.log_filepath.stat().st_size == 0:
                self._current_sequence_id = 0
                self._last_entry_hash = GENESIS_PREV_HASH
                return

            try:
                last_valid_seq = 0
                last_hash = GENESIS_PREV_HASH
                with open(self.log_filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            seq = record.get("ledger_sequence_id")
                            entry_h = record.get("ledger_entry_hash")
                            if seq is not None and entry_h:
                                last_valid_seq = int(seq)
                                last_hash = entry_h
                        except json.JSONDecodeError:
                            continue
                self._current_sequence_id = last_valid_seq
                self._last_entry_hash = last_hash
            except Exception as e:
                logger.warning("Could not sync initial ledger state from '%s': %s", self.log_filepath, e)
                self._current_sequence_id = 0
                self._last_entry_hash = GENESIS_PREV_HASH

    @classmethod
    def get_instance(cls, log_filepath: str = "aegis_audit.jsonl") -> "CryptographicLedger":
        """Thread-safe singleton accessor."""
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls(log_filepath=log_filepath)
            return cls._instance

    def sign_event(
        self,
        event_dict: Dict[str, Any],
        timestamp: str,
    ) -> Dict[str, Any]:
        """Compute cryptographic hash chain and HMAC signature for an audit event dictionary.

        Args:
            event_dict: Serialized dictionary of the AuditEvent.
            timestamp: ISO 8601 timestamp string.

        Returns:
            Dictionary containing sequence_id, prev_hash, entry_hash, and signature.
        """
        with self._lock:
            next_seq = self._current_sequence_id + 1
            prev_hash = self._last_entry_hash

            # Remove any existing ledger fields for canonical payload serialization
            clean_event = {
                k: v for k, v in event_dict.items()
                if k not in {"ledger_sequence_id", "ledger_prev_hash", "ledger_entry_hash", "ledger_signature"}
            }
            canonical_json = json.dumps(clean_event, sort_keys=True, separators=(",", ":"))

            # Calculate SHA-256 block hash
            hash_input = f"{next_seq}:{prev_hash}:{timestamp}:{canonical_json}".encode("utf-8")
            entry_hash = hashlib.sha256(hash_input).hexdigest()

            # Calculate HMAC-SHA256 signature
            signature = hmac.new(self.secret_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

            # Update in-memory chain head
            self._current_sequence_id = next_seq
            self._last_entry_hash = entry_hash

            return {
                "ledger_sequence_id": next_seq,
                "ledger_prev_hash": prev_hash,
                "ledger_entry_hash": entry_hash,
                "ledger_signature": signature,
            }

    def verify_ledger_integrity(
        self,
        log_filepath: Optional[str] = None,
    ) -> Tuple[bool, int, Optional[str]]:
        """Verify the complete cryptographic hash chain and HMAC signatures of a log file.

        Args:
            log_filepath: Optional log file path override (defaults to instance log_filepath).

        Returns:
            Tuple of (is_valid: bool, verified_entries_count: int, error_reason: Optional[str]).
        """
        target_path = Path(log_filepath) if log_filepath else self.log_filepath
        if not target_path.exists() or target_path.stat().st_size == 0:
            return True, 0, None

        with self._lock:
            expected_prev_hash = GENESIS_PREV_HASH
            expected_seq = 1
            verified_count = 0

            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    for line_idx, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as e:
                            return False, verified_count, f"Line {line_idx}: Invalid JSON payload ({e})"

                        seq = record.get("ledger_sequence_id")
                        prev_h = record.get("ledger_prev_hash")
                        entry_h = record.get("ledger_entry_hash")
                        sig = record.get("ledger_signature")
                        ts = record.get("timestamp", "")

                        # If record has no ledger fields at all (legacy entry before genesis), allow if before chain
                        if seq is None and prev_h is None and entry_h is None and sig is None:
                            if verified_count == 0 and expected_seq == 1:
                                continue
                            return False, verified_count, f"Line {line_idx}: Missing cryptographic ledger metadata"

                        # If record has partial or missing ledger fields, flag tampering / corruption
                        if seq is None or prev_h is None or entry_h is None or sig is None:
                            return False, verified_count, f"Line {line_idx}: Missing cryptographic ledger metadata"

                        # 1. Verify sequence continuity
                        if seq != expected_seq:
                            return False, verified_count, f"Line {line_idx}: Broken sequence ID (expected {expected_seq}, got {seq})"

                        # 2. Verify previous hash continuity
                        if prev_h != expected_prev_hash:
                            return False, verified_count, f"Line {line_idx}: Broken hash chain link (prev_hash mismatch)"

                        # 3. Recalculate entry hash
                        clean_event = {
                            k: v for k, v in record.items()
                            if k not in {"ledger_sequence_id", "ledger_prev_hash", "ledger_entry_hash", "ledger_signature"}
                        }
                        canonical_json = json.dumps(clean_event, sort_keys=True, separators=(",", ":"))
                        hash_input = f"{seq}:{prev_h}:{ts}:{canonical_json}".encode("utf-8")
                        recalculated_hash = hashlib.sha256(hash_input).hexdigest()

                        if recalculated_hash != entry_h:
                            return False, verified_count, f"Line {line_idx}: Entry hash integrity failure (tampering detected)"

                        # 4. Verify HMAC signature
                        expected_sig = hmac.new(self.secret_key, entry_h.encode("utf-8"), hashlib.sha256).hexdigest()
                        if not hmac.compare_digest(expected_sig, sig):
                            return False, verified_count, f"Line {line_idx}: Invalid cryptographic signature (forgery detected)"

                        expected_prev_hash = entry_h
                        expected_seq += 1
                        verified_count += 1

                return True, verified_count, None

            except Exception as e:
                logger.error("Ledger verification failed with system error: %s", e)
                return False, verified_count, f"System verification exception: {e}"

    @property
    def last_entry_hash(self) -> str:
        with self._lock:
            return self._last_entry_hash

    verify_chain_integrity = verify_ledger_integrity
    verify_chain = verify_ledger_integrity

    def reset(self) -> None:
        """Reset ledger sequence state (primarily for test fixture isolation)."""
        with self._lock:
            self._current_sequence_id = 0
            self._last_entry_hash = GENESIS_PREV_HASH

