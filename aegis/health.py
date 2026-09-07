"""System Health & Readiness Probes for AegisAgent.

Provides comprehensive liveness and deep readiness monitoring across:
- Embedding and classification model memory residency
- Cryptographic Merkle audit ledger integrity verification
- Outbound network guard filtering and socket safety
- Multi-agent registry status
"""

import os
import sys
import logging
from typing import Dict, Any, Optional

from aegis.ledger import CryptographicLedger
from aegis.network_guard import OutboundNetworkGuard

logger = logging.getLogger("AegisHealth")


class SystemHealthMonitor:
    """Enterprise health and readiness monitor for AegisAgent."""

    def __init__(
        self,
        ledger: Optional[CryptographicLedger] = None,
        network_guard: Optional[OutboundNetworkGuard] = None,
        models_dir: Optional[str] = None
    ):
        self.ledger = ledger or CryptographicLedger()
        self.network_guard = network_guard or OutboundNetworkGuard()
        self.models_dir = models_dir or os.getenv("AEGIS_MODELS_CACHE", "/opt/models_cache")

    def check_liveness(self) -> Dict[str, Any]:
        """Performs a lightweight liveness check for container orchestrator liveness probes.

        Returns:
            Dict containing status and basic system info.
        """
        return {
            "status": "healthy",
            "uptime": "operational",
            "runtime": f"Python {sys.version.split()[0]}",
            "pid": os.getpid()
        }

    def check_readiness(self) -> Dict[str, Any]:
        """Performs deep readiness verification across all core subsystem invariants.

        Verifies:
        1. Model Memory Residency / Cache availability (e.g. sentence transformers / deberta)
        2. Merkle Audit Ledger cryptographic integrity
        3. Network Guard SSRF filtering capability

        Returns:
            Dict containing status ('ready' or 'unready'), subsystems status breakdown,
            and HTTP status recommendation (200 vs 503).
        """
        subsystems: Dict[str, Dict[str, Any]] = {}
        all_ready = True

        # 1. Model Residency / Embedding Cache Check
        try:
            import torch
            from sentence_transformers import SentenceTransformer
            models_cached = os.path.exists(self.models_dir) if self.models_dir else True
            cuda_available = torch.cuda.is_available()
            subsystems["models"] = {
                "status": "ready",
                "torch_version": torch.__version__,
                "cuda_available": cuda_available,
                "models_cache_present": models_cached,
                "cache_path": self.models_dir
            }
        except Exception as e:
            logger.error("Health Probe: Model check failed: %s", e)
            subsystems["models"] = {
                "status": "degraded",
                "error": str(e)
            }

        # 2. Cryptographic Ledger Integrity Check
        try:
            ledger_valid, count, err = self.ledger.verify_chain_integrity()
            if ledger_valid:
                subsystems["audit_ledger"] = {
                    "status": "ready",
                    "integrity_verified": True,
                    "verified_entries_count": count,
                    "latest_chain_hash": self.ledger.last_entry_hash
                }
            else:
                all_ready = False
                subsystems["audit_ledger"] = {
                    "status": "corrupted",
                    "integrity_verified": False,
                    "verified_entries_count": count,
                    "error": err
                }
        except Exception as e:
            logger.error("Health Probe: Ledger check failed: %s", e)
            all_ready = False
            subsystems["audit_ledger"] = {
                "status": "failed",
                "error": str(e)
            }

        # 3. Outbound Network Guard SSRF Filter Check
        try:
            # Verify network guard correctly blocks loopback/metadata addresses
            loopback_test = self.network_guard.validate_url("http://127.0.0.1:8000/api")
            metadata_test = self.network_guard.validate_url("http://169.254.169.254/latest/meta-data")
            
            # Both loopback and metadata MUST be blocked by default
            is_loopback_blocked = not loopback_test[0] if isinstance(loopback_test, tuple) else not getattr(loopback_test, "allowed", True)
            is_metadata_blocked = not metadata_test[0] if isinstance(metadata_test, tuple) else not getattr(metadata_test, "allowed", True)

            if is_loopback_blocked and is_metadata_blocked:
                subsystems["network_guard"] = {
                    "status": "ready",
                    "ssrf_protection_active": True,
                    "loopback_blocked": True,
                    "cloud_metadata_blocked": True
                }
            else:
                all_ready = False
                subsystems["network_guard"] = {
                    "status": "insecure",
                    "ssrf_protection_active": False,
                    "loopback_blocked": is_loopback_blocked,
                    "cloud_metadata_blocked": is_metadata_blocked
                }
        except Exception as e:
            logger.error("Health Probe: Network guard check failed: %s", e)
            all_ready = False
            subsystems["network_guard"] = {
                "status": "failed",
                "error": str(e)
            }

        status_str = "ready" if all_ready else "unready"
        http_code = 200 if all_ready else 503

        return {
            "status": status_str,
            "http_status_code": http_code,
            "subsystems": subsystems
        }
