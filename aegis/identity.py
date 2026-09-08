"""Non-Human Identity (NHI) and Scoped Delegation Token management for AegisAgent V2.

Implements ephemeral/persistent agent cryptographic identities, task-scoped delegation tokens
(Agent Passports), and strict capability boundary gating in compliance with OWASP ASI03.
"""

import base64
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, Field

from aegis.types import Capability

logger = logging.getLogger(__name__)


class AgentIdentity(BaseModel):
    """Cryptographic Non-Human Identity representation for an autonomous agent."""

    agent_id: str = Field(..., description="Unique identifier or designated role of the agent")
    public_key_pem: str = Field(..., description="PEM-encoded Ed25519 public key")
    assigned_capabilities: Set[Capability] = Field(
        default_factory=set, description="Strict set of capabilities permitted for this identity"
    )
    delegation_depth_limit: int = Field(
        default=2, ge=0, description="Maximum sub-agent hops allowed"
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Identity creation timestamp in ISO-8601 UTC",
    )

    model_config = {"arbitrary_types_allowed": True}


class AgentIdentityManager:
    """Manages agent cryptographic identities, Ed25519 keystores, and delegation tokens."""

    def __init__(self) -> None:
        """Initialize in-memory keystore, registry, and revocation list."""
        self._private_keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self._identities: Dict[str, AgentIdentity] = {}
        self._revoked_tokens: Set[str] = set()

    def register_agent(
        self,
        agent_id: str,
        assigned_capabilities: Set[Capability],
        delegation_depth_limit: int = 2,
    ) -> AgentIdentity:
        """Generate an Ed25519 keypair and register an agent identity."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        identity = AgentIdentity(
            agent_id=agent_id,
            public_key_pem=pub_pem,
            assigned_capabilities=set(assigned_capabilities),
            delegation_depth_limit=delegation_depth_limit,
        )

        self._private_keys[agent_id] = private_key
        self._identities[agent_id] = identity
        logger.info(f"Registered AgentIdentity: {agent_id} with {len(assigned_capabilities)} capabilities")
        return identity

    def register_external_identity(self, identity: AgentIdentity) -> None:
        """Register an existing agent identity (public key only)."""
        self._identities[identity.agent_id] = identity

    def get_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        """Retrieve an identity by agent_id."""
        return self._identities.get(agent_id)

    def list_identities(self) -> Dict[str, AgentIdentity]:
        """Return all registered identities."""
        return dict(self._identities)

    def sign_payload(self, agent_id: str, payload_bytes: bytes) -> str:
        """Sign arbitrary payload bytes using the agent's private key, returning base64 signature."""
        private_key = self._private_keys.get(agent_id)
        if not private_key:
            raise ValueError(f"No private key available for agent_id '{agent_id}' to sign payload.")
        sig = private_key.sign(payload_bytes)
        return base64.urlsafe_b64encode(sig).decode("utf-8")

    def verify_signature(self, agent_id: str, payload_bytes: bytes, signature_b64: str) -> bool:
        """Verify an Ed25519 signature against an agent's registered public key."""
        identity = self._identities.get(agent_id)
        if not identity:
            logger.warning(f"Verification failed: Agent '{agent_id}' is not registered.")
            return False

        try:
            public_key = serialization.load_pem_public_key(identity.public_key_pem.encode("utf-8"))
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False
            sig_bytes = base64.urlsafe_b64decode(signature_b64.encode("utf-8"))
            public_key.verify(sig_bytes, payload_bytes)
            return True
        except (InvalidSignature, ValueError, Exception) as exc:
            logger.warning(f"Signature verification failed for agent '{agent_id}': {exc}")
            return False

    def issue_delegation_token(
        self,
        issuer: AgentIdentity,
        delegate_id: str,
        scope: Set[Capability],
        ttl_seconds: int = 300,
        current_depth: int = 0,
    ) -> str:
        """Issue a cryptographically signed, short-lived task-scoped delegation token (Agent Passport)."""
        # Validate that the delegated scope is a strict subset of issuer's capabilities
        for cap in scope:
            if cap not in issuer.assigned_capabilities:
                raise ValueError(
                    f"Delegation privilege escalation rejected: Capability '{cap.value}' "
                    f"exceeds issuer '{issuer.agent_id}' assigned capabilities."
                )

        target_depth = current_depth + 1
        if target_depth > issuer.delegation_depth_limit:
            raise ValueError(
                f"Delegation depth limit exceeded: depth {target_depth} > "
                f"limit {issuer.delegation_depth_limit} for issuer '{issuer.agent_id}'."
            )

        now = time.time()
        claims: Dict[str, Any] = {
            "jti": uuid.uuid4().hex,
            "iss": issuer.agent_id,
            "sub": delegate_id,
            "scope": [c.value for c in scope],
            "depth": target_depth,
            "iat": int(now),
            "exp": int(now + ttl_seconds),
        }

        claims_json = json.dumps(claims, sort_keys=True)
        claims_b64 = base64.urlsafe_b64encode(claims_json.encode("utf-8")).decode("utf-8")
        sig_b64 = self.sign_payload(issuer.agent_id, claims_b64.encode("utf-8"))

        return f"{claims_b64}.{sig_b64}"

    def revoke_token(self, jti: str) -> None:
        """Revoke a delegation token by its unique JTI."""
        self._revoked_tokens.add(jti)

    def is_token_revoked(self, jti: str) -> bool:
        """Check if a token JTI is in the revocation list."""
        return jti in self._revoked_tokens

    def verify_delegation_token(
        self, token_str: str, required_capability: Capability
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Validate delegation token signature, expiration, revocation, and capability envelope."""
        if not token_str or "." not in token_str:
            return False, "MALFORMED_TOKEN", None

        parts = token_str.strip().split(".")
        if len(parts) != 2:
            return False, "MALFORMED_TOKEN_STRUCTURE", None

        claims_b64, sig_b64 = parts[0], parts[1]

        try:
            claims_json = base64.urlsafe_b64decode(claims_b64.encode("utf-8")).decode("utf-8")
            claims = json.loads(claims_json)
        except Exception as exc:
            return False, f"TOKEN_DECODE_FAILED: {exc}", None

        # Verify revocation status
        jti = claims.get("jti")
        if jti and jti in self._revoked_tokens:
            return False, "TOKEN_REVOKED", claims

        issuer_id = claims.get("iss")
        if not issuer_id:
            return False, "MISSING_ISSUER_IN_TOKEN", None

        # Verify signature with issuer's registered public key
        if not self.verify_signature(issuer_id, claims_b64.encode("utf-8"), sig_b64):
            return False, f"INVALID_TOKEN_SIGNATURE_FROM_{issuer_id}", None

        # Verify expiration
        exp = claims.get("exp", 0)
        if time.time() > exp:
            return False, "TOKEN_EXPIRED", claims

        # Verify capability scope
        scope = set(claims.get("scope", []))
        if required_capability.value not in scope:
            return (
                False,
                f"CAPABILITY_NOT_IN_DELEGATED_SCOPE: '{required_capability.value}' not in {scope}",
                claims,
            )

        return True, "VALID", claims
