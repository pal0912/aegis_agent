"""Hot-Reloadable Declarative Policy Engine for AegisAgent V2.

Decouples hardcoded rules into declarative, hot-reloadable YAML/JSON security policies
supporting fine-grained role capabilities, delegation limits, and network restrictions.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, field_validator
import yaml

from aegis.types import Capability

logger = logging.getLogger(__name__)


class RolePolicyConfig(BaseModel):
    """Declarative policy configuration for a specific agent role or Non-Human Identity."""

    allowed_capabilities: List[Capability] = Field(
        default_factory=list, description="Capabilities granted to this role"
    )
    max_delegation_depth: int = Field(
        default=2, ge=0, description="Maximum sub-agent delegation depth permitted"
    )
    rate_limit_per_minute: int = Field(
        default=60, ge=1, description="Maximum operational tool calls allowed per minute"
    )
    requires_consensus: bool = Field(
        default=False, description="Whether actions by this role require dual-agent consensus"
    )
    requires_human_approval: bool = Field(
        default=False, description="Whether actions by this role require human-in-the-loop approval"
    )

    @field_validator("allowed_capabilities", mode="before")
    @classmethod
    def parse_capabilities(cls, v: Any) -> List[Capability]:
        """Convert string list into Capability enums."""
        if isinstance(v, list):
            parsed: List[Capability] = []
            for item in v:
                if isinstance(item, Capability):
                    parsed.append(item)
                elif isinstance(item, str):
                    try:
                        parsed.append(Capability[item.strip().upper()])
                    except KeyError:
                        try:
                            parsed.append(Capability(item.strip().lower()))
                        except ValueError:
                            raise ValueError(f"Unknown Capability identifier: '{item}'")
            return parsed
        return v


class NetworkPolicyConfig(BaseModel):
    """Network egress restrictions defined in declarative policy."""

    allowed_domains: List[str] = Field(
        default_factory=list, description="Explicitly whitelisted domains or wildcard patterns"
    )
    blocked_cidrs: List[str] = Field(
        default_factory=list, description="Explicitly blocked IP ranges or CIDR blocks"
    )


class GlobalPolicyConfig(BaseModel):
    """Global operational controls across all agents."""

    fail_closed: bool = Field(default=True, description="Fail closed on security validation exceptions")
    max_workflow_steps: int = Field(
        default=15, ge=1, description="Maximum steps allowed per autonomous workflow execution"
    )


class DeclarativePolicySchema(BaseModel):
    """Top-level declarative policy schema."""

    version: str = Field(default="2.0", description="Policy schema version")
    global_settings: GlobalPolicyConfig = Field(
        default_factory=GlobalPolicyConfig, alias="global", description="Global parameters"
    )
    roles: Dict[str, RolePolicyConfig] = Field(
        default_factory=dict, description="Role-to-capability mappings"
    )
    network: NetworkPolicyConfig = Field(
        default_factory=NetworkPolicyConfig, description="Egress network policy rules"
    )

    model_config = {"populate_by_name": True}


class DeclarativePolicyEngine:
    """Hot-reloadable declarative security policy engine for distributed agent swarms."""

    DEFAULT_POLICY_YAML = """
version: "2.0"
global:
  fail_closed: true
  max_workflow_steps: 15
roles:
  researcher:
    allowed_capabilities: [READ_PUBLIC]
    max_delegation_depth: 1
    rate_limit_per_minute: 20
  coder:
    allowed_capabilities: [READ_PUBLIC, READ_PRIVATE, WRITE_FILE, EXECUTE_CODE]
    max_delegation_depth: 2
    rate_limit_per_minute: 30
  deployer:
    allowed_capabilities: [READ_PRIVATE, WRITE_DATABASE, EXECUTE_CODE, NETWORK_EXTERNAL]
    max_delegation_depth: 1
    requires_consensus: true
    requires_human_approval: true
  db_admin:
    allowed_capabilities: [READ_PRIVATE, WRITE_DATABASE]
    requires_consensus: true
    requires_human_approval: true
network:
  allowed_domains: ["*.github.com", "api.internal.corp"]
  blocked_cidrs: ["10.0.0.0/8", "169.254.0.0/16", "127.0.0.0/8"]
"""

    def __init__(self, policy_path: Optional[str] = None) -> None:
        """Initialize policy engine and load either file or default policy."""
        self._policy_path: Optional[str] = policy_path
        self._policy: DeclarativePolicySchema = self.load_policy_string(self.DEFAULT_POLICY_YAML)
        if policy_path and os.path.exists(policy_path):
            self.load_policy_file(policy_path)

    def load_policy_file(self, path: str) -> DeclarativePolicySchema:
        """Load and validate declarative policy from a YAML or JSON file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Policy file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        self._policy = self.load_policy_string(content)
        self._policy_path = path
        logger.info(f"DeclarativePolicyEngine: Successfully loaded policy file '{path}'")
        return self._policy

    def load_policy_string(self, content: str) -> DeclarativePolicySchema:
        """Parse YAML/JSON content and validate against DeclarativePolicySchema."""
        try:
            raw_data = yaml.safe_load(content)
            if not isinstance(raw_data, dict):
                raise ValueError("Declarative policy content must parse to a dictionary root.")
            policy = DeclarativePolicySchema.model_validate(raw_data)
            self._policy = policy
            return policy
        except Exception as exc:
            logger.error(f"DeclarativePolicyEngine parsing error: {exc}")
            raise ValueError(f"Failed to parse declarative policy: {exc}") from exc

    def reload(self) -> DeclarativePolicySchema:
        """Hot-reload policy from disk without restarting the host process."""
        if not self._policy_path:
            logger.warning("DeclarativePolicyEngine: No policy file path configured to reload.")
            return self._policy
        return self.load_policy_file(self._policy_path)

    def evaluate_role_permission(
        self, role: str, capability: Capability
    ) -> Tuple[bool, str]:
        """Evaluate if a role possesses permission for a given capability."""
        normalized_role = role.strip().lower()
        role_config = self._policy.roles.get(normalized_role)
        if not role_config:
            return (
                False,
                f"ROLE_NOT_DEFINED: Role '{role}' is not declared in declarative policy schema.",
            )

        if capability not in role_config.allowed_capabilities:
            return (
                False,
                f"CAPABILITY_NOT_PERMITTED_FOR_ROLE: Capability '{capability.value}' is not granted to role '{role}'.",
            )

        return True, f"ROLE_PERMISSION_GRANTED: Capability '{capability.value}' allowed for role '{role}'."

    def get_role_config(self, role: str) -> Optional[RolePolicyConfig]:
        """Retrieve declarative configuration for a specific role."""
        return self._policy.roles.get(role.strip().lower())

    def get_policy(self) -> DeclarativePolicySchema:
        """Return the current active policy schema."""
        return self._policy
