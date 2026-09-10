"""Capability-based security model and privilege arbitration engine for AegisAgent V2.

Maps agent tool proposals to fine-grained operational capabilities and enforces
deterministic containment boundaries under tainted session states.
"""

import logging
import re
from typing import Any, Dict, Optional, Set

from aegis.types import Capability

logger = logging.getLogger(__name__)


class CapabilityRegistry:
    """Registry and inference engine for operational tool capabilities."""

    # Default deterministic tool-to-capability mappings
    DEFAULT_TOOL_MAPPINGS: Dict[str, Capability] = {
        # Public Read / Safe Calculation
        "web_search": Capability.READ_PUBLIC,
        "get_weather": Capability.READ_PUBLIC,
        "search_docs": Capability.READ_PUBLIC,
        "browse_public": Capability.READ_PUBLIC,
        "calculate": Capability.READ_PUBLIC,
        "add_numbers": Capability.READ_PUBLIC,
        "calc": Capability.READ_PUBLIC,
        "math": Capability.READ_PUBLIC,
        # Private Read
        "read_file": Capability.READ_PRIVATE,
        "read_db": Capability.READ_PRIVATE,
        "query_database": Capability.READ_PRIVATE,
        "fetch_customer_record": Capability.READ_PRIVATE,
        "get_secret": Capability.READ_PRIVATE,
        "get_env": Capability.READ_PRIVATE,
        # File System Mutation
        "write_file": Capability.WRITE_FILE,
        "delete_file": Capability.WRITE_FILE,
        "append_file": Capability.WRITE_FILE,
        "unlink_file": Capability.WRITE_FILE,
        # Database Mutation
        "write_db": Capability.WRITE_DATABASE,
        "modify_database": Capability.WRITE_DATABASE,
        "insert_record": Capability.WRITE_DATABASE,
        "update_record": Capability.WRITE_DATABASE,
        "delete_record": Capability.WRITE_DATABASE,
        # Code & Shell Execution
        "execute_shell": Capability.EXECUTE_CODE,
        "run_bash": Capability.EXECUTE_CODE,
        "python_eval": Capability.EXECUTE_CODE,
        "run_terminal_command": Capability.EXECUTE_CODE,
        # Outbound External Messaging
        "send_email": Capability.SEND_EXTERNAL_MESSAGE,
        "send_slack_message": Capability.SEND_EXTERNAL_MESSAGE,
        "send_sms": Capability.SEND_EXTERNAL_MESSAGE,
        "trigger_webhook": Capability.SEND_EXTERNAL_MESSAGE,
        # Outbound Network & HTTP
        "http_request": Capability.NETWORK_EXTERNAL,
        "fetch_url": Capability.NETWORK_EXTERNAL,
        "download_file": Capability.NETWORK_EXTERNAL,
        "socket_connect": Capability.NETWORK_EXTERNAL,
        # Financial Actions
        "transfer_funds": Capability.FINANCIAL_ACTION,
        "charge_credit_card": Capability.FINANCIAL_ACTION,
        "execute_payment": Capability.FINANCIAL_ACTION,
        # Administrative Actions
        "drop_table": Capability.ADMIN,
        "grant_privilege": Capability.ADMIN,
        "revoke_privilege": Capability.ADMIN,
        "rotate_credential": Capability.ADMIN,
        "modify_access_control": Capability.ADMIN,
    }

    # Capabilities strictly prohibited when a session is tainted
    TAINTED_DISALLOWED_CAPABILITIES: Set[Capability] = {
        Capability.WRITE_FILE,
        Capability.WRITE_DATABASE,
        Capability.SEND_EXTERNAL_MESSAGE,
        Capability.EXECUTE_CODE,
        Capability.NETWORK_EXTERNAL,
        Capability.FINANCIAL_ACTION,
        Capability.ADMIN,
        Capability.READ_PRIVATE,
    }

    def __init__(self, custom_mappings: Optional[Dict[str, Capability]] = None) -> None:
        """Initialize capability registry with default and optional custom mappings."""
        self.mappings: Dict[str, Capability] = dict(self.DEFAULT_TOOL_MAPPINGS)
        self.manifests: Dict[str, Dict[str, Any]] = {}
        if custom_mappings:
            self.mappings.update(custom_mappings)

    def register_tool(
        self,
        tool_name: str,
        capability: Capability,
        manifest: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register or override a capability mapping and optional security manifest for a tool."""
        norm_name = tool_name.lower().strip()
        self.mappings[norm_name] = capability
        if manifest:
            self.manifests[norm_name] = dict(manifest)

    def get_tool_manifest(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve security manifest for a registered tool if present."""
        return self.manifests.get(tool_name.lower().strip())

    def infer_capability(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Capability:
        """Infer operational capability for a tool invocation based on name and arguments.

        Args:
            tool_name: Name of the tool to be invoked.
            arguments: Tool parameters and payload dictionary.

        Returns:
            Inferred Capability enum value (Capability.UNKNOWN if unclassified).
        """
        normalized_name = tool_name.lower().strip()

        # 1. Exact match in registered mappings
        if normalized_name in self.mappings:
            return self.mappings[normalized_name]

        args = arguments or {}
        arg_keys = set(k.lower() for k in args.keys())
        str_args = str(args).lower()

        # 2. Dangerous / High-Risk Argument-based inference (takes precedence over benign tool name heuristics)
        if any(k in arg_keys for k in ["command", "cmd", "script", "code", "bash_script"]):
            return Capability.EXECUTE_CODE

        if any(k in arg_keys for k in ["amount", "recipient_account", "card_number", "wire_routing"]):
            return Capability.FINANCIAL_ACTION

        if "sql" in arg_keys or "sql_query" in arg_keys:
            sql_text = str(args.get("sql", args.get("sql_query", ""))).upper()
            if any(w in sql_text for w in ["DROP ", "ALTER ", "TRUNCATE "]):
                return Capability.ADMIN
            if any(w in sql_text for w in ["INSERT ", "UPDATE ", "DELETE ", "REPLACE "]):
                return Capability.WRITE_DATABASE
            return Capability.READ_PRIVATE

        # 3. High-Risk Tool Name patterns
        if any(token in normalized_name for token in ["shell", "exec", "bash", "cmd", "eval", "terminal", "run_code"]):
            return Capability.EXECUTE_CODE

        if any(token in normalized_name for token in ["email", "mail", "sms", "slack", "notify", "message", "webhook"]):
            return Capability.SEND_EXTERNAL_MESSAGE

        if any(token in normalized_name for token in ["transfer", "pay", "charge", "fund", "wire", "invoice_pay", "billing"]):
            return Capability.FINANCIAL_ACTION

        if any(token in normalized_name for token in ["drop", "admin", "grant", "revoke", "rotate", "delete_user", "truncate"]):
            return Capability.ADMIN

        if any(token in normalized_name for token in ["http", "curl", "socket", "network", "fetch_url", "download", "post_api"]):
            return Capability.NETWORK_EXTERNAL

        if any(token in normalized_name for token in ["write_db", "modify_db", "insert", "update", "db_write", "sql_write"]):
            return Capability.WRITE_DATABASE

        if any(token in normalized_name for token in ["write", "create_file", "save_file", "delete_file", "remove_file", "unlink"]):
            return Capability.WRITE_FILE

        if any(token in normalized_name for token in ["read_db", "query_db", "get_secret", "env", "private", "customer", "credential", "auth_token"]):
            return Capability.READ_PRIVATE

        # 4. Contextual Argument-based checks
        if any(k in arg_keys for k in ["url", "endpoint", "webhook_url"]):
            if "query" in arg_keys and "search" in normalized_name:
                return Capability.READ_PUBLIC
            return Capability.NETWORK_EXTERNAL

        if "query" in arg_keys:
            sql_text = str(args.get("query", "")).upper()
            if any(w in sql_text for w in ["DROP ", "ALTER ", "TRUNCATE "]):
                return Capability.ADMIN
            if any(w in sql_text for w in ["INSERT ", "UPDATE ", "DELETE ", "REPLACE "]):
                return Capability.WRITE_DATABASE

        if any(k in arg_keys for k in ["file_path", "filename", "path"]):
            if any(token in normalized_name for token in ["write", "save", "edit", "append", "delete"]):
                return Capability.WRITE_FILE
            return Capability.READ_PRIVATE

        # 5. Benign name patterns (evaluated only if arguments are not high-risk)
        if any(token in normalized_name for token in ["search", "weather", "docs", "browse", "public_info", "calc", "math", "add_numbers", "sum"]):
            return Capability.READ_PUBLIC

        # Unknown / unclassified tool requires explicit registration or verification
        logger.warning("CapabilityRegistry: Tool '%s' is unregistered and unclassified -> UNKNOWN", tool_name)
        return Capability.UNKNOWN

    @classmethod
    def is_allowed_for_tainted_session(cls, capability: Capability) -> bool:
        """Evaluate if a capability is permissible when execution session is tainted.

        Tainted sessions are strictly prohibited from mutating persistence stores,
        executing shell/code, making outbound network requests, sending messages,
        performing financial transactions, reading private credentials, executing admin actions,
        or invoking unclassified tools.

        Args:
            capability: Requested operational Capability.

        Returns:
            True if permitted for tainted sessions (READ_PUBLIC only); False otherwise.
        """
        return capability == Capability.READ_PUBLIC
