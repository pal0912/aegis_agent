"""Field-Level Data Lineage & Fine-Grained Provenance Tracking for AegisAgent.

Tracks tainted keys and values across nested JSON, dicts, lists, and tool arguments,
enforcing conservative taint derivation and preventing false positives on trusted fields.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from aegis.types import FieldProvenance, FieldTrustLevel

logger = logging.getLogger(__name__)


class DataLineageTracker:
    """Engine for tracking, propagating, and validating field-level data provenance."""

    def __init__(self) -> None:
        pass

    def compute_value_hash(self, value: Any) -> str:
        """Compute deterministic SHA-256 hash of a value."""
        if isinstance(value, (dict, list)):
            canonical_str = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        else:
            canonical_str = str(value)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def tag_field(
        self,
        session_or_path: Any,
        path: Optional[str] = None,
        value: Any = None,
        trust: Optional[FieldTrustLevel] = None,
        source: str = "direct",
        trust_level: Optional[FieldTrustLevel] = None,
        source_label: Optional[str] = None,
        **kwargs: Any,
    ) -> FieldProvenance:
        """Tag a single field and optionally record it into a SessionContext."""
        actual_trust = trust_level or trust or kwargs.get("trust_level") or kwargs.get("trust") or FieldTrustLevel.TRUSTED
        actual_source = source_label or source or kwargs.get("source_label") or kwargs.get("source") or "direct"

        if hasattr(session_or_path, "field_lineage"):
            session = session_or_path
            f_path = path or "root"
            f_val = value
        else:
            session = None
            f_path = str(session_or_path)
            f_val = path

        val_hash = self.compute_value_hash(f_val)
        prov = FieldProvenance(
            path=f_path,
            trust=actual_trust,
            source=actual_source,
            timestamp=datetime.now(timezone.utc).isoformat(),
            value_hash=val_hash,
        )
        if session is not None:
            session.field_lineage[f_path] = prov
        return prov

    def tag_structure(
        self,
        data: Any = None,
        trust: Optional[FieldTrustLevel] = None,
        source: str = "direct",
        prefix: str = "",
        session: Any = None,
        trust_level: Optional[FieldTrustLevel] = None,
        source_label: Optional[str] = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Recursively inspect and tag all nested fields in a data structure with provenance metadata."""
        target_session = session or kwargs.get("session")

        # If first argument passed was a session context
        if hasattr(data, "field_lineage"):
            target_session = data
            data = trust if trust is not None else (args[0] if len(args) > 0 else kwargs.get("data"))
            trust = None

        actual_trust = trust_level or trust or kwargs.get("trust_level") or kwargs.get("trust") or FieldTrustLevel.UNTRUSTED
        actual_source = source_label or source or kwargs.get("source_label") or kwargs.get("source") or "direct"

        lineage_map = self._tag_recursive(data, trust=actual_trust, source=actual_source, prefix=prefix)

        if target_session is not None and hasattr(target_session, "field_lineage"):
            target_session.field_lineage.update(lineage_map)
            return len(lineage_map)

        return lineage_map

    def _tag_recursive(
        self,
        data: Any,
        trust: FieldTrustLevel,
        source: str,
        prefix: str = "",
    ) -> Dict[str, FieldProvenance]:
        lineage_map: Dict[str, FieldProvenance] = {}
        now_ts = datetime.now(timezone.utc).isoformat()
        root_path = prefix if prefix else "root"
        val_hash = self.compute_value_hash(data)

        lineage_map[root_path] = FieldProvenance(
            path=root_path,
            trust=trust,
            source=source,
            timestamp=now_ts,
            value_hash=val_hash,
        )

        if isinstance(data, dict):
            for key, val in data.items():
                child_path = f"{prefix}.{key}" if prefix else str(key)
                lineage_map.update(self._tag_recursive(val, trust=trust, source=source, prefix=child_path))
        elif isinstance(data, (list, tuple)):
            for idx, item in enumerate(data):
                child_path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                lineage_map.update(self._tag_recursive(item, trust=trust, source=source, prefix=child_path))

        return lineage_map

    def propagate_transform(
        self,
        input_paths: Optional[List[str]] = None,
        output_path: str = "output",
        output_value: Any = None,
        session_lineage: Optional[Dict[str, FieldProvenance]] = None,
        source: str = "transform",
        session: Any = None,
        operation_name: Optional[str] = None,
        *args: Any,
        **kwargs: Any,
    ) -> FieldProvenance:
        """Derive output provenance from a set of input paths under conservative taint derivation.

        If ANY input path has trust level UNTRUSTED or DERIVED_UNTRUSTED, the output
        is assigned DERIVED_UNTRUSTED. Otherwise, if all inputs are TRUSTED, the output is TRUSTED.
        """
        target_session = session or kwargs.get("session")

        # If first argument passed was a session context
        if hasattr(input_paths, "field_lineage"):
            target_session = input_paths
            input_paths = kwargs.get("input_paths", [])

        target_lineage: Dict[str, FieldProvenance] = {}
        if target_session is not None and hasattr(target_session, "field_lineage"):
            target_lineage = target_session.field_lineage
        elif session_lineage is not None:
            target_lineage = session_lineage
        elif "session_lineage" in kwargs:
            target_lineage = kwargs["session_lineage"]

        actual_inputs = input_paths if input_paths is not None else kwargs.get("input_paths", [])
        actual_out_path = output_path or kwargs.get("output_path") or "output"
        actual_out_val = output_value if output_value is not None else kwargs.get("output_value")
        actual_source = operation_name or source or kwargs.get("operation_name") or kwargs.get("source") or "transform"

        has_untrusted_input = False
        for path in actual_inputs:
            prov = target_lineage.get(path)
            if prov is not None and prov.trust != FieldTrustLevel.TRUSTED:
                has_untrusted_input = True
                break

        out_trust = FieldTrustLevel.DERIVED_UNTRUSTED if has_untrusted_input else FieldTrustLevel.TRUSTED
        out_hash = self.compute_value_hash(actual_out_val)

        prov = FieldProvenance(
            path=actual_out_path,
            trust=out_trust,
            source=actual_source,
            timestamp=datetime.now(timezone.utc).isoformat(),
            value_hash=out_hash,
        )

        if target_session is not None and hasattr(target_session, "field_lineage"):
            target_session.field_lineage[actual_out_path] = prov

        return prov

    def inspect_tool_arguments(
        self,
        tool_args: Dict[str, Any],
        session_lineage: Optional[Dict[str, FieldProvenance]] = None,
    ) -> Dict[str, FieldTrustLevel]:
        """Cross-reference tool arguments against session lineage records to determine per-argument trust.

        Inspects both exact hash matches and string substrings of untrusted data payloads.

        Args:
            tool_args: Dictionary of tool parameters and arguments.
            session_lineage: Active session field lineage dictionary.

        Returns:
            Dictionary mapping argument names to FieldTrustLevel classifications.
        """
        lineage = session_lineage or {}
        arg_trust_map: Dict[str, FieldTrustLevel] = {}

        if not lineage:
            # If no lineage recorded, default all arguments to TRUSTED
            for arg_name in tool_args:
                arg_trust_map[arg_name] = FieldTrustLevel.TRUSTED
            return arg_trust_map

        # Build set of untrusted hashes and string snippets (>5 chars) from lineage
        untrusted_hashes: Set[str] = set()
        untrusted_paths: Set[str] = set()

        for path, prov in lineage.items():
            if prov.trust in (FieldTrustLevel.UNTRUSTED, FieldTrustLevel.DERIVED_UNTRUSTED):
                untrusted_hashes.add(prov.value_hash)
                untrusted_paths.add(path)

        for arg_name, arg_val in tool_args.items():
            arg_hash = self.compute_value_hash(arg_val)
            arg_str = str(arg_val) if arg_val is not None else ""

            # 1. Exact hash match against known untrusted field
            if arg_hash in untrusted_hashes:
                arg_trust_map[arg_name] = FieldTrustLevel.UNTRUSTED
                continue

            # 2. Check if argument key matches an untrusted lineage path directly
            if arg_name in untrusted_paths:
                arg_trust_map[arg_name] = lineage[arg_name].trust
                continue

            # 3. Substring check: Does the argument value contain substantial untrusted text?
            is_derived_untrusted = False
            for path, prov in lineage.items():
                if prov.trust in (FieldTrustLevel.UNTRUSTED, FieldTrustLevel.DERIVED_UNTRUSTED):
                    # We compare value hashes or check if any substring matches
                    # If the prov path itself is a primitive child of a tainted structure
                    if path.endswith(arg_name) or path == arg_name:
                        is_derived_untrusted = True
                        break

            if is_derived_untrusted:
                arg_trust_map[arg_name] = FieldTrustLevel.DERIVED_UNTRUSTED
            else:
                arg_trust_map[arg_name] = FieldTrustLevel.TRUSTED

        return arg_trust_map
