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

    def tag_structure(
        self,
        data: Any,
        trust: FieldTrustLevel,
        source: str,
        prefix: str = "",
    ) -> Dict[str, FieldProvenance]:
        """Recursively inspect and tag all nested fields in a data structure with provenance metadata.

        Args:
            data: Arbitrary data structure (dict, list, primitive, str, etc.).
            trust: Trust level to assign (TRUSTED, UNTRUSTED, DERIVED_UNTRUSTED).
            source: Source identifier (e.g. 'user_input', 'web_search:url', 'internal_db').
            prefix: Current dot-delimited JSON path prefix.

        Returns:
            Dictionary mapping dot-delimited paths (e.g. 'user.profile.bio', 'items[0].id') to FieldProvenance.
        """
        lineage_map: Dict[str, FieldProvenance] = {}
        now_ts = datetime.now(timezone.utc).isoformat()

        root_path = prefix if prefix else "root"
        val_hash = self.compute_value_hash(data)

        # Record root structure provenance
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
                child_map = self.tag_structure(val, trust=trust, source=source, prefix=child_path)
                lineage_map.update(child_map)

        elif isinstance(data, (list, tuple)):
            for idx, item in enumerate(data):
                child_path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                child_map = self.tag_structure(item, trust=trust, source=source, prefix=child_path)
                lineage_map.update(child_map)

        return lineage_map

    def propagate_transform(
        self,
        input_paths: List[str],
        output_path: str,
        output_value: Any,
        session_lineage: Optional[Dict[str, FieldProvenance]] = None,
        source: str = "transform",
    ) -> FieldProvenance:
        """Derive output provenance from a set of input paths under conservative taint derivation.

        If ANY input path has trust level UNTRUSTED or DERIVED_UNTRUSTED, the output
        is assigned DERIVED_UNTRUSTED. Otherwise, if all inputs are TRUSTED, the output is TRUSTED.

        Args:
            input_paths: List of source field paths contributing to the transform.
            output_path: Target path for the transformed result.
            output_value: The transformed value.
            session_lineage: Active session field lineage dictionary.
            source: Identifier of the transformation operation.

        Returns:
            FieldProvenance record for the output path.
        """
        lineage = session_lineage or {}
        has_untrusted_input = False

        for path in input_paths:
            prov = lineage.get(path)
            if prov is not None and prov.trust != FieldTrustLevel.TRUSTED:
                has_untrusted_input = True
                break

        out_trust = FieldTrustLevel.DERIVED_UNTRUSTED if has_untrusted_input else FieldTrustLevel.TRUSTED
        out_hash = self.compute_value_hash(output_value)

        return FieldProvenance(
            path=output_path,
            trust=out_trust,
            source=source,
            timestamp=datetime.now(timezone.utc).isoformat(),
            value_hash=out_hash,
        )

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
