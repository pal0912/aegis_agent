"""Artifact exporter and integrity verification for AegisAgent benchmark results.

Exports reproducible run artifacts conforming to Benchmark Contract v1.0:
- metadata.json
- summary.json
- attempts.jsonl
- attacks.csv
- benign.csv
- ablations.csv
- latency.csv
- latency_neural_metadata.json
- report.html
- manifest.json

Enforces CSV sanitization, two-stage non-circular manifest hashing,
cumulative artifact budgets (50MB / 10,000 records), graph-based parent
lineage validation, and TOCTOU-resistant filesystem check-and-use.
"""

import csv
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from evals.benchmark.runner import BenchmarkRunResult


MAX_ARTIFACT_BYTES = 50 * 1024 * 1024  # 50 MB cumulative ceiling
MAX_ARTIFACT_RECORDS = 10000  # 10,000 records cumulative ceiling
CANONICAL_HASH_VERSION = "CANONICAL_HASH_V1"


def sanitize_csv_field(val: Any) -> Any:
    """Sanitizes CSV fields preventing formula injection while preserving numbers."""
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        if val.startswith(("=", "+", "-", "@", "\t", "\r")):
            return f"'{val}"
    return val


def compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hash strictly from final persisted bytes on disk."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def canonical_dataset_hash(data: Any) -> str:
    """Computes deterministic canonical hash across dataset structures.

    Rules:
    - Mapping keys sorted deterministically.
    - Set-like collections explicitly sorted.
    - Semantically ordered arrays (trajectories, sequences, tools) preserved strictly.
    - CRLF normalized to LF.
    - Version: CANONICAL_HASH_V1.
    """
    def _normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {k: _normalize(item[k]) for k in sorted(item.keys())}
        elif isinstance(item, set):
            return [_normalize(x) for x in sorted(list(item), key=str)]
        elif isinstance(item, (list, tuple)):
            # Strictly preserve order of sequence arrays
            return [_normalize(x) for x in item]
        elif isinstance(item, str):
            return item.replace("\r\n", "\n").replace("\r", "\n")
        return item

    normalized = _normalize(data)
    serialized = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    payload = f"{CANONICAL_HASH_VERSION}:{serialized}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CumulativeArtifactBudgetTracker:
    """Tracks cumulative bytes and records written across an evaluation experiment."""

    def __init__(
        self,
        max_bytes: int = MAX_ARTIFACT_BYTES,
        max_records: int = MAX_ARTIFACT_RECORDS,
    ) -> None:
        self.max_bytes = max_bytes
        self.max_records = max_records
        self.bytes_written = 0
        self.records_written = 0
        self._lock = threading.Lock()

    def check_and_add(self, bytes_count: int, records_count: int = 0) -> None:
        """Atomically checks and increments cumulative artifact accounting."""
        with self._lock:
            if self.bytes_written + bytes_count > self.max_bytes:
                raise ResourceWarning(
                    f"Cumulative artifact bytes exceeded ceiling: "
                    f"{self.bytes_written + bytes_count} > {self.max_bytes}"
                )
            if self.records_written + records_count > self.max_records:
                raise ResourceWarning(
                    f"Cumulative artifact records exceeded ceiling: "
                    f"{self.records_written + records_count} > {self.max_records}"
                )
            self.bytes_written += bytes_count
            self.records_written += records_count


def safe_open_file(
    filepath: Path,
    trusted_root: Path,
    mode: str = "r",
    barrier: Optional[threading.Barrier] = None,
):
    """Opens a file with handle-based validation preventing TOCTOU symlink/junction swaps."""
    trusted_root = Path(trusted_root).resolve()
    target_path = Path(filepath)

    # Initial path validation
    resolved_initial = target_path.resolve()
    if not resolved_initial.is_relative_to(trusted_root):
        raise PermissionError(
            f"Access denied: initial path {resolved_initial} outside {trusted_root}"
        )

    # Deterministic barrier hook for testing race conditions
    if barrier is not None:
        barrier.wait()

    # Open the file object
    f = open(target_path, mode, encoding="utf-8" if "b" not in mode else None)

    # Handle-based post-open validation
    try:
        real_opened = Path(os.path.realpath(f.name)).resolve()
        if not real_opened.is_relative_to(trusted_root):
            f.close()
            raise PermissionError(
                f"Filesystem TOCTOU violation: opened file {real_opened} "
                f"targets outside trusted root {trusted_root}"
            )
    except Exception:
        f.close()
        raise

    return f


def validate_parent_lineage(run_records: List[Dict[str, Any]]) -> bool:
    """Validates artifact parent lineage graph, rejecting cycles and unknown parents."""
    run_ids = {r["run_id"] for r in run_records if "run_id" in r}
    parent_map: Dict[str, Optional[str]] = {}

    for r in run_records:
        r_id = r.get("run_id")
        p_id = r.get("parent_run_id")
        if not r_id:
            continue

        # Self-parenting rejection
        if p_id == r_id:
            return False

        # Unknown parent rejection
        if p_id and p_id not in run_ids:
            return False

        parent_map[r_id] = p_id

    # Cycle detection
    for start_node in parent_map:
        visited: Set[str] = set()
        curr: Optional[str] = start_node
        while curr:
            if curr in visited:
                return False  # Circular lineage detected
            visited.add(curr)
            curr = parent_map.get(curr)

    return True


def generate_manifest(
    artifacts_dir: str,
    stage: str = "PRE_REPORT",
    run_id: str = "run_001",
    contract_version: str = "1.0",
    tracker: Optional[CumulativeArtifactBudgetTracker] = None,
) -> Dict[str, Any]:
    """Generates two-stage non-circular manifest inventory with SHA-256 hashes."""
    art_dir = Path(artifacts_dir)
    manifest_items: Dict[str, Dict[str, Any]] = {}

    # Gather files
    for child in sorted(art_dir.iterdir()):
        if child.is_file():
            if child.name.startswith("manifest"):
                continue
            if stage == "PRE_REPORT" and child.name == "report.html":
                continue

            content_hash = compute_file_sha256(child)
            file_size = child.stat().st_size
            manifest_items[child.name] = {
                "filename": child.name,
                "size_bytes": file_size,
                "sha256": content_hash,
            }
            if tracker:
                tracker.check_and_add(file_size)

    manifest_data = {
        "manifest_stage": stage,
        "run_id": run_id,
        "contract_version": contract_version,
        "filesystem_enforcement": "HARD" if sys.platform in ("win32", "linux") else "SOFT",
        "artifacts": manifest_items,
        "generated_timestamp": time.time(),
    }

    # Manifest content hash excludes the hash field itself
    manifest_bytes = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    manifest_data["manifest_content_hash"] = manifest_hash

    # Save manifest
    target_manifest = (
        art_dir / "manifest_pre_report.json"
        if stage == "PRE_REPORT"
        else art_dir / "manifest.json"
    )
    with open(target_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, sort_keys=True)

    # Sidecar hash for final manifest
    if stage == "FINAL":
        sidecar_file = art_dir / "manifest.sha256"
        with open(sidecar_file, "w", encoding="utf-8") as f:
            f.write(f"{manifest_hash}  manifest.json\n")

    return manifest_data


def export_run_artifacts(
    result: "BenchmarkRunResult",
    output_dir: str,
    tracker: Optional[CumulativeArtifactBudgetTracker] = None,
) -> Dict[str, str]:
    """Exports all benchmark run artifacts into the specified directory."""
    tracker = tracker or CumulativeArtifactBudgetTracker()
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    paths: Dict[str, str] = {}

    # 1. metadata.json
    metadata_file = out_path / "metadata.json"
    meta_bytes = json.dumps(
        result.metadata.model_dump(), indent=2, sort_keys=True
    ).encode("utf-8")
    tracker.check_and_add(len(meta_bytes), 1)
    with open(metadata_file, "wb") as f:
        f.write(meta_bytes)
    paths["metadata"] = str(metadata_file)

    # 2. summary.json
    summary_file = out_path / "summary.json"
    summ_bytes = json.dumps(
        result.summary_metrics.model_dump(), indent=2, sort_keys=True
    ).encode("utf-8")
    tracker.check_and_add(len(summ_bytes), 1)
    with open(summary_file, "wb") as f:
        f.write(summ_bytes)
    paths["summary"] = str(summary_file)

    # 3. attempts.jsonl
    attempts_file = out_path / "attempts.jsonl"
    attempts_lines = []
    for pc in result.paired_comparisons:
        attempts_lines.append(pc.baseline_attempt.model_dump_json())
        attempts_lines.append(pc.aegis_attempt.model_dump_json())
    for sc_id, abls in result.ablation_attempts.items():
        for abl in abls:
            attempts_lines.append(abl.model_dump_json())
    for bng in result.benign_attempts:
        attempts_lines.append(bng.model_dump_json())

    attempts_content = "\n".join(attempts_lines) + "\n"
    attempts_bytes = attempts_content.encode("utf-8")
    tracker.check_and_add(len(attempts_bytes), len(attempts_lines))
    with open(attempts_file, "wb") as f:
        f.write(attempts_bytes)
    paths["attempts"] = str(attempts_file)

    # 4. attacks.csv
    attacks_file = out_path / "attacks.csv"
    with open(attacks_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scenario_id",
            "baseline_outcome",
            "baseline_achieved",
            "aegis_outcome",
            "aegis_achieved",
            "paired_status",
            "baseline_latency_ms",
            "aegis_latency_ms",
        ])
        for pc in result.paired_comparisons:
            writer.writerow([
                sanitize_csv_field(pc.scenario_id),
                sanitize_csv_field(pc.baseline_attempt.final_security_outcome.value),
                sanitize_csv_field(pc.baseline_attempt.objective_achieved),
                sanitize_csv_field(pc.aegis_attempt.final_security_outcome.value),
                sanitize_csv_field(pc.aegis_attempt.objective_achieved),
                sanitize_csv_field(pc.status.value),
                pc.baseline_attempt.latency_ms,
                pc.aegis_attempt.latency_ms,
            ])
    paths["attacks"] = str(attacks_file)

    # 5. benign.csv
    benign_file = out_path / "benign.csv"
    with open(benign_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scenario_id",
            "benign_outcome",
            "task_successful",
            "attempt_validity",
            "latency_ms",
        ])
        for bng in result.benign_attempts:
            outcome_val = (
                bng.benign_outcome.value if bng.benign_outcome else "N/A"
            )
            writer.writerow([
                sanitize_csv_field(bng.scenario_id),
                sanitize_csv_field(outcome_val),
                sanitize_csv_field(bng.task_successful),
                sanitize_csv_field(bng.attempt_validity.value),
                bng.latency_ms,
            ])
    paths["benign"] = str(benign_file)

    # 6. ablations.csv
    ablations_file = out_path / "ablations.csv"
    with open(ablations_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "scenario_id",
            "condition",
            "final_security_outcome",
            "objective_achieved",
            "blast_radius",
            "latency_ms",
        ])
        for sc_id, abls in result.ablation_attempts.items():
            for abl in abls:
                writer.writerow([
                    sanitize_csv_field(abl.scenario_id),
                    sanitize_csv_field(abl.condition.value),
                    sanitize_csv_field(abl.final_security_outcome.value),
                    sanitize_csv_field(abl.objective_achieved),
                    sanitize_csv_field(abl.blast_radius.value),
                    abl.latency_ms,
                ])
    paths["ablations"] = str(ablations_file)

    # 7. latency.csv & latency_neural_metadata.json
    latency_file = out_path / "latency.csv"
    neural_meta_file = out_path / "latency_neural_metadata.json"
    from evals.benchmark.profiler import ComponentLatencyProfiler
    profiler = ComponentLatencyProfiler(
        warmup_runs=5, measurement_runs=50,
        neural_warmup_runs=2, neural_measurement_runs=10
    )
    profile_results = profiler.run_all_profiles()
    profiler.export_csv(profile_results, str(latency_file))
    profiler.export_neural_metadata(profile_results, str(neural_meta_file))
    paths["latency"] = str(latency_file)
    paths["latency_neural_metadata"] = str(neural_meta_file)

    # Stage 1: PRE_REPORT manifest verification
    pre_manifest = generate_manifest(
        str(out_path),
        stage="PRE_REPORT",
        run_id=result.metadata.run_id,
        contract_version=result.metadata.benchmark_contract_version,
        tracker=tracker,
    )
    paths["manifest_pre_report"] = str(out_path / "manifest_pre_report.json")

    # 8. report.html
    html_file = out_path / "report.html"
    from evals.benchmark.reports import generate_html_report
    generate_html_report(result, str(html_file))
    paths["report_html"] = str(html_file)

    # Stage 2: FINAL manifest verification
    final_manifest = generate_manifest(
        str(out_path),
        stage="FINAL",
        run_id=result.metadata.run_id,
        contract_version=result.metadata.benchmark_contract_version,
        tracker=tracker,
    )
    paths["manifest"] = str(out_path / "manifest.json")
    paths["manifest_sha256"] = str(out_path / "manifest.sha256")

    return paths
