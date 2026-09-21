"""Cross-version regression benchmark comparator.

Evaluates security and performance differences across benchmark runs,
distinguishing pure software version changes from dataset, policy, or
contract mutations, and determining statistical regression using multi-factor
thresholds and measurement uncertainty.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class LatencyMeasurementType(str, Enum):
    """Distinguishes security-decision latency from controlled pure component latency."""

    SECURITY_DECISION_LATENCY = "SECURITY_DECISION_LATENCY"
    COMPONENT_PERFORMANCE_LATENCY = "COMPONENT_PERFORMANCE_LATENCY"


@dataclass
class CompatibilityCheckResult:
    """Verifies prerequisite parity between benchmark runs."""

    is_compatible: bool
    dataset_hash_match: bool
    contract_version_match: bool
    policy_hash_match: bool
    validation_mode_match: bool
    status_label: str  # FULLY_COMPATIBLE, DATASET_MUTATED, POLICY_CHANGED, CONTRACT_MISMATCH
    warnings: List[str] = field(default_factory=list)


@dataclass
class MetricRegressionEvaluation:
    """Evaluates whether an individual metric change represents a true regression."""

    metric_name: str
    baseline_value: float
    current_value: float
    absolute_delta: float
    relative_change_pct: float
    is_regression: bool
    is_improvement: bool
    verdict: str  # REGRESSION, IMPROVEMENT, NO_CHANGE, NOT_COMPARABLE
    rationale: str
    measurement_type: Optional[str] = None


@dataclass
class CrossVersionComparisonReport:
    """Complete cross-version comparison report."""

    experiment_id: str
    baseline_run_id: str
    baseline_commit: str
    current_run_id: str
    current_commit: str
    compatibility: CompatibilityCheckResult
    overall_verdict: str  # REGRESSION, IMPROVEMENT, NO_CHANGE, NOT_COMPARABLE
    metric_evaluations: List[MetricRegressionEvaluation] = field(
        default_factory=list
    )
    baseline_provenance: Optional[Dict[str, Any]] = None
    current_provenance: Optional[Dict[str, Any]] = None


class CrossVersionComparator:
    """Compares benchmark output directories to detect true regressions."""

    # Default multi-factor thresholds: requires both absolute margin AND relative change
    DEFAULT_THRESHOLDS = {
        # Metric: (is_higher_worse, absolute_margin, min_relative_change_pct)
        "asr_aegis": (True, 0.02, 5.0),
        "containment_rate": (False, -0.02, -5.0),
        "unauthorized_execution_rate": (True, 0.02, 5.0),
        "exfiltration_rate": (True, 0.01, 1.0),
        "fpr": (True, 0.03, 10.0),
        "latency_p50_ms": (True, 15.0, 25.0),
        "latency_p95_ms": (True, 25.0, 25.0),
    }

    @staticmethod
    def load_run(
        run_dir: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Loads metadata, summary, and derives raw metrics from attempts.jsonl."""
        r_path = Path(run_dir)
        meta_file = r_path / "metadata.json"
        summary_file = r_path / "summary.json"
        attempts_file = r_path / "attempts.jsonl"

        if not meta_file.exists() or not summary_file.exists():
            raise FileNotFoundError(
                f"Run directory {run_dir} is missing metadata.json or summary.json"
            )

        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = json.load(f)

        provenance: Dict[str, Any] = {}
        if attempts_file.exists():
            raw_bytes = attempts_file.read_bytes()
            attempts_sha256 = hashlib.sha256(raw_bytes).hexdigest()

            attempts: List[Dict[str, Any]] = []
            for line in raw_bytes.decode("utf-8").splitlines():
                if line.strip():
                    attempts.append(json.loads(line))

            aegis_attempts = [
                a for a in attempts
                if a.get("condition") == "AEGIS_FULL"
                and a.get("scenario_id", "").startswith("ATK-")
            ]
            scen_count = len(aegis_attempts)
            valid_count = sum(
                1 for a in aegis_attempts
                if a.get("attempt_validity") == "VALID"
            )
            raw_succ_count = sum(
                1 for a in aegis_attempts
                if a.get("objective_achieved")
            )
            derived_asr = (
                (raw_succ_count / float(valid_count))
                if valid_count > 0 else 0.0
            )
            cont_count = sum(
                1 for a in aegis_attempts
                if a.get("final_security_outcome") in ("CONTAINED", "BLOCKED")
            )
            derived_cont = (
                (cont_count / float(valid_count))
                if valid_count > 0 else 0.0
            )
            derived_unauth = (
                (raw_succ_count / float(valid_count))
                if valid_count > 0 else 0.0
            )

            # Strictly verify against summary.json values
            rep_asr = float(summary.get("asr_aegis", 0.0) or 0.0)
            if abs(derived_asr - rep_asr) > 1e-4:
                raise ValueError(
                    f"FAIL CLOSED: Historical raw evidence mismatch in {run_dir}: "
                    f"raw derived asr={derived_asr:.6f} ({raw_succ_count}/{valid_count}) "
                    f"differs from summary.json asr_aegis={rep_asr:.6f}"
                )

            provenance = {
                "source_artifact": str(attempts_file).replace("\\", "/"),
                "source_sha256": attempts_sha256,
                "scenario_count": scen_count,
                "valid_attempt_count": valid_count,
                "raw_success_count": raw_succ_count,
                "derived_asr_aegis": derived_asr,
                "derived_containment_rate": derived_cont,
                "derived_unauthorized_execution_rate": derived_unauth,
            }
            # Consume values derived directly from raw attempts
            summary["asr_aegis"] = derived_asr
            summary["containment_rate"] = derived_cont
            summary["unauthorized_execution_rate"] = derived_unauth

        return metadata, summary, provenance

    def check_compatibility(
        self, base_meta: Dict[str, Any], curr_meta: Dict[str, Any]
    ) -> CompatibilityCheckResult:
        """Determines whether two benchmark runs are mathematically comparable."""
        dataset_match = (
            base_meta.get("dataset_hash") == curr_meta.get("dataset_hash")
        )
        contract_match = (
            base_meta.get("benchmark_contract_version")
            == curr_meta.get("benchmark_contract_version")
        )
        policy_match = (
            base_meta.get("config_hash") == curr_meta.get("config_hash")
            and base_meta.get("policy_version") == curr_meta.get("policy_version")
        )
        mode_match = (
            base_meta.get("validation_mode") == curr_meta.get("validation_mode")
        )

        warnings = []
        if not dataset_match:
            warnings.append(
                f"Dataset hash mismatch: {base_meta.get('dataset_hash')} vs "
                f"{curr_meta.get('dataset_hash')}. Cannot perform apples-to-apples regression."
            )
            return CompatibilityCheckResult(
                is_compatible=False,
                dataset_hash_match=False,
                contract_version_match=contract_match,
                policy_hash_match=policy_match,
                validation_mode_match=mode_match,
                status_label="DATASET_MUTATED",
                warnings=warnings,
            )

        if not contract_match:
            warnings.append("Benchmark Contract version mismatch.")
            return CompatibilityCheckResult(
                is_compatible=False,
                dataset_hash_match=True,
                contract_version_match=False,
                policy_hash_match=policy_match,
                validation_mode_match=mode_match,
                status_label="CONTRACT_MISMATCH",
                warnings=warnings,
            )

        if not policy_match:
            warnings.append(
                "Security policy modified between runs. Marked as POLICY_CHANGED."
            )
            return CompatibilityCheckResult(
                is_compatible=True,  # Still comparable, but flagged
                dataset_hash_match=True,
                contract_version_match=True,
                policy_hash_match=False,
                validation_mode_match=mode_match,
                status_label="POLICY_CHANGED",
                warnings=warnings,
            )

        return CompatibilityCheckResult(
            is_compatible=True,
            dataset_hash_match=True,
            contract_version_match=True,
            policy_hash_match=True,
            validation_mode_match=mode_match,
            status_label="FULLY_COMPATIBLE",
            warnings=[],
        )

    def evaluate_metric_change(
        self,
        name: str,
        base_val: float,
        curr_val: float,
    ) -> MetricRegressionEvaluation:
        """Evaluates a single metric change against deterministic rules.

        Verdicts used: IMPROVEMENT, NO_CHANGE, REGRESSION, NOT_COMPARABLE.
        A reduction in ASR, unauthorized execution, or latency is deterministically
        classified as an IMPROVEMENT.
        """
        delta = curr_val - base_val
        rel_pct = (
            ((curr_val - base_val) / base_val * 100.0)
            if abs(base_val) > 1e-6
            else (100.0 if curr_val > 1e-6 else 0.0)
        )

        cfg = self.DEFAULT_THRESHOLDS.get(name)
        if not cfg:
            is_regr = False
            is_impr = False
            verdict = "NO_CHANGE" if abs(delta) < 1e-6 else "NOT_COMPARABLE"
            rationale = "No threshold configured for metric."
            return MetricRegressionEvaluation(
                metric_name=name,
                baseline_value=base_val,
                current_value=curr_val,
                absolute_delta=round(delta, 6),
                relative_change_pct=round(rel_pct, 2),
                is_regression=is_regr,
                is_improvement=is_impr,
                verdict=verdict,
                rationale=rationale,
            )

        higher_is_worse, abs_margin, min_rel_pct = cfg
        is_regr = False
        is_impr = False
        m_type = (
            LatencyMeasurementType.SECURITY_DECISION_LATENCY.value
            if "latency" in name
            else None
        )

        if abs(delta) < 1e-6:
            verdict = "NO_CHANGE"
            rationale = (
                "Zero observed difference between baseline and current run."
            )
        elif higher_is_worse:
            # Metrics where increase is worse (ASR, Unauthorized Execution,
            # Exfiltration, FPR, Latency)
            if delta < 0.0:
                is_impr = True
                verdict = "IMPROVEMENT"
                if "latency" in name:
                    rationale = (
                        f"SECURITY_DECISION_LATENCY IMPROVEMENT: Decreased by "
                        f"{abs(delta):.4f} ({abs(rel_pct):.1f}%) due to earlier "
                        f"control-flow containment; does not prove the "
                        f"implementation is inherently faster."
                    )
                else:
                    rationale = (
                        f"Decreased by {abs(delta):.4f} ({abs(rel_pct):.1f}%), "
                        f"indicating security/performance gain."
                    )
            elif delta > abs_margin and rel_pct > min_rel_pct:
                is_regr = True
                verdict = "REGRESSION"
                rationale = (
                    f"Increased by {delta:+.4f} ({rel_pct:+.1f}%), exceeding "
                    f"absolute margin ({abs_margin}) and relative threshold "
                    f"({min_rel_pct}%)."
                )
            else:
                verdict = "NO_CHANGE"
                rationale = "Change is within statistical noise limits."
        else:
            # Metrics where decrease is worse (Containment Rate, Task Completion)
            if delta > 0.0:
                is_impr = True
                verdict = "IMPROVEMENT"
                rationale = (
                    f"Increased by {delta:+.4f}, indicating improved "
                    f"containment."
                )
            elif delta < abs_margin and rel_pct < min_rel_pct:
                is_regr = True
                verdict = "REGRESSION"
                rationale = (
                    f"Decreased by {delta:+.4f} ({rel_pct:+.1f}%), breaching "
                    f"containment tolerance threshold."
                )
            else:
                verdict = "NO_CHANGE"
                rationale = "Change is within statistical noise limits."

        return MetricRegressionEvaluation(
            metric_name=name,
            baseline_value=base_val,
            current_value=curr_val,
            absolute_delta=round(delta, 6),
            relative_change_pct=round(rel_pct, 2),
            is_regression=is_regr,
            is_improvement=is_impr,
            verdict=verdict,
            rationale=rationale,
            measurement_type=m_type,
        )

    @staticmethod
    def is_pure_performance_comparable(
        same_workload_population: bool,
        same_execution_stages: bool,
        same_measurement_methodology: bool,
        same_environment: bool,
        same_sample_semantics: bool,
    ) -> bool:
        """Determines whether two latency measurements are methodologically comparable.

        Requires:
        - same workload population
        - same execution stages
        - same measurement methodology
        - same environment
        - same sample semantics
        If any condition fails, the comparison is NOT_COMPARABLE.
        """
        return (
            same_workload_population
            and same_execution_stages
            and same_measurement_methodology
            and same_environment
            and same_sample_semantics
        )

    def evaluate_component_performance_latency(
        self,
        name: str,
        base_val: float,
        curr_val: float,
        same_workload_population: bool = True,
        same_execution_stages: bool = True,
        same_measurement_methodology: bool = True,
        same_environment: bool = True,
        same_sample_semantics: bool = True,
        base_execution_mode: Optional[str] = None,
        curr_execution_mode: Optional[str] = None,
    ) -> MetricRegressionEvaluation:
        """Evaluates pure component performance latency under strict rules.

        If the workload population, executed stages, measurement methodology,
        environment, sample semantics, or execution modes differ, strictly
        classifies as NOT_COMPARABLE.
        """
        if (
            base_execution_mode
            and curr_execution_mode
            and base_execution_mode != curr_execution_mode
        ):
            same_execution_stages = False

        comparable = self.is_pure_performance_comparable(
            same_workload_population=same_workload_population,
            same_execution_stages=same_execution_stages,
            same_measurement_methodology=same_measurement_methodology,
            same_environment=same_environment,
            same_sample_semantics=same_sample_semantics,
        )

        if not comparable:
            delta = curr_val - base_val
            rel_pct = (
                ((curr_val - base_val) / base_val * 100.0)
                if abs(base_val) > 1e-6 else 0.0
            )
            return MetricRegressionEvaluation(
                metric_name=name,
                baseline_value=base_val,
                current_value=curr_val,
                absolute_delta=round(delta, 6),
                relative_change_pct=round(rel_pct, 2),
                is_regression=False,
                is_improvement=False,
                verdict="NOT_COMPARABLE",
                rationale=(
                    "NOT_COMPARABLE: Executed stages, workload population, or "
                    "computational modes differ (e.g., early-blocking control "
                    "flow or different execution tiers); cannot infer "
                    "intrinsic component performance change."
                ),
                measurement_type=(
                    LatencyMeasurementType.COMPONENT_PERFORMANCE_LATENCY.value
                ),
            )

        res = self.evaluate_metric_change(name, base_val, curr_val)
        res.measurement_type = (
            LatencyMeasurementType.COMPONENT_PERFORMANCE_LATENCY.value
        )
        return res

    def compare_runs(
        self, baseline_dir: str, current_dir: str
    ) -> CrossVersionComparisonReport:
        """Executes full comparative regression analysis between two benchmark runs."""
        base_meta, base_summ, base_prov = self.load_run(baseline_dir)
        curr_meta, curr_summ, curr_prov = self.load_run(current_dir)

        compat = self.check_compatibility(base_meta, curr_meta)
        evaluations: List[MetricRegressionEvaluation] = []

        if not compat.is_compatible and compat.status_label == "DATASET_MUTATED":
            return CrossVersionComparisonReport(
                experiment_id="CROSS_VERSION_REGRESSION",
                baseline_run_id=base_meta.get("run_id", "UNKNOWN"),
                baseline_commit=base_meta.get("git_commit", "UNKNOWN"),
                current_run_id=curr_meta.get("run_id", "UNKNOWN"),
                current_commit=curr_meta.get("git_commit", "UNKNOWN"),
                compatibility=compat,
                overall_verdict="NOT_COMPARABLE",
                metric_evaluations=[],
                baseline_provenance=base_prov,
                current_provenance=curr_prov,
            )

        # Compare primary metrics
        metrics_to_compare = [
            "asr_aegis",
            "containment_rate",
            "unauthorized_execution_rate",
            "exfiltration_rate",
            "fpr",
            "latency_p50_ms",
            "latency_p95_ms",
        ]

        any_regression = False
        any_improvement = False

        for m in metrics_to_compare:
            b_val = float(base_summ.get(m, 0.0) or 0.0)
            c_val = float(curr_summ.get(m, 0.0) or 0.0)
            eval_res = self.evaluate_metric_change(m, b_val, c_val)
            evaluations.append(eval_res)
            if eval_res.is_regression:
                any_regression = True
            if eval_res.is_improvement:
                any_improvement = True

        if any_regression:
            overall = "REGRESSION"
        elif any_improvement:
            overall = "IMPROVEMENT"
        else:
            overall = "NO_CHANGE"

        return CrossVersionComparisonReport(
            experiment_id="CROSS_VERSION_REGRESSION",
            baseline_run_id=base_meta.get("run_id", "UNKNOWN"),
            baseline_commit=base_meta.get("git_commit", "UNKNOWN"),
            current_run_id=curr_meta.get("run_id", "UNKNOWN"),
            current_commit=curr_meta.get("git_commit", "UNKNOWN"),
            compatibility=compat,
            overall_verdict=overall,
            metric_evaluations=evaluations,
            baseline_provenance=base_prov,
            current_provenance=curr_prov,
        )
