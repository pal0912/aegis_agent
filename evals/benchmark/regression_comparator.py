"""Cross-version regression benchmark comparator.

Evaluates security and performance differences across benchmark runs,
distinguishing pure software version changes from dataset, policy, or
contract mutations, and determining statistical regression using multi-factor
thresholds and measurement uncertainty.
"""

from dataclasses import asdict, dataclass, field
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
    verdict: str  # REGRESSION, IMPROVEMENT, EQUIVALENT, NOISE
    rationale: str


@dataclass
class CrossVersionComparisonReport:
    """Complete cross-version comparison report."""

    experiment_id: str
    baseline_run_id: str
    baseline_commit: str
    current_run_id: str
    current_commit: str
    compatibility: CompatibilityCheckResult
    overall_verdict: str  # REGRESSION_DETECTED, SECURITY_IMPROVEMENT, EQUIVALENT_WITHIN_NOISE, INCOMPARABLE
    metric_evaluations: List[MetricRegressionEvaluation] = field(
        default_factory=list
    )


class CrossVersionComparator:
    """Compares benchmark output directories to detect true regressions."""

    # Default multi-factor thresholds: requires both absolute margin AND relative change
    DEFAULT_THRESHOLDS = {
        # Metric: (is_higher_worse, absolute_margin, min_relative_change_pct)
        "asr_aegis": (True, 0.02, 5.0),  # Increase in Aegis ASR > 2.0% absolute and > 5% relative
        "containment_rate": (False, -0.02, -5.0),  # Drop in containment > 2.0% absolute
        "unauthorized_execution_rate": (True, 0.02, 5.0),
        "exfiltration_rate": (True, 0.01, 1.0),
        "fpr": (True, 0.03, 10.0),  # Benign FPR increase > 3.0% absolute
        "latency_p50_ms": (True, 15.0, 25.0),  # Latency P50 regression > 15ms and > 25%
        "latency_p95_ms": (True, 25.0, 25.0),
    }

    @staticmethod
    def load_run(run_dir: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Loads metadata.json and summary.json from a run directory."""
        r_path = Path(run_dir)
        meta_file = r_path / "metadata.json"
        summary_file = r_path / "summary.json"

        if not meta_file.exists() or not summary_file.exists():
            raise FileNotFoundError(
                f"Run directory {run_dir} is missing metadata.json or summary.json"
            )

        with open(meta_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        with open(summary_file, "r", encoding="utf-8") as f:
            summary = json.load(f)

        return metadata, summary

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
        """Evaluates a single metric change against multi-factor noise boundaries."""
        delta = curr_val - base_val
        rel_pct = (
            ((curr_val - base_val) / base_val * 100.0)
            if abs(base_val) > 1e-6
            else (100.0 if curr_val > 1e-6 else 0.0)
        )

        cfg = self.DEFAULT_THRESHOLDS.get(name)
        if not cfg:
            # Default evaluation
            is_regr = False
            is_impr = False
            verdict = "EQUIVALENT"
            rationale = "No threshold configured; recorded as observational."
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

        if higher_is_worse:
            # Metric where increase is bad (e.g. ASR, Exfil, Latency)
            if delta > abs_margin and rel_pct > min_rel_pct:
                is_regr = True
                verdict = "REGRESSION"
                rationale = (
                    f"Increased by {delta:+.4f} ({rel_pct:+.1f}%), exceeding "
                    f"absolute margin ({abs_margin}) and relative threshold ({min_rel_pct}%)."
                )
            elif delta < -abs_margin:
                is_impr = True
                verdict = "IMPROVEMENT"
                rationale = f"Decreased by {delta:+.4f} ({rel_pct:+.1f}%), indicating security/performance gain."
            else:
                verdict = "NOISE"
                rationale = "Within expected variance bounds; not a genuine regression."
        else:
            # Metric where decrease is bad (e.g. Containment, Task Completion)
            if delta < abs_margin and rel_pct < min_rel_pct:
                is_regr = True
                verdict = "REGRESSION"
                rationale = (
                    f"Decreased by {delta:+.4f} ({rel_pct:+.1f}%), breaching "
                    f"containment tolerance threshold."
                )
            elif delta > abs(abs_margin):
                is_impr = True
                verdict = "IMPROVEMENT"
                rationale = f"Increased by {delta:+.4f}, indicating improved containment."
            else:
                verdict = "NOISE"
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
        )

    def compare_runs(
        self, baseline_dir: str, current_dir: str
    ) -> CrossVersionComparisonReport:
        """Executes full comparative regression analysis between two benchmark runs."""
        base_meta, base_summ = self.load_run(baseline_dir)
        curr_meta, curr_summ = self.load_run(current_dir)

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
                overall_verdict="INCOMPARABLE_DATASET_CHANGED",
                metric_evaluations=[],
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
            overall = "REGRESSION_DETECTED"
        elif any_improvement:
            overall = "SECURITY_IMPROVEMENT"
        else:
            overall = "EQUIVALENT_WITHIN_NOISE"

        return CrossVersionComparisonReport(
            experiment_id="CROSS_VERSION_REGRESSION",
            baseline_run_id=base_meta.get("run_id", "UNKNOWN"),
            baseline_commit=base_meta.get("git_commit", "UNKNOWN"),
            current_run_id=curr_meta.get("run_id", "UNKNOWN"),
            current_commit=curr_meta.get("git_commit", "UNKNOWN"),
            compatibility=compat,
            overall_verdict=overall,
            metric_evaluations=evaluations,
        )
