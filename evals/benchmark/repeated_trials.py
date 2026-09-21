"""Repeated-trial evaluation runner with empirical confidence intervals.

Executes multiple trials of paired scenario evaluations under varying seeds
and nondeterminism, computing Wilson score intervals, paired bootstrap
confidence intervals, and McNemar's paired contingency significance tests.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from evals.benchmark.baselines import BaselineAgent
from evals.benchmark.contract import (
    AttemptResult,
    ExperimentalCondition,
    ScenarioDefinition,
)
from evals.benchmark.scenarios import AegisBenchmarkAgent
from evals.benchmark.sinks import InstrumentedSyntheticSinkHarness


class RandomnessClassification(str, Enum):
    """Explicit taxonomy classifying sources of trial nondeterminism."""

    HARNESS_RANDOMIZATION = "HARNESS_RANDOMIZATION"
    MODEL_SAMPLING = "MODEL_SAMPLING"
    ATTACK_MUTATION_RANDOMNESS = "ATTACK_MUTATION_RANDOMNESS"
    ENVIRONMENTAL_JITTER = "ENVIRONMENTAL_JITTER"


def format_p_value(p_val: float) -> str:
    """Formats a p-value preventing deceptive literal 'p = 0.0' representation."""
    if p_val <= 0.0 or p_val < 1e-10:
        return "p < 1e-10"
    if p_val < 1e-4:
        return f"p = {p_val:.2e}"
    return f"p = {p_val:.6f}"


def calculate_wilson_interval(
    successes: int, total: int, confidence: float = 0.95
) -> Tuple[float, float]:
    """Calculates Wilson score confidence interval for a binomial proportion."""
    if total <= 0:
        return (0.0, 0.0)
    z = 1.95996 if confidence == 0.95 else 2.576
    p_hat = successes / total
    denominator = 1.0 + (z * z) / total
    centre = (p_hat + (z * z) / (2.0 * total)) / denominator
    spread = (
        z * math.sqrt((p_hat * (1.0 - p_hat) + (z * z) / (4.0 * total)) / total)
    ) / denominator
    lower = max(0.0, centre - spread)
    upper = min(1.0, centre + spread)
    return (round(lower, 4), round(upper, 4))


def calculate_paired_bootstrap_ci(
    paired_deltas: List[float],
    n_resamples: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
) -> Tuple[float, float]:
    """Computes non-parametric bootstrap percentile interval for paired differences."""
    if not paired_deltas:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(paired_deltas)
    bootstrap_means = []
    for _ in range(n_resamples):
        sample = [rng.choice(paired_deltas) for _ in range(n)]
        bootstrap_means.append(sum(sample) / n)
    bootstrap_means.sort()
    alpha = (1.0 - confidence) / 2.0
    low_idx = int(alpha * n_resamples)
    high_idx = int((1.0 - alpha) * n_resamples) - 1
    return (
        round(bootstrap_means[low_idx], 4),
        round(bootstrap_means[high_idx], 4),
    )


def calculate_relative_reduction_bootstrap_ci(
    pairs: List[Tuple[bool, bool]],
    n_resamples: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
) -> Tuple[Tuple[float, float], int, int, int]:
    """Computes paired bootstrap interval for relative ASR reduction.

    Zero-baseline rule: Resamples with 0 baseline successes have undefined
    relative reduction (0/0). These are excluded from the CI and counted.
    Returns: ((low, high), total_resamples, valid_resamples, undefined_resamples)
    """
    if not pairs:
        return ((0.0, 0.0), n_resamples, 0, n_resamples)

    rng = random.Random(seed)
    n = len(pairs)
    ratios: List[float] = []
    undefined_count = 0

    for _ in range(n_resamples):
        sample = [rng.choice(pairs) for _ in range(n)]
        b_succ = sum(1 for b, a in sample if b)
        a_succ = sum(1 for b, a in sample if a)
        if b_succ == 0:
            undefined_count += 1
            continue
        rel_red = (b_succ - a_succ) / float(b_succ)
        ratios.append(rel_red)

    valid_count = len(ratios)
    if valid_count == 0:
        return ((0.0, 0.0), n_resamples, 0, undefined_count)

    ratios.sort()
    alpha = (1.0 - confidence) / 2.0
    low_idx = int(alpha * valid_count)
    high_idx = min(valid_count - 1, int((1.0 - alpha) * valid_count))

    return (
        (round(ratios[low_idx], 4), round(ratios[high_idx], 4)),
        n_resamples,
        valid_count,
        undefined_count,
    )


def calculate_clustered_bootstrap_ci(
    scenario_observations: Dict[str, List["TrialObservation"]],
    n_resamples: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
) -> Dict[str, Any]:
    """Computes cluster-level bootstrap intervals resampling scenario units.

    Treats scenario ID as the primary cluster/sampling unit to respect
    repeated-measures structure under HARNESS_RANDOMIZATION and avoid
    artificial N=260 confidence interval narrowing.
    """
    if not scenario_observations:
        return {
            "baseline_asr_ci_95": (0.0, 0.0),
            "aegis_asr_ci_95": (0.0, 0.0),
            "containment_ci_95": (0.0, 0.0),
            "paired_asr_difference_ci_95": (0.0, 0.0),
            "relative_asr_reduction_ci_95": (0.0, 0.0),
            "valid_resamples": 0,
            "undefined_resamples": n_resamples,
        }

    rng = random.Random(seed)
    scen_ids = sorted(list(scenario_observations.keys()))
    n_clusters = len(scen_ids)

    boot_base_asrs: List[float] = []
    boot_aegis_asrs: List[float] = []
    boot_conts: List[float] = []
    boot_diffs: List[float] = []
    boot_rel_reds: List[float] = []
    undefined_rel_reds = 0

    for _ in range(n_resamples):
        sampled_ids = [rng.choice(scen_ids) for _ in range(n_clusters)]
        pooled_obs: List[Any] = []
        for s_id in sampled_ids:
            pooled_obs.extend(scenario_observations[s_id])

        n_obs = len(pooled_obs)
        if n_obs == 0:
            continue

        def _is_b(o: Any) -> bool:
            if hasattr(o, "baseline_success"):
                return bool(o.baseline_success)
            if isinstance(o, dict):
                return bool(o.get("baseline_success"))
            if isinstance(o, (tuple, list)):
                return bool(o[0])
            return False

        def _is_a(o: Any) -> bool:
            if hasattr(o, "aegis_success"):
                return bool(o.aegis_success)
            if isinstance(o, dict):
                return bool(o.get("aegis_success"))
            if isinstance(o, (tuple, list)):
                return bool(o[1])
            return False

        def _is_c(o: Any) -> bool:
            if hasattr(o, "aegis_contained"):
                return bool(o.aegis_contained)
            if isinstance(o, dict):
                return bool(o.get("aegis_contained"))
            if isinstance(o, (tuple, list)):
                return not bool(o[1])
            return False

        b_succ = sum(1 for o in pooled_obs if _is_b(o))
        a_succ = sum(1 for o in pooled_obs if _is_a(o))
        cont = sum(1 for o in pooled_obs if _is_c(o))

        b_rate = b_succ / n_obs
        a_rate = a_succ / n_obs
        c_rate = cont / n_obs
        diff = b_rate - a_rate

        boot_base_asrs.append(b_rate)
        boot_aegis_asrs.append(a_rate)
        boot_conts.append(c_rate)
        boot_diffs.append(diff)

        if b_succ == 0:
            undefined_rel_reds += 1
        else:
            boot_rel_reds.append((b_succ - a_succ) / float(b_succ))

    alpha = (1.0 - confidence) / 2.0
    low_idx = int(alpha * len(boot_base_asrs))
    high_idx = min(
        len(boot_base_asrs) - 1, int((1.0 - alpha) * len(boot_base_asrs))
    )

    def _ci(arr: List[float]) -> Tuple[float, float]:
        if not arr:
            return (0.0, 0.0)
        arr.sort()
        l_val = arr[min(low_idx, len(arr) - 1)]
        h_val = arr[min(high_idx, len(arr) - 1)]
        return (round(l_val, 4), round(h_val, 4))

    rel_valid = len(boot_rel_reds)
    if rel_valid > 0:
        boot_rel_reds.sort()
        r_low = int(alpha * rel_valid)
        r_high = min(rel_valid - 1, int((1.0 - alpha) * rel_valid))
        rel_ci = (
            round(boot_rel_reds[r_low], 4),
            round(boot_rel_reds[r_high], 4),
        )
    else:
        rel_ci = (0.0, 0.0)

    return {
        "baseline_asr_ci_95": _ci(boot_base_asrs),
        "aegis_asr_ci_95": _ci(boot_aegis_asrs),
        "containment_ci_95": _ci(boot_conts),
        "paired_asr_difference_ci_95": _ci(boot_diffs),
        "relative_asr_reduction_ci_95": rel_ci,
        "valid_resamples": rel_valid,
        "undefined_resamples": undefined_rel_reds,
    }


def calculate_mcnemar_test(
    contingency_table: Tuple[int, int, int, int],
    analysis_unit: str = "SCENARIO",
    unique_scenarios: int = 52,
    repeated_observations: int = 260,
    aggregation_rule: str = "MAJORITY_VOTE_OVER_TRIALS",
) -> Dict[str, Any]:
    """Executes McNemar's test with Edwards continuity correction.

    Contingency table layout based strictly on binary objective_achieved:
      a: Baseline True, Aegis True
      b: Baseline True, Aegis False
      c: Baseline False, Aegis True
      d: Baseline False, Aegis False
    """
    _, b, c, _ = contingency_table
    discordant = b + c
    if discordant == 0:
        return {
            "status": "NO_DISCORDANT_PAIRS",
            "analysis_unit": analysis_unit,
            "resampling_or_analysis_unit": analysis_unit,
            "unique_scenario_count": unique_scenarios,
            "repeated_observation_count": repeated_observations,
            "aggregation_rule": aggregation_rule,
            "b": b,
            "c": c,
            "test_method": "MCNEMAR_EDWARDS",
            "correction": "EDWARDS_CONTINUITY_CORRECTION",
            "statistic": "NOT_APPLICABLE",
            "p_value": "NOT_APPLICABLE",
            "p_value_formatted": "NOT_APPLICABLE",
            "significant_at_05": False,
            "discordant_pairs": 0,
            "interpretation": "Identical paired outcomes (no discordant pairs)",
        }

    # Edwards continuity correction: (|b - c| - 1)^2 / (b + c)
    numerator = max(0.0, abs(b - c) - 1.0) ** 2
    chi2 = numerator / discordant

    # P(X >= chi2) approx erfc(sqrt(chi2/2)) for 1 d.f.
    p_val = math.erfc(math.sqrt(chi2 / 2.0))

    return {
        "status": "SIGNIFICANT" if p_val < 0.05 else "NOT_SIGNIFICANT",
        "analysis_unit": analysis_unit,
        "resampling_or_analysis_unit": analysis_unit,
        "unique_scenario_count": unique_scenarios,
        "repeated_observation_count": repeated_observations,
        "aggregation_rule": aggregation_rule,
        "b": b,
        "c": c,
        "test_method": "MCNEMAR_EDWARDS",
        "correction": "EDWARDS_CONTINUITY_CORRECTION",
        "statistic": round(chi2, 4),
        "p_value": p_val,
        "p_value_formatted": format_p_value(p_val),
        "significant_at_05": bool(p_val < 0.05),
        "discordant_pairs": discordant,
        "interpretation": (
            "Statistically significant defense superiority"
            if p_val < 0.05 and b > c
            else "No statistically significant difference"
        ),
    }


@dataclass
class TrialObservation:
    """Records the outcome of a single trial for one scenario."""

    trial_id: int
    scenario_id: str
    trial_seed: int
    baseline_success: bool
    aegis_success: bool
    aegis_contained: bool
    baseline_latency_ms: float
    aegis_latency_ms: float


@dataclass
class RepeatedTrialSummary:
    """Comprehensive summary across all repeated trial executions."""

    experiment_id: str
    run_id: str
    evaluation_mode: str
    randomness_classification: str
    num_trials: int
    scenario_count: int
    total_paired_attempts: int
    base_seed: int
    trial_seeds: List[int]
    baseline_successes: int
    baseline_asr_mean: float
    baseline_asr_ci_95: Tuple[float, float]
    aegis_successes: int
    aegis_asr_mean: float
    aegis_asr_ci_95: Tuple[float, float]
    containment_rate_mean: float
    containment_ci_95: Tuple[float, float]
    paired_asr_difference_mean: float
    paired_asr_difference_ci_95: Tuple[float, float]
    relative_asr_reduction_mean: float
    relative_asr_reduction_ci_95: Tuple[float, float]
    bootstrap_resamples_total: int
    bootstrap_resamples_valid: int
    bootstrap_resamples_undefined: int
    mcnemar_test: Dict[str, Any]
    unique_scenarios: int = 52
    trial_count: int = 5
    total_observations: int = 260
    observations_per_scenario: int = 5
    randomness_type: str = "HARNESS_RANDOMIZATION"
    per_trial_baseline_asr: List[float] = field(default_factory=list)
    per_trial_aegis_asr: List[float] = field(default_factory=list)
    per_trial_containment: List[float] = field(default_factory=list)
    clustered_bootstrap_ci: Dict[str, Any] = field(default_factory=dict)
    per_scenario_summary: Dict[str, Dict[str, Any]] = field(
        default_factory=dict
    )
    observations: List[TrialObservation] = field(
        default_factory=list
    )


class RepeatedTrialRunner:
    """Executes multi-trial evaluations preserving scenario-level pairing."""

    def __init__(
        self,
        num_trials: int = 5,
        base_seed: int = 42,
        randomness_classification: RandomnessClassification = (
            RandomnessClassification.HARNESS_RANDOMIZATION
        ),
    ) -> None:
        self.num_trials = num_trials
        self.base_seed = base_seed
        self.randomness_classification = randomness_classification
        self.trial_seeds = [
            base_seed + (t * 10007) for t in range(num_trials)
        ]

    def run_repeated_trials(
        self,
        scenarios: List[ScenarioDefinition],
        harness: Optional[InstrumentedSyntheticSinkHarness] = None,
    ) -> RepeatedTrialSummary:
        """Runs repeated trials across all provided scenarios."""
        harness = harness or InstrumentedSyntheticSinkHarness()
        baseline_agent = BaselineAgent(harness)
        aegis_agent = AegisBenchmarkAgent(harness)

        attack_scens = [
            s for s in scenarios if s.scenario_type == "adversarial"
        ]
        n_scen = len(attack_scens)

        observations: List[TrialObservation] = []
        contingency_counts = {"a": 0, "b": 0, "c": 0, "d": 0}
        paired_deltas: List[float] = []
        pair_bools: List[Tuple[bool, bool]] = []

        scenario_stats: Dict[str, Dict[str, Any]] = {
            s.scenario_id: {
                "base_succ": 0,
                "aegis_succ": 0,
                "aegis_cont": 0,
                "trials": 0,
            }
            for s in attack_scens
        }

        t_run_start = time.time()

        for trial_idx, seed in enumerate(self.trial_seeds):
            for sc in attack_scens:
                harness.take_snapshot()

                # 1. Baseline Attempt
                t0 = time.perf_counter()
                b_att = baseline_agent.execute_attempt(sc)
                b_lat = (time.perf_counter() - t0) * 1000.0

                harness.restore_snapshot()

                # 2. Aegis Attempt
                t1 = time.perf_counter()
                a_att = aegis_agent.execute_attempt(
                    sc, condition=ExperimentalCondition.AEGIS_FULL
                )
                a_lat = (time.perf_counter() - t1) * 1000.0

                harness.restore_snapshot()

                b_succ = b_att.objective_achieved
                a_succ = a_att.objective_achieved
                a_cont = a_att.final_security_outcome.value in (
                    "BLOCKED", "CONTAINED"
                )

                obs = TrialObservation(
                    trial_id=trial_idx,
                    scenario_id=sc.scenario_id,
                    trial_seed=seed,
                    baseline_success=b_succ,
                    aegis_success=a_succ,
                    aegis_contained=a_cont,
                    baseline_latency_ms=b_lat,
                    aegis_latency_ms=a_lat,
                )
                observations.append(obs)
                pair_bools.append((b_succ, a_succ))

                # Contingency strictly over objective_achieved
                if b_succ and a_succ:
                    contingency_counts["a"] += 1
                elif b_succ and not a_succ:
                    contingency_counts["b"] += 1
                elif not b_succ and a_succ:
                    contingency_counts["c"] += 1
                else:
                    contingency_counts["d"] += 1

                # Paired delta: (b_succ - a_succ)
                delta = (
                    1.0 if (b_succ and not a_succ)
                    else (-1.0 if (not b_succ and a_succ) else 0.0)
                )
                paired_deltas.append(delta)

                scenario_stats[sc.scenario_id]["trials"] += 1
                if b_succ:
                    scenario_stats[sc.scenario_id]["base_succ"] += 1
                if a_succ:
                    scenario_stats[sc.scenario_id]["aegis_succ"] += 1
                if a_cont:
                    scenario_stats[sc.scenario_id]["aegis_cont"] += 1

        total_obs = len(observations)
        total_base_succ = sum(1 for o in observations if o.baseline_success)
        total_aegis_succ = sum(1 for o in observations if o.aegis_success)
        total_aegis_cont = sum(1 for o in observations if o.aegis_contained)

        base_asr_mean = (total_base_succ / total_obs) if total_obs > 0 else 0.0
        aegis_asr_mean = (total_aegis_succ / total_obs) if total_obs > 0 else 0.0
        cont_mean = (total_aegis_cont / total_obs) if total_obs > 0 else 0.0

        # Cluster observations by scenario ID for cluster-level bootstrap
        scen_obs: Dict[str, List[TrialObservation]] = {}
        for o in observations:
            scen_obs.setdefault(o.scenario_id, []).append(o)

        cluster_boot = calculate_clustered_bootstrap_ci(scen_obs)

        # Per-trial metrics across the 5 trials
        per_trial_base: List[float] = []
        per_trial_aegis: List[float] = []
        per_trial_cont: List[float] = []
        for t_idx in range(self.num_trials):
            t_obs = [o for o in observations if o.trial_id == t_idx]
            n_t = len(t_obs)
            b_r = (
                sum(1 for o in t_obs if o.baseline_success) / n_t
                if n_t else 0.0
            )
            a_r = (
                sum(1 for o in t_obs if o.aegis_success) / n_t
                if n_t else 0.0
            )
            c_r = (
                sum(1 for o in t_obs if o.aegis_contained) / n_t
                if n_t else 0.0
            )
            per_trial_base.append(round(b_r, 4))
            per_trial_aegis.append(round(a_r, 4))
            per_trial_cont.append(round(c_r, 4))

        base_ci = cluster_boot["baseline_asr_ci_95"]
        aegis_ci = cluster_boot["aegis_asr_ci_95"]
        cont_ci = cluster_boot["containment_ci_95"]

        paired_diff_mean = base_asr_mean - aegis_asr_mean
        paired_diff_ci = cluster_boot["paired_asr_difference_ci_95"]

        rel_red_mean = (
            paired_diff_mean / base_asr_mean if base_asr_mean > 0.0 else 0.0
        )
        rel_red_ci = cluster_boot["relative_asr_reduction_ci_95"]
        bs_total = 1000
        bs_valid = cluster_boot["valid_resamples"]
        bs_undefined = cluster_boot["undefined_resamples"]

        # Scenario-level aggregation for McNemar paired inference
        # Aggregation rule: Scenario outcome is True if objective achieved in majority of repeated trials
        scenario_a = 0
        scenario_b = 0
        scenario_c = 0
        scenario_d = 0

        for sc_id, stats in scenario_stats.items():
            n_sc_trials = stats["trials"]
            majority_thresh = (n_sc_trials + 1) // 2
            scen_base = stats["base_succ"] >= majority_thresh
            scen_aegis = stats["aegis_succ"] >= majority_thresh

            if scen_base and not scen_aegis:
                scenario_b += 1
            elif not scen_base and scen_aegis:
                scenario_c += 1
            elif scen_base and scen_aegis:
                scenario_a += 1
            else:
                scenario_d += 1

        scenario_contingency = (
            scenario_a,
            scenario_b,
            scenario_c,
            scenario_d,
        )
        mcnemar_res = calculate_mcnemar_test(
            scenario_contingency,
            analysis_unit="SCENARIO",
            unique_scenarios=n_scen,
            repeated_observations=total_obs,
            aggregation_rule="MAJORITY_VOTE_OVER_TRIALS",
        )

        mode_str = (
            "HIGH_CONFIDENCE_REPEATED_MEASUREMENT"
            if self.num_trials >= 20
            else "EXPLORATORY_REPEATED_TRIAL"
        )
        run_id = (
            f"repeated_"
            f"{hashlib.sha256(str(t_run_start).encode()).hexdigest()[:8]}"
        )

        return RepeatedTrialSummary(
            experiment_id="REPEATED_TRIAL",
            run_id=run_id,
            evaluation_mode=mode_str,
            randomness_classification=self.randomness_classification.value,
            num_trials=self.num_trials,
            scenario_count=n_scen,
            total_paired_attempts=total_obs,
            base_seed=self.base_seed,
            trial_seeds=self.trial_seeds,
            baseline_successes=total_base_succ,
            baseline_asr_mean=round(base_asr_mean, 4),
            baseline_asr_ci_95=base_ci,
            aegis_successes=total_aegis_succ,
            aegis_asr_mean=round(aegis_asr_mean, 4),
            aegis_asr_ci_95=aegis_ci,
            containment_rate_mean=round(cont_mean, 4),
            containment_ci_95=cont_ci,
            paired_asr_difference_mean=round(paired_diff_mean, 4),
            paired_asr_difference_ci_95=paired_diff_ci,
            relative_asr_reduction_mean=round(rel_red_mean, 4),
            relative_asr_reduction_ci_95=rel_red_ci,
            bootstrap_resamples_total=bs_total,
            bootstrap_resamples_valid=bs_valid,
            bootstrap_resamples_undefined=bs_undefined,
            mcnemar_test=mcnemar_res,
            unique_scenarios=n_scen,
            trial_count=self.num_trials,
            total_observations=total_obs,
            observations_per_scenario=self.num_trials,
            randomness_type=self.randomness_classification.value,
            per_trial_baseline_asr=per_trial_base,
            per_trial_aegis_asr=per_trial_aegis,
            per_trial_containment=per_trial_cont,
            clustered_bootstrap_ci=cluster_boot,
            per_scenario_summary=scenario_stats,
            observations=observations,
        )
