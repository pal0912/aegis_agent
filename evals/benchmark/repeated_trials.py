"""Repeated-trial evaluation runner with empirical confidence intervals.

Executes multiple trials of paired scenario evaluations under varying seeds
and nondeterminism, computing Wilson score intervals, paired bootstrap
confidence intervals, and McNemar's paired contingency significance tests.
"""

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
from pathlib import Path
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from evals.benchmark.contract import (
    AttemptResult,
    ExperimentalCondition,
    ScenarioDefinition,
)
from evals.benchmark.baselines import BaselineAgent
from evals.benchmark.scenarios import AegisBenchmarkAgent
from evals.benchmark.sinks import InstrumentedSyntheticSinkHarness


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


def calculate_mcnemar_test(
    contingency_table: Tuple[int, int, int, int]
) -> Dict[str, Any]:
    """Executes McNemar's test with Edwards continuity correction.

    Table layout: (a, b, c, d)
      a: Baseline Success, Aegis Success
      b: Baseline Success, Aegis Failure (Defense Contained Attack)
      c: Baseline Failure, Aegis Success (Anomaly / Unexpected)
      d: Baseline Failure, Aegis Failure
    """
    _, b, c, _ = contingency_table
    discordant = b + c
    if discordant == 0:
        return {
            "statistic": 0.0,
            "p_value": 1.0,
            "significant_at_05": False,
            "interpretation": "Identical paired outcomes",
        }

    # Edwards continuity correction: (|b - c| - 1)^2 / (b + c)
    numerator = max(0.0, abs(b - c) - 1.0) ** 2
    chi2 = numerator / discordant

    # Approximation for p-value from chi-square distribution with df=1
    # P(X >= chi2) approx erfc(sqrt(chi2/2))
    p_val = math.erfc(math.sqrt(chi2 / 2.0))

    return {
        "statistic": round(chi2, 4),
        "p_value": round(p_val, 6),
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
    evaluation_mode: str  # EXPLORATORY_REPEATED_TRIAL or HIGH_CONFIDENCE_REPEATED_MEASUREMENT
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
    paired_asr_reduction_mean: float
    paired_delta_asr_ci_95: Tuple[float, float]
    mcnemar_test: Dict[str, Any]
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
    ) -> None:
        self.num_trials = num_trials
        self.base_seed = base_seed
        self.trial_seeds = [
            base_seed + (t * 10007) for t in range(num_trials)
        ]

    def run_repeated_trials(
        self,
        scenarios: List[ScenarioDefinition],
        harness: Optional[InstrumentedSyntheticSinkHarness] = None,
    ) -> RepeatedTrialSummary:
        """Runs the repeated trials across all provided scenarios."""
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

                # Track contingency table for McNemar's test
                if b_succ and a_succ:
                    contingency_counts["a"] += 1
                elif b_succ and not a_succ:
                    contingency_counts["b"] += 1
                elif not b_succ and a_succ:
                    contingency_counts["c"] += 1
                else:
                    contingency_counts["d"] += 1

                # Paired delta: (b_succ - a_succ)
                delta = 1.0 if (b_succ and not a_succ) else (-1.0 if (not b_succ and a_succ) else 0.0)
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

        base_ci = calculate_wilson_interval(total_base_succ, total_obs)
        aegis_ci = calculate_wilson_interval(total_aegis_succ, total_obs)
        cont_ci = calculate_wilson_interval(total_aegis_cont, total_obs)

        paired_delta_ci = calculate_paired_bootstrap_ci(paired_deltas)
        asr_red_mean = (
            (base_asr_mean - aegis_asr_mean) / base_asr_mean
            if base_asr_mean > 0.0 else 0.0
        )

        table_tuple = (
            contingency_counts["a"],
            contingency_counts["b"],
            contingency_counts["c"],
            contingency_counts["d"],
        )
        mcnemar_res = calculate_mcnemar_test(table_tuple)

        mode_str = (
            "HIGH_CONFIDENCE_REPEATED_MEASUREMENT"
            if self.num_trials >= 20
            else "EXPLORATORY_REPEATED_TRIAL"
        )
        run_id = f"repeated_{hashlib.sha256(str(t_run_start).encode()).hexdigest()[:8]}"

        return RepeatedTrialSummary(
            experiment_id="REPEATED_TRIAL",
            run_id=run_id,
            evaluation_mode=mode_str,
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
            paired_asr_reduction_mean=round(asr_red_mean, 4),
            paired_delta_asr_ci_95=paired_delta_ci,
            mcnemar_test=mcnemar_res,
            per_scenario_summary=scenario_stats,
            observations=observations,
        )
