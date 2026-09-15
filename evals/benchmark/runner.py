"""Differential and paired benchmark execution runner for AegisAgent.

Orchestrates reproducible, paired-state evaluations comparing unhardened
baseline against AegisAgent (and single-control ablations) across adversarial
and benign workloads under strict snapshot isolation.
"""

import datetime
import hashlib
import platform
import uuid
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from evals.benchmark.baselines import BaselineAgent
from evals.benchmark.contract import (
    AttemptResult,
    BenchmarkMetadata,
    BenchmarkSummaryMetrics,
    ComparisonStatus,
    ExperimentalCondition,
    PairedComparisonResult,
    ScenarioDefinition,
    ValidationScopeMode,
    calculate_summary_metrics,
)
from evals.benchmark.datasets import (
    BENCHMARK_DATASET_VERSION,
    compute_dataset_hash,
    load_attack_corpus,
    load_benign_corpus,
    load_canonical_smoke_scenario,
)
from evals.benchmark.scenarios import AegisBenchmarkAgent
from evals.benchmark.sinks import InstrumentedSyntheticSinkHarness


class BenchmarkRunConfig(BaseModel):
    """Configuration for a benchmark execution run."""
    model_config = ConfigDict(frozen=True)

    run_id: str = Field(default_factory=lambda: f"run_{uuid.uuid4().hex[:8]}")
    mode: str = "smoke"  # "smoke", "full", or "differential_smoke"
    ablation_conditions: List[ExperimentalCondition] = Field(
        default_factory=list
    )
    validation_mode: ValidationScopeMode = ValidationScopeMode.DRY_RUN
    seed: int = 42
    output_dir: Optional[str] = None


class BenchmarkRunResult(BaseModel):
    """Container holding all outputs, evidence, and metrics of a run."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    metadata: BenchmarkMetadata
    summary_metrics: BenchmarkSummaryMetrics
    scenarios: List[ScenarioDefinition]
    paired_comparisons: List[PairedComparisonResult]
    ablation_attempts: Dict[str, List[AttemptResult]] = Field(
        default_factory=dict
    )
    benign_attempts: List[AttemptResult] = Field(default_factory=list)


class BenchmarkRunner:
    """Differential and paired benchmark experiment runner.

    Guarantees:
    1. Fresh isolated sink state restored before every attempt.
    2. Strict paired comparison between identical scenario snapshots.
    3. Observable evidence used for objective oracle evaluation.
    4. Unhardened baseline demonstrates what happens without Aegis.
    5. Aegis failures reported objectively without assumption of success.
    """

    def __init__(self, config: Optional[BenchmarkRunConfig] = None):
        self.config = config or BenchmarkRunConfig()
        self.harness = InstrumentedSyntheticSinkHarness()
        self.baseline_agent = BaselineAgent(self.harness)
        self.aegis_agent = AegisBenchmarkAgent(self.harness)

    def run_scenario_differential(
        self,
        scenario: ScenarioDefinition,
        ablations: Optional[List[ExperimentalCondition]] = None,
    ) -> Tuple[PairedComparisonResult, List[AttemptResult]]:
        """Executes a single scenario differentially across conditions."""
        # Ensure fresh initial snapshot
        self.harness.take_snapshot()

        # 1. Baseline Attempt
        baseline_att = self.baseline_agent.execute_attempt(scenario)

        # Restore snapshot to ensure identical initial state
        self.harness.restore_snapshot()

        # 2. Aegis Full Attempt
        aegis_att = self.aegis_agent.execute_attempt(
            scenario, condition=ExperimentalCondition.AEGIS_FULL
        )

        # Restore snapshot
        self.harness.restore_snapshot()

        # 3. Optional Ablation Attempts
        ablation_results: List[AttemptResult] = []
        conditions_to_run = (
            ablations if ablations is not None
            else self.config.ablation_conditions
        )
        for cond in conditions_to_run:
            att = self.aegis_agent.execute_attempt(scenario, condition=cond)
            ablation_results.append(att)
            self.harness.restore_snapshot()

        # 4. Build PairedComparisonResult
        paired_result = PairedComparisonResult(
            scenario_id=scenario.scenario_id,
            baseline_attempt=baseline_att,
            aegis_attempt=aegis_att,
            status=ComparisonStatus.COMPLETE_COMPARISON,
        )

        return paired_result, ablation_results

    def run_benign_attempt(
        self, scenario: ScenarioDefinition
    ) -> AttemptResult:
        """Executes a benign scenario under Aegis Full for utility and FPR."""
        self.harness.take_snapshot()
        attempt = self.aegis_agent.execute_attempt(
            scenario, condition=ExperimentalCondition.AEGIS_FULL
        )
        self.harness.restore_snapshot()
        return attempt

    def run_differential_smoke(self) -> BenchmarkRunResult:
        """Runs the canonical IPI_WEB_001 differential smoke experiment."""
        scenario = load_canonical_smoke_scenario()
        ablations = [
            ExperimentalCondition.AEGIS_NO_DLP,
            ExperimentalCondition.AEGIS_NO_NETWORK,
        ]

        paired, abls = self.run_scenario_differential(
            scenario, ablations=ablations
        )

        # Benign smoke sample for utility baseline
        benign_scenarios = load_benign_corpus(subset="smoke")
        benign_attempts = [
            self.run_benign_attempt(b) for b in benign_scenarios[:1]
        ]

        all_scenarios = [scenario] + benign_scenarios[:1]
        summary = calculate_summary_metrics(
            scenarios=all_scenarios,
            paired_comparisons=[paired],
            benign_attempts=benign_attempts,
        )

        metadata = self._build_metadata(all_scenarios)

        result = BenchmarkRunResult(
            metadata=metadata,
            summary_metrics=summary,
            scenarios=all_scenarios,
            paired_comparisons=[paired],
            ablation_attempts={scenario.scenario_id: abls},
            benign_attempts=benign_attempts,
        )

        if self.config.output_dir:
            from evals.benchmark.artifacts import export_run_artifacts
            export_run_artifacts(result, self.config.output_dir)

        return result

    def run(self) -> BenchmarkRunResult:
        """Executes the full configured benchmark run."""
        if self.config.mode == "differential_smoke":
            return self.run_differential_smoke()

        # Load corpora
        subset = "smoke" if self.config.mode == "smoke" else "full"
        attack_scenarios = load_attack_corpus(subset=subset)
        benign_scenarios = load_benign_corpus(subset=subset)

        paired_comparisons: List[PairedComparisonResult] = []
        ablation_attempts: Dict[str, List[AttemptResult]] = {}
        benign_attempts: List[AttemptResult] = []

        # 1. Adversarial Scenarios
        for sc in attack_scenarios:
            paired, abls = self.run_scenario_differential(sc)
            paired_comparisons.append(paired)
            if abls:
                ablation_attempts[sc.scenario_id] = abls

        # 2. Benign Scenarios
        for bng in benign_scenarios:
            att = self.run_benign_attempt(bng)
            benign_attempts.append(att)

        all_scenarios = attack_scenarios + benign_scenarios
        summary = calculate_summary_metrics(
            scenarios=all_scenarios,
            paired_comparisons=paired_comparisons,
            benign_attempts=benign_attempts,
        )

        metadata = self._build_metadata(all_scenarios)

        result = BenchmarkRunResult(
            metadata=metadata,
            summary_metrics=summary,
            scenarios=all_scenarios,
            paired_comparisons=paired_comparisons,
            ablation_attempts=ablation_attempts,
            benign_attempts=benign_attempts,
        )

        if self.config.output_dir:
            from evals.benchmark.artifacts import export_run_artifacts
            export_run_artifacts(result, self.config.output_dir)

        return result

    def _build_metadata(
        self, scenarios: List[ScenarioDefinition]
    ) -> BenchmarkMetadata:
        """Builds reproducible BenchmarkMetadata conforming to contract."""
        cfg_str = (
            f"{self.config.mode}|{self.config.seed}|"
            f"{self.config.validation_mode}"
        )
        cfg_hash = hashlib.sha256(cfg_str.encode("utf-8")).hexdigest()

        return BenchmarkMetadata(
            run_id=self.config.run_id,
            random_seed=self.config.seed,
            python_version=platform.python_version(),
            os_version=f"{platform.system()} {platform.release()}",
            cpu_info=platform.processor() or "unknown-cpu",
            gpu_info=None,
            aegis_version="2.0.0",
            detector_version="deberta-v3-small-ipi-v2",
            policy_version="strict-enterprise-v1.0",
            config_hash=cfg_hash,
            dataset_version=BENCHMARK_DATASET_VERSION,
            dataset_hash=compute_dataset_hash(scenarios),
            scenario_count=len(scenarios),
            validation_mode=self.config.validation_mode.value,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
