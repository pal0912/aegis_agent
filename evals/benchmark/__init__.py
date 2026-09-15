"""AegisAgent Benchmark Contract and Evaluation Framework.

Version: 1.0
Contract specification: docs/benchmark_contract.md
"""

from .baselines import BaselineAgent
from .contract import (
    BENCHMARK_CONTRACT_VERSION,
    AttackObjective,
    AttackObjectiveType,
    AttemptResult,
    AttemptValidity,
    BenignInterventionCategory,
    BenignOutcome,
    BenchmarkMetadata,
    BenchmarkSummaryMetrics,
    BlastRadiusLevel,
    ComparisonStatus,
    ControlActivationRecord,
    ControlState,
    ExpectedOutcome,
    ExperimentalCondition,
    IntermediateImpacts,
    ObjectiveStateTransition,
    ObservableEvidence,
    PairedComparisonResult,
    ScenarioDefinition,
    ScenarioValidity,
    SecurityOutcome,
    ValidationScopeMode,
    calculate_summary_metrics,
)
from .datasets import (
    BENCHMARK_DATASET_VERSION,
    compute_dataset_hash,
    load_attack_corpus,
    load_benign_corpus,
    load_canonical_smoke_scenario,
)
from .runner import (
    BenchmarkRunConfig,
    BenchmarkRunner,
    BenchmarkRunResult,
)
from .scenarios import AegisBenchmarkAgent
from .sinks import (
    InstrumentedSyntheticSinkHarness,
    SyntheticDatabaseSink,
    SyntheticFilesystemSink,
    SyntheticNetworkSink,
    SyntheticSecretSink,
    SyntheticToolExecutionSink,
)

try:
    from evals.benchmark_legacy import (
        AegisBenchmarkRunner,
        main,
        run_all_evals,
    )
except ImportError:
    AegisBenchmarkRunner = None
    run_all_evals = None
    main = None

__all__ = [
    "BENCHMARK_CONTRACT_VERSION",
    "BENCHMARK_DATASET_VERSION",
    "ScenarioValidity",
    "AttemptValidity",
    "SecurityOutcome",
    "BenignOutcome",
    "BenignInterventionCategory",
    "ExperimentalCondition",
    "AttackObjectiveType",
    "ControlState",
    "BlastRadiusLevel",
    "ComparisonStatus",
    "ValidationScopeMode",
    "IntermediateImpacts",
    "ObservableEvidence",
    "ObjectiveStateTransition",
    "AttackObjective",
    "ExpectedOutcome",
    "ScenarioDefinition",
    "ControlActivationRecord",
    "AttemptResult",
    "PairedComparisonResult",
    "BenchmarkMetadata",
    "BenchmarkSummaryMetrics",
    "calculate_summary_metrics",
    "InstrumentedSyntheticSinkHarness",
    "SyntheticDatabaseSink",
    "SyntheticFilesystemSink",
    "SyntheticNetworkSink",
    "SyntheticSecretSink",
    "SyntheticToolExecutionSink",
    "BaselineAgent",
    "AegisBenchmarkAgent",
    "BenchmarkRunner",
    "BenchmarkRunConfig",
    "BenchmarkRunResult",
    "load_attack_corpus",
    "load_benign_corpus",
    "load_canonical_smoke_scenario",
    "compute_dataset_hash",
    "AegisBenchmarkRunner",
    "run_all_evals",
    "main",
]
