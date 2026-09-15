"""AegisAgent Benchmark Contract and Evaluation Framework.

Version: 1.0
Contract specification: docs/benchmark_contract.md
"""

from .contract import (
    BENCHMARK_CONTRACT_VERSION,
    AttackObjective,
    AttackObjectiveType,
    AttemptResult,
    AttemptValidity,
    BenignInterventionCategory,
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

try:
    from evals.benchmark_legacy import AegisBenchmarkRunner
except ImportError:
    AegisBenchmarkRunner = None

__all__ = [
    "BENCHMARK_CONTRACT_VERSION",
    "ScenarioValidity",
    "AttemptValidity",
    "SecurityOutcome",
    "ExperimentalCondition",
    "AttackObjectiveType",
    "ControlState",
    "BlastRadiusLevel",
    "BenignInterventionCategory",
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
    "AegisBenchmarkRunner",
]
