"""End-to-end execution script for the Advanced Evaluation Layer suite.

Executes all 7 advanced evaluation studies with strict experiment isolation:
1. Adaptive Red-Team Evaluation (results/advanced_eval/adaptive/)
2. Repeated Trials Study (results/advanced_eval/repeated/)
3. Container Runtime Boundary Verification (results/advanced_eval/container/)
4. Cross-Version Regression Comparator (results/advanced_eval/regression/)
5. Residual Risk Experiments (results/advanced_eval/residual_risks/)
6. Component Latency Profiling (results/advanced_eval/performance/)
7. Demonstration Trace Generation (results/advanced_eval/demo/)
"""

from dataclasses import asdict
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List

from evals.benchmark.adaptive_redteam import (
    AdaptiveRedTeamEngine,
)
from evals.benchmark.container_runtime import (
    ContainerSecurityProfile,
    ContainerizedRuntimeHarness,
)
from evals.benchmark.datasets import load_attack_corpus
from evals.benchmark.demo_trace import (
    DemonstrationTraceEngine,
)
from evals.benchmark.profiler import (
    ComponentLatencyProfiler,
)
from evals.benchmark.regression_comparator import (
    CrossVersionComparator,
)
from evals.benchmark.repeated_trials import (
    RepeatedTrialRunner,
)
from evals.benchmark.residual_risks import (
    ResidualRiskEvaluator,
)
from evals.benchmark.scenarios import AegisBenchmarkAgent
from evals.benchmark.sinks import InstrumentedSyntheticSinkHarness

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("advanced_eval_suite")


def run_all_advanced_evaluations(
    output_base_dir: str = "results/advanced_eval",
) -> Dict[str, Any]:
    """Executes the complete advanced evaluation methodology suite."""
    base_path = Path(output_base_dir)
    base_path.mkdir(parents=True, exist_ok=True)

    suite_summary: Dict[str, Any] = {
        "suite_name": "AegisAgent Advanced Evaluation Layer",
        "timestamp": time.time(),
        "experiments_completed": [],
    }

    # ========================================================================
    # 1. Adaptive Red-Team Evaluation
    # ========================================================================
    logger.info("=== Starting 1. Adaptive Red-Team Evaluation ===")
    adaptive_dir = base_path / "adaptive"
    adaptive_dir.mkdir(parents=True, exist_ok=True)

    all_attacks = load_attack_corpus(subset="full")
    # Select representative adversarial scenarios across attack families
    sample_ids = [
        "ATK-001",  # Prompt Injection Direct
        "ATK-010",  # Jailbreak Roleplay
        "ATK-024",  # Misleading Tool Capability Smuggling
        "ATK-036",  # MCP Schema Poisoning
        "ATK-044",  # Multimodal ASCII Smuggling
    ]
    adaptive_scenarios = [s for s in all_attacks if s.scenario_id in sample_ids]
    if not adaptive_scenarios:
        adaptive_scenarios = all_attacks[:5]

    engine = AdaptiveRedTeamEngine(
        max_turns=5,
        mutation_budget=10,
        timeout_seconds=30.0,
        random_seed=42,
    )
    harness = InstrumentedSyntheticSinkHarness()
    agent = AegisBenchmarkAgent(harness)

    adaptive_summary = engine.evaluate_adaptive_corpus(
        adaptive_scenarios, harness, agent
    )
    adaptive_dict = asdict(adaptive_summary)

    with open(adaptive_dir / "summary.json", "w", encoding="utf-8") as f:
        # Exclude detailed trajectories from summary for readability
        summ_copy = dict(adaptive_dict)
        summ_copy.pop("trajectories", None)
        json.dump(summ_copy, f, indent=2)

    with open(adaptive_dir / "trajectories.jsonl", "w", encoding="utf-8") as f:
        for traj in adaptive_dict.get("trajectories", []):
            f.write(json.dumps(traj) + "\n")

    logger.info(
        f"Adaptive Red-Team completed: ASR={adaptive_summary.adaptive_asr:.2%}, "
        f"Paths={adaptive_summary.unique_attack_paths_count}, "
        f"Entropy={adaptive_summary.normalized_path_entropy:.3f}"
    )
    suite_summary["experiments_completed"].append("ADAPTIVE_REDTEAM")

    # ========================================================================
    # 2. Repeated Trials Study
    # ========================================================================
    logger.info("=== Starting 2. Repeated Trials Study (5 Trials) ===")
    repeated_dir = base_path / "repeated"
    repeated_dir.mkdir(parents=True, exist_ok=True)

    trial_runner = RepeatedTrialRunner(num_trials=5, base_seed=1000)
    rep_summary = trial_runner.run_repeated_trials(all_attacks)
    rep_dict = asdict(rep_summary)

    with open(repeated_dir / "summary.json", "w", encoding="utf-8") as f:
        summ_copy = dict(rep_dict)
        summ_copy.pop("observations", None)
        json.dump(summ_copy, f, indent=2)

    with open(repeated_dir / "trials.jsonl", "w", encoding="utf-8") as f:
        for obs in rep_dict.get("observations", []):
            f.write(json.dumps(obs) + "\n")

    logger.info(
        f"Repeated Trials completed: Baseline ASR={rep_summary.baseline_asr_mean:.2%} "
        f"CI={rep_summary.baseline_asr_ci_95}, Aegis ASR={rep_summary.aegis_asr_mean:.2%} "
        f"CI={rep_summary.aegis_asr_ci_95}, McNemar p={rep_summary.mcnemar_test.get('p_value')}"
    )
    suite_summary["experiments_completed"].append("REPEATED_TRIAL")

    # ========================================================================
    # 3. Container Runtime Boundary Verification
    # ========================================================================
    logger.info("=== Starting 3. Container Runtime Boundary Verification ===")
    container_dir = base_path / "container"
    container_dir.mkdir(parents=True, exist_ok=True)

    container_harness = ContainerizedRuntimeHarness(
        profile=ContainerSecurityProfile(user="1000:1000", read_only_rootfs=True)
    )
    container_meta = container_harness.get_runtime_metadata()

    # Execute representative test commands
    commands_to_test = [
        ("echo 'healthy'", "read_only_probe"),
        ("touch /var/test.txt", "unauthorized_write_attempt"),
        ("curl http://evil.corp", "unauthorized_egress_attempt"),
    ]
    container_results = []
    for cmd, name in commands_to_test:
        res = container_harness.execute_isolated(
            command=cmd,
            attempt_id=f"att_cont_{name}",
            scenario_id=f"SCEN_CONT_{name.upper()}",
            timeout_seconds=5.0,
        )
        container_results.append(asdict(res))

    with open(container_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(container_meta, f, indent=2)

    with open(container_dir / "results.json", "w", encoding="utf-8") as f:
        json.dump(container_results, f, indent=2)

    logger.info(
        f"Container runtime verified. Mode: {container_meta.get('runtime_type')}, "
        f"Isolation Claim: {container_meta.get('isolation_claim')}"
    )
    suite_summary["experiments_completed"].append("CONTAINER_RUNTIME")

    # ========================================================================
    # 4. Cross-Version Regression Comparator
    # ========================================================================
    logger.info("=== Starting 4. Cross-Version Regression Comparator ===")
    regression_dir = base_path / "regression"
    regression_dir.mkdir(parents=True, exist_ok=True)

    comparator = CrossVersionComparator()
    pre_dir = "results/full_run_pre_remediation"
    final_dir = "results/final_full_run"

    if Path(pre_dir).exists() and Path(final_dir).exists():
        report = comparator.compare_runs(pre_dir, final_dir)
        with open(
            regression_dir / "regression_report.json", "w", encoding="utf-8"
        ) as f:
            json.dump(asdict(report), f, indent=2)
        logger.info(
            f"Regression comparison complete: verdict={report.overall_verdict}, "
            f"compatibility={report.compatibility.status_label}"
        )
        suite_summary["experiments_completed"].append(
            "CROSS_VERSION_REGRESSION"
        )
    else:
        logger.warning(
            "Pre-remediation or final run dir missing; skipped full run compare."
        )

    # ========================================================================
    # 5. Residual Risk Experiments
    # ========================================================================
    logger.info("=== Starting 5. Residual Risk Experiments ===")
    residual_dir = base_path / "residual_risks"
    residual_dir.mkdir(parents=True, exist_ok=True)

    risk_evaluator = ResidualRiskEvaluator(seed=42)
    risk_report = risk_evaluator.execute_all_residual_risk_studies(harness, agent)

    with open(
        residual_dir / "residual_risk_report.json", "w", encoding="utf-8"
    ) as f:
        json.dump(asdict(risk_report), f, indent=2)

    logger.info("Residual risk studies complete. Saved residual_risk_report.json")
    suite_summary["experiments_completed"].append("RESIDUAL_RISK")

    # ========================================================================
    # 6. Component Latency Profiling
    # ========================================================================
    logger.info("=== Starting 6. Component Latency Profiling ===")
    perf_dir = base_path / "performance"
    perf_dir.mkdir(parents=True, exist_ok=True)

    profiler = ComponentLatencyProfiler(
        warmup_runs=5,
        measurement_runs=25,
        neural_warmup_runs=2,
        neural_measurement_runs=10,
    )
    profiles = profiler.run_all_profiles()
    profiler.export_csv(profiles, str(perf_dir / "component_latency.csv"))
    profiler.export_neural_metadata(
        profiles, str(perf_dir / "neural_metadata.json")
    )

    with open(perf_dir / "profiles.json", "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2)

    logger.info("Component latency profiling complete. Exported CSV & JSON.")
    suite_summary["experiments_completed"].append("PERFORMANCE_STUDY")

    # ========================================================================
    # 7. Demonstration Trace Generation
    # ========================================================================
    logger.info("=== Starting 7. Demonstration Trace Generation ===")
    demo_dir = base_path / "demo"
    demo_dir.mkdir(parents=True, exist_ok=True)

    demo_engine = DemonstrationTraceEngine()
    demo_traces = demo_engine.generate_demonstration_suite(harness, agent)
    md_content = demo_engine.render_markdown_report(demo_traces)

    with open(demo_dir / "demo_trace.md", "w", encoding="utf-8") as f:
        f.write(md_content)

    with open(demo_dir / "traces.json", "w", encoding="utf-8") as f:
        json.dump([asdict(t) for t in demo_traces], f, indent=2)

    logger.info("Demonstration traces generated and rendered to demo_trace.md")
    suite_summary["experiments_completed"].append("DEMO_TRACES")

    # Save overall suite manifest
    with open(base_path / "suite_manifest.json", "w", encoding="utf-8") as f:
        json.dump(suite_summary, f, indent=2)

    logger.info("=== All Advanced Evaluation Experiments Completed Successfully ===")
    return suite_summary


if __name__ == "__main__":
    run_all_advanced_evaluations()
