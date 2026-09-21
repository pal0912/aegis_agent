"""End-to-end execution script for the Advanced Evaluation Layer suite.

Executes all advanced evaluation studies with strict experiment isolation:
1. Adaptive Red-Team Evaluation (results/advanced_eval_final/)
2. Repeated Trials Study (results/repeated_trials_final/)
3. Container Runtime Boundary Verification (results/container_final/)
4. Cross-Version Regression Comparator (results/regression_final/)
5. Residual Risk Experiments (results/residual_risks_final/)
6. Component Latency Profiling (results/performance_final/)
7. Demonstration Trace Generation (results/advanced_eval_final/demo/)
"""

from dataclasses import asdict
import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from evals.benchmark.adaptive_redteam import (
    AdaptiveRedTeamEngine,
    ObservationModel,
)
from evals.benchmark.artifacts import (
    generate_manifest,
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
    adaptive_dir_path: str = "results/advanced_eval_final",
    repeated_dir_path: str = "results/repeated_trials_final",
    container_dir_path: str = "results/container_final",
    regression_dir_path: str = "results/regression_final",
    residual_dir_path: str = "results/residual_risks_final",
    performance_dir_path: str = "results/performance_final",
) -> Dict[str, Any]:
    """Executes the complete hardened advanced evaluation methodology suite."""
    adaptive_dir = Path(adaptive_dir_path)
    repeated_dir = Path(repeated_dir_path)
    container_dir = Path(container_dir_path)
    regression_dir = Path(regression_dir_path)
    residual_dir = Path(residual_dir_path)
    perf_dir = Path(performance_dir_path)

    for d in [
        adaptive_dir,
        repeated_dir,
        container_dir,
        regression_dir,
        residual_dir,
        perf_dir,
    ]:
        d.mkdir(parents=True, exist_ok=True)

    suite_summary: Dict[str, Any] = {
        "suite_name": "AegisAgent Advanced Evaluation Layer (Hardened)",
        "timestamp": time.time(),
        "experiments_completed": [],
    }

    all_attacks = load_attack_corpus(subset="full")
    harness = InstrumentedSyntheticSinkHarness()
    agent = AegisBenchmarkAgent(harness)

    # ========================================================================
    # 1. Adaptive Red-Team Evaluation (Black-Box & Privileged Separate)
    # ========================================================================
    logger.info("=== Starting 1. Adaptive Red-Team (Black-Box & Privileged) ===")
    sample_ids = [
        "ATK-001",
        "ATK-010",
        "ATK-024",
        "ATK-036",
        "ATK-044",
    ]
    adaptive_scenarios = [
        s for s in all_attacks if s.scenario_id in sample_ids
    ]
    if not adaptive_scenarios:
        adaptive_scenarios = all_attacks[:5]

    # 1a. Black-Box Adaptive Red-Team
    engine_bbox = AdaptiveRedTeamEngine(
        max_turns=5,
        mutation_budget=10,
        timeout_seconds=30.0,
        random_seed=42,
        observation_model=ObservationModel.BLACK_BOX,
    )
    bbox_summary = engine_bbox.evaluate_adaptive_corpus(
        adaptive_scenarios, harness, agent
    )
    bbox_dict = asdict(bbox_summary)

    bbox_dir = Path("results/advanced_eval_final/black_box")
    for target_dir in [adaptive_dir, bbox_dir]:
        target_dir.mkdir(parents=True, exist_ok=True)
        with open(target_dir / "summary.json", "w", encoding="utf-8") as f:
            summ_copy = dict(bbox_dict)
            summ_copy.pop("trajectories", None)
            json.dump(summ_copy, f, indent=2)

        with open(
            target_dir / "trajectories.jsonl", "w", encoding="utf-8"
        ) as f:
            for traj in bbox_dict.get("trajectories", []):
                f.write(json.dumps(traj) + "\n")

        generate_manifest(
            str(target_dir),
            stage="FINAL",
            run_id=bbox_summary.run_id,
        )

    # 1b. Privileged Security Feedback Adaptive Red-Team
    engine_priv = AdaptiveRedTeamEngine(
        max_turns=5,
        mutation_budget=10,
        timeout_seconds=30.0,
        random_seed=42,
        observation_model=ObservationModel.PRIVILEGED_SECURITY_FEEDBACK,
    )
    priv_summary = engine_priv.evaluate_adaptive_corpus(
        adaptive_scenarios, harness, agent
    )
    priv_dict = asdict(priv_summary)

    priv_dir = Path("results/advanced_eval_final/privileged")
    priv_dir.mkdir(parents=True, exist_ok=True)
    with open(priv_dir / "summary.json", "w", encoding="utf-8") as f:
        summ_copy = dict(priv_dict)
        summ_copy.pop("trajectories", None)
        json.dump(summ_copy, f, indent=2)

    with open(priv_dir / "trajectories.jsonl", "w", encoding="utf-8") as f:
        for traj in priv_dict.get("trajectories", []):
            f.write(json.dumps(traj) + "\n")

    generate_manifest(
        str(priv_dir),
        stage="FINAL",
        run_id=priv_summary.run_id,
    )

    logger.info(
        f"Adaptive Red-Team completed: Black-Box Observed ASR="
        f"{bbox_summary.observed_adaptive_asr:.2%}, Privileged Observed ASR="
        f"{priv_summary.observed_adaptive_asr:.2%}"
    )
    suite_summary["experiments_completed"].append("ADAPTIVE_REDTEAM")

    # ========================================================================
    # 2. Repeated Trials Study (5 Trials)
    # ========================================================================
    logger.info("=== Starting 2. Repeated Trials Study (5 Trials) ===")
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

    generate_manifest(
        str(repeated_dir),
        stage="FINAL",
        run_id=rep_summary.run_id,
    )

    logger.info(
        f"Repeated Trials completed: Baseline ASR={rep_summary.baseline_asr_mean:.2%} "
        f"CI={rep_summary.baseline_asr_ci_95}, Aegis ASR={rep_summary.aegis_asr_mean:.2%} "
        f"CI={rep_summary.aegis_asr_ci_95}, McNemar p={rep_summary.mcnemar_test.get('p_value_formatted')}"
    )
    suite_summary["experiments_completed"].append("REPEATED_TRIAL")

    # ========================================================================
    # 3. Container Runtime Boundary Verification
    # ========================================================================
    logger.info("=== Starting 3. Container Runtime Boundary Verification ===")
    container_harness = ContainerizedRuntimeHarness(
        profile=ContainerSecurityProfile(user="1000:1000", read_only_rootfs=True)
    )
    container_meta = container_harness.get_runtime_metadata()

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

    generate_manifest(
        str(container_dir),
        stage="FINAL",
        run_id="container_boundary_check",
    )

    logger.info(
        f"Container runtime verified. Mode: {container_meta.get('runtime_type')}, "
        f"Isolation Claim: {container_meta.get('isolation_claim')}"
    )
    suite_summary["experiments_completed"].append("CONTAINER_RUNTIME")

    # ========================================================================
    # 4. Cross-Version Regression Comparator
    # ========================================================================
    logger.info("=== Starting 4. Cross-Version Regression Comparator ===")
    comparator = CrossVersionComparator()
    pre_dir = "results/full_run_pre_remediation"
    final_dir = "results/final_full_run"

    if Path(pre_dir).exists() and Path(final_dir).exists():
        report = comparator.compare_runs(pre_dir, final_dir)
        with open(
            regression_dir / "regression_report.json", "w", encoding="utf-8"
        ) as f:
            json.dump(asdict(report), f, indent=2)
        generate_manifest(
            str(regression_dir),
            stage="FINAL",
            run_id="regression_v1_vs_v2",
        )
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
    risk_evaluator = ResidualRiskEvaluator(seed=42)
    risk_report = risk_evaluator.execute_all_residual_risk_studies(harness, agent)

    with open(
        residual_dir / "residual_risk_report.json", "w", encoding="utf-8"
    ) as f:
        json.dump(asdict(risk_report), f, indent=2)

    generate_manifest(
        str(residual_dir),
        stage="FINAL",
        run_id=risk_report.run_id,
    )

    logger.info("Residual risk studies complete. Saved residual_risk_report.json")
    suite_summary["experiments_completed"].append("RESIDUAL_RISK")

    # ========================================================================
    # 6. Component Latency Profiling
    # ========================================================================
    logger.info("=== Starting 6. Component Latency Profiling ===")
    profiler = ComponentLatencyProfiler(
        warmup_runs=5,
        measurement_runs=50,
        neural_warmup_runs=5,
        neural_measurement_runs=50,
    )
    profiles = profiler.run_all_profiles()
    profiler.export_csv(profiles, str(perf_dir / "component_latency.csv"))
    profiler.export_neural_metadata(
        profiles, str(perf_dir / "neural_metadata.json")
    )

    with open(perf_dir / "profiles.json", "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2)

    profiler.export_raw_samples(str(perf_dir / "raw_latency.jsonl"))

    generate_manifest(
        str(perf_dir),
        stage="FINAL",
        run_id="perf_profiling_50_samples",
    )

    logger.info("Component latency profiling complete. Exported CSV & JSON.")
    suite_summary["experiments_completed"].append("PERFORMANCE_STUDY")

    # ========================================================================
    # 7. Demonstration Trace Generation
    # ========================================================================
    logger.info("=== Starting 7. Demonstration Trace Generation ===")
    demo_dir = adaptive_dir / "demo"
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

    logger.info("=== All Advanced Evaluation Experiments Completed Successfully ===")
    return suite_summary


if __name__ == "__main__":
    run_all_advanced_evaluations()
