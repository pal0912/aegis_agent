"""Artifact exporter for AegisAgent benchmark execution results.

Exports reproducible run artifacts conforming to Benchmark Contract v1.0:
- metadata.json
- summary.json
- attempts.jsonl
- attacks.csv
- benign.csv
- ablations.csv
- report.html
"""

import csv
import json
from pathlib import Path
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from evals.benchmark.runner import BenchmarkRunResult


def export_run_artifacts(
    result: "BenchmarkRunResult", output_dir: str
) -> Dict[str, str]:
    """Exports all benchmark run artifacts into the specified directory."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    paths: Dict[str, str] = {}

    # 1. metadata.json
    metadata_file = out_path / "metadata.json"
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(result.metadata.model_dump(), f, indent=2)
    paths["metadata"] = str(metadata_file)

    # 2. summary.json
    summary_file = out_path / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(result.summary_metrics.model_dump(), f, indent=2)
    paths["summary"] = str(summary_file)

    # 3. attempts.jsonl
    attempts_file = out_path / "attempts.jsonl"
    with open(attempts_file, "w", encoding="utf-8") as f:
        for pc in result.paired_comparisons:
            f.write(pc.baseline_attempt.model_dump_json() + "\n")
            f.write(pc.aegis_attempt.model_dump_json() + "\n")
        for sc_id, abls in result.ablation_attempts.items():
            for abl in abls:
                f.write(abl.model_dump_json() + "\n")
        for bng in result.benign_attempts:
            f.write(bng.model_dump_json() + "\n")
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
                pc.scenario_id,
                pc.baseline_attempt.final_security_outcome.value,
                pc.baseline_attempt.objective_achieved,
                pc.aegis_attempt.final_security_outcome.value,
                pc.aegis_attempt.objective_achieved,
                pc.status.value,
                f"{pc.baseline_attempt.latency_ms:.2f}",
                f"{pc.aegis_attempt.latency_ms:.2f}",
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
                bng.scenario_id,
                outcome_val,
                bng.task_successful,
                bng.attempt_validity.value,
                f"{bng.latency_ms:.2f}",
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
                    abl.scenario_id,
                    abl.condition.value,
                    abl.final_security_outcome.value,
                    abl.objective_achieved,
                    abl.blast_radius.value,
                    f"{abl.latency_ms:.2f}",
                ])
    paths["ablations"] = str(ablations_file)

    # 7. latency.csv (explicit latency tiers profiled)
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

    # 8. report.html
    html_file = out_path / "report.html"
    from evals.benchmark.reports import generate_html_report
    generate_html_report(result, str(html_file))
    paths["report_html"] = str(html_file)

    return paths
