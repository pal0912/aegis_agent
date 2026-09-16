"""Command-line interface for AegisAgent benchmark execution engine.

Usage:
    python -m evals.benchmark --mode smoke --output-dir results/
    python -m evals.benchmark --mode differential_smoke --output-dir results/
    python -m evals.benchmark --mode full --output-dir results/ --ablation all
"""

import argparse
import sys
from typing import List

from evals.benchmark.contract import ExperimentalCondition, ValidationScopeMode
from evals.benchmark.reports import print_terminal_summary
from evals.benchmark.runner import BenchmarkRunConfig, BenchmarkRunner


def parse_args(argv: List[str] = None) -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="AegisAgent Benchmark Execution Engine (Contract v1.0)"
    )
    parser.add_argument(
        "--mode",
        choices=["smoke", "validation", "full", "differential_smoke"],
        default="smoke",
        help="Benchmark execution mode (default: smoke).",
    )
    parser.add_argument(
        "--output-dir",
        default="results",
        help="Directory to write run artifacts (default: results).",
    )
    parser.add_argument(
        "--ablation",
        choices=[
            "none", "all", "dlp", "network", "detector", "capability", "memory"
        ],
        default="all",
        help="Single-control ablation condition to evaluate (default: all).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--validation-mode",
        choices=["DRY_RUN", "SIMULATION"],
        default="DRY_RUN",
        help="Validation safety mode (default: DRY_RUN).",
    )
    return parser.parse_args(argv)


def run_benchmark_cli(argv: List[str] = None) -> int:
    """Main CLI execution logic."""
    args = parse_args(argv)

    ablations = []
    if args.ablation == "all":
        ablations = [
            ExperimentalCondition.AEGIS_NO_DETECTOR,
            ExperimentalCondition.AEGIS_NO_DLP,
            ExperimentalCondition.AEGIS_NO_NETWORK,
            ExperimentalCondition.AEGIS_NO_CAPABILITY,
            ExperimentalCondition.AEGIS_NO_MEMORY,
        ]
    elif args.ablation == "dlp":
        ablations = [ExperimentalCondition.AEGIS_NO_DLP]
    elif args.ablation == "network":
        ablations = [ExperimentalCondition.AEGIS_NO_NETWORK]
    elif args.ablation == "detector":
        ablations = [ExperimentalCondition.AEGIS_NO_DETECTOR]
    elif args.ablation == "capability":
        ablations = [ExperimentalCondition.AEGIS_NO_CAPABILITY]
    elif args.ablation == "memory":
        ablations = [ExperimentalCondition.AEGIS_NO_MEMORY]

    val_mode = (
        ValidationScopeMode.SIMULATION
        if args.validation_mode == "SIMULATION"
        else ValidationScopeMode.DRY_RUN
    )

    config = BenchmarkRunConfig(
        mode=args.mode,
        output_dir=args.output_dir,
        ablation_conditions=ablations,
        seed=args.seed,
        validation_mode=val_mode,
    )

    runner = BenchmarkRunner(config)
    result = runner.run()

    print_terminal_summary(result)
    print(f"Artifacts successfully written to: {args.output_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(run_benchmark_cli())
