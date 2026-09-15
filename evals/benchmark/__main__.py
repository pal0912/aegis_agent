"""Module execution entry point for python -m evals.benchmark."""

import sys
from evals.benchmark.cli import run_benchmark_cli

if __name__ == "__main__":
    sys.exit(run_benchmark_cli())
