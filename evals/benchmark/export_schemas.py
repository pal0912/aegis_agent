"""Export JSON Schemas for AegisAgent Benchmark Contract models."""

import json
from pathlib import Path
from evals.benchmark.contract import (
    AttemptResult,
    BenchmarkMetadata,
    BenchmarkSummaryMetrics,
    PairedComparisonResult,
    ScenarioDefinition,
)

SCHEMAS_DIR = Path(__file__).parent / "schemas"


def export_all_schemas():
    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)

    models = {
        "scenario_definition.json": ScenarioDefinition,
        "attempt_result.json": AttemptResult,
        "paired_comparison_result.json": PairedComparisonResult,
        "benchmark_metadata.json": BenchmarkMetadata,
        "benchmark_summary_metrics.json": BenchmarkSummaryMetrics,
    }

    for filename, model_cls in models.items():
        schema_dict = model_cls.model_json_schema()
        output_path = SCHEMAS_DIR / filename
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(schema_dict, f, indent=2)
        print(f"Exported schema: {output_path}")


if __name__ == "__main__":
    export_all_schemas()
