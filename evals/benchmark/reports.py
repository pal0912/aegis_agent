"""Report generation for AegisAgent benchmark execution results.

Generates self-contained interactive HTML reports and formatted terminal
summaries adhering strictly to Benchmark Contract v1.0.
"""

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evals.benchmark.runner import BenchmarkRunResult


def generate_html_report(
    result: "BenchmarkRunResult", output_path: str
) -> None:
    """Generates a self-contained, clean HTML report."""
    m = result.summary_metrics
    meta = result.metadata

    asr_base_str = (
        f"{(m.asr_baseline or 0.0) * 100:.1f}%"
        if m.asr_baseline is not None else "N/A"
    )
    asr_aegis_str = (
        f"{(m.asr_aegis or 0.0) * 100:.1f}%"
        if m.asr_aegis is not None else "N/A"
    )
    asr_red_str = (
        f"{(m.asr_reduction or 0.0) * 100:.1f}%"
        if m.asr_reduction is not None else "N/A"
    )
    cont_str = (
        f"{(m.containment_rate or 0.0) * 100:.1f}%"
        if m.containment_rate is not None else "N/A"
    )
    fpr_str = (
        f"{(m.fpr or 0.0) * 100:.1f}%"
        if m.fpr is not None else "0.0%"
    )
    util_loss_str = (
        f"{(m.utility_loss or 0.0) * 100:.1f}%"
        if m.utility_loss is not None else "0.0%"
    )

    # Attack rows
    attack_rows = []
    for pc in result.paired_comparisons:
        b_att = pc.baseline_attempt
        a_att = pc.aegis_attempt

        # Controls triggered
        ctrls_triggered = [
            k for k, v in a_att.controls.model_dump().items()
            if v in ("TRIGGERED", "BLOCKED")
        ]
        ctrls_str = ", ".join(ctrls_triggered) if ctrls_triggered else "None"

        # Evidence summary
        ev = a_att.evidence
        ev_items = []
        if ev.secrets_accessed:
            ev_items.append(f"secrets_read: {len(ev.secrets_accessed)}")
        if ev.secrets_exfiltrated:
            ev_items.append(f"exfiltrated: {len(ev.secrets_exfiltrated)}")
        if ev.tools_executed:
            ev_items.append(f"tools: {len(ev.tools_executed)}")
        ev_str = ", ".join(ev_items) if ev_items else "zero_side_effects"

        is_safe = a_att.final_security_outcome.value in (
            "BLOCKED", "CONTAINED"
        )
        a_badge = "badge-success" if is_safe else "badge-danger"
        b_badge = (
            "badge-danger" if b_att.objective_achieved else "badge-warning"
        )

        b_val = b_att.final_security_outcome.value
        a_val = a_att.final_security_outcome.value
        row = f"""
        <tr>
            <td><code>{pc.scenario_id}</code></td>
            <td><span class="badge {b_badge}">{b_val}</span></td>
            <td><span class="badge {a_badge}">{a_val}</span></td>
            <td>{ctrls_str}</td>
            <td><code>{ev_str}</code></td>
            <td>{a_att.latency_ms:.1f} ms</td>
        </tr>
        """
        attack_rows.append(row)

    # Benign rows
    benign_rows = []
    for bng in result.benign_attempts:
        outcome_val = bng.benign_outcome.value if bng.benign_outcome else "N/A"
        badge = "badge-success" if bng.task_successful else "badge-danger"
        row = f"""
        <tr>
            <td><code>{bng.scenario_id}</code></td>
            <td><span class="badge {badge}">{outcome_val}</span></td>
            <td>{'Yes' if bng.task_successful else 'No'}</td>
            <td>{bng.latency_ms:.1f} ms</td>
        </tr>
        """
        benign_rows.append(row)

    # Ablation rows
    ablation_rows = []
    for sc_id, abls in result.ablation_attempts.items():
        for abl in abls:
            is_abl_safe = abl.final_security_outcome.value in (
                "BLOCKED", "CONTAINED"
            )
            badge = "badge-success" if is_abl_safe else "badge-danger"
            abl_outcome = abl.final_security_outcome.value
            row = f"""
            <tr>
                <td><code>{abl.scenario_id}</code></td>
                <td><code>{abl.condition.value}</code></td>
                <td><span class="badge {badge}">{abl_outcome}</span></td>
                <td>{'Yes' if abl.objective_achieved else 'No'}</td>
                <td><code>{abl.blast_radius.value}</code></td>
                <td>{abl.latency_ms:.1f} ms</td>
            </tr>
            """
            ablation_rows.append(row)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisAgent Benchmark Report - {meta.run_id}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }}
        h1 {{ margin: 0 0 0.5rem 0; font-size: 1.8rem; color: var(--primary); }}
        .meta {{ color: var(--text-muted); font-size: 0.85rem; }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }}
        .kpi-title {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem; }}
        .kpi-value {{ font-size: 1.8rem; font-weight: bold; color: var(--text); }}
        .kpi-sub {{ font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem; }}
        .section-title {{ font-size: 1.25rem; margin: 2rem 0 1rem 0; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 2rem;
        }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; font-size: 0.9rem; border-bottom: 1px solid var(--border); }}
        th {{ background: #111827; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
        code {{ background: #0b1329; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-success {{ background: rgba(34, 197, 94, 0.15); color: var(--success); border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AegisAgent Benchmark Report (Contract v{meta.benchmark_contract_version})</h1>
            <div class="meta">
                Run ID: <code>{meta.run_id}</code> &bull; Timestamp: {meta.timestamp} &bull; OS: {meta.os_version} &bull; Python: {meta.python_version} &bull; Mode: {meta.validation_mode}
            </div>
        </header>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Attack Success Rate (ASR)</div>
                <div class="kpi-value">{asr_aegis_str}</div>
                <div class="kpi-sub">Baseline: {asr_base_str} (Red: {asr_red_str})</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Containment Rate</div>
                <div class="kpi-value">{cont_str}</div>
                <div class="kpi-sub">Blocked or Contained</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">False Positive Rate (FPR)</div>
                <div class="kpi-value">{fpr_str}</div>
                <div class="kpi-sub">Utility Loss: {util_loss_str}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Latency P50 / P95</div>
                <div class="kpi-value">{m.latency_p50_ms:.1f}ms</div>
                <div class="kpi-sub">P95: {m.latency_p95_ms:.1f}ms &bull; P99: {m.latency_p99_ms:.1f}ms</div>
            </div>
        </div>

        <h2 class="section-title">Paired Adversarial Evaluations ({len(result.paired_comparisons)} scenarios)</h2>
        <table>
            <thead>
                <tr>
                    <th>Scenario</th>
                    <th>Baseline</th>
                    <th>Aegis Full</th>
                    <th>Controls Triggered</th>
                    <th>Observable Evidence</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
                {''.join(attack_rows)}
            </tbody>
        </table>

        <h2 class="section-title">Benign Utility Evaluations ({len(result.benign_attempts)} documents)</h2>
        <table>
            <thead>
                <tr>
                    <th>Scenario</th>
                    <th>Outcome</th>
                    <th>Task Success</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
                {''.join(benign_rows)}
            </tbody>
        </table>

        {f'''
        <h2 class="section-title">Single-Control Ablation Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Scenario</th>
                    <th>Ablation Condition</th>
                    <th>Outcome</th>
                    <th>Obj Achieved</th>
                    <th>Blast Radius</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
                {''.join(ablation_rows)}
            </tbody>
        </table>
        ''' if ablation_rows else ''}
    </div>
</body>
</html>
"""

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def print_terminal_summary(result: "BenchmarkRunResult") -> None:
    """Prints a formatted summary table to the terminal."""
    m = result.summary_metrics
    meta = result.metadata

    asr_base = (
        f"{(m.asr_baseline or 0.0) * 100:.1f}%"
        if m.asr_baseline is not None else "N/A"
    )
    asr_aegis = (
        f"{(m.asr_aegis or 0.0) * 100:.1f}%"
        if m.asr_aegis is not None else "N/A"
    )
    asr_red = (
        f"{(m.asr_reduction or 0.0) * 100:.1f}%"
        if m.asr_reduction is not None else "N/A"
    )
    cont = (
        f"{(m.containment_rate or 0.0) * 100:.1f}%"
        if m.containment_rate is not None else "N/A"
    )
    fpr = (
        f"{(m.fpr or 0.0) * 100:.1f}%"
        if m.fpr is not None else "0.0%"
    )

    print("\n" + "=" * 70)
    print(f"AEGIS BENCHMARK RUN COMPLETE [Run ID: {meta.run_id}]")
    print("=" * 70)
    print(
        f"Contract: v{meta.benchmark_contract_version} | "
        f"Mode: {meta.validation_mode} | Seed: {meta.random_seed}"
    )
    print(
        f"Scenarios: {m.total_scenarios} ({m.valid_scenarios} valid) | "
        f"Attempts: {m.total_attempts}"
    )
    print("-" * 70)
    print(f"Baseline ASR:           {asr_base}")
    print(f"Aegis Full ASR:         {asr_aegis}")
    print(f"ASR Reduction:          {asr_red}")
    print(f"Containment Rate:       {cont}")
    print(f"Benign FPR:             {fpr}")
    print(
        f"Latency P50 / P95:      {m.latency_p50_ms:.1f}ms / "
        f"{m.latency_p95_ms:.1f}ms"
    )
    print("=" * 70 + "\n")
