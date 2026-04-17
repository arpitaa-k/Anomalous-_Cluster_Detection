from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


def _safe_float(value: Any) -> str:
    try:
        return f"{float(value):.6g}"
    except (TypeError, ValueError):
        return "n/a"


def generate_artifacts(
    df: pd.DataFrame,
    output_file: Path,
    eval_metrics: dict[str, float],
) -> dict[str, Path]:
    output_dir = output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, Path] = {}

    top50_path = output_dir / "top_50_anomalies.csv"
    df.sort_values("oddball_score", ascending=False).head(50).to_csv(top50_path, index=False)
    artifacts["top_50"] = top50_path

    # Plot 1: overall score distribution.
    score_hist_path = output_dir / "plot_score_distribution.png"
    plt.figure(figsize=(8, 5))
    plt.hist(df["oddball_score"], bins=40, color="#2a9d8f", edgecolor="#1f1f1f", alpha=0.85)
    plt.title("OddBall Score Distribution")
    plt.xlabel("OddBall Score")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(score_hist_path, dpi=150)
    plt.close()
    artifacts["score_distribution"] = score_hist_path

    # Plot 2: label-wise score histogram when node labels are available.
    if "is_malicious" in df.columns and df["is_malicious"].notna().any():
        label_hist_path = output_dir / "plot_score_by_label.png"
        benign = df[df["is_malicious"] == False]["oddball_score"]
        malicious = df[df["is_malicious"] == True]["oddball_score"]

        plt.figure(figsize=(8, 5))
        if len(benign) > 0:
            plt.hist(benign, bins=40, alpha=0.7, label="Benign", color="#4c78a8")
        if len(malicious) > 0:
            plt.hist(malicious, bins=40, alpha=0.7, label="Malicious", color="#e45756")
        plt.title("OddBall Score by Node Label")
        plt.xlabel("OddBall Score")
        plt.ylabel("Count")
        if len(benign) > 0 or len(malicious) > 0:
            plt.legend()
        plt.tight_layout()
        plt.savefig(label_hist_path, dpi=150)
        plt.close()
        artifacts["score_by_label"] = label_hist_path

    # Plot 3: top anomalies bar chart.
    top_plot_path = output_dir / "plot_top_20_anomalies.png"
    top20 = df.sort_values("oddball_score", ascending=False).head(20).copy()
    plt.figure(figsize=(10, 7))
    plt.barh(top20["node"].astype(str)[::-1], top20["oddball_score"][::-1], color="#f4a261")
    plt.title("Top 20 Nodes by OddBall Score")
    plt.xlabel("OddBall Score")
    plt.ylabel("Node")
    plt.tight_layout()
    plt.savefig(top_plot_path, dpi=150)
    plt.close()
    artifacts["top_20_plot"] = top_plot_path

    summary_path = output_dir / "assignment_summary.md"
    total_nodes = len(df)
    adaptive_anomalies = int(df["is_anomaly"].sum()) if "is_anomaly" in df.columns else 0
    group_hypothesis_pass = bool(eval_metrics.get("group_hypothesis_pass", 0.0) >= 1.0)

    lines = [
        "# Assignment Results Summary",
        "",
        "## Run Overview",
        f"- Input output file: {output_file.name}",
        f"- Total processed nodes: {total_nodes}",
        f"- Adaptive anomalies: {adaptive_anomalies}",
        f"- Group-level hypothesis pass: {group_hypothesis_pass}",
        "",
        "## Statistical Evaluation",
    ]

    if eval_metrics:
        for key in [
            "evaluated_nodes",
            "malicious_nodes",
            "benign_nodes",
            "roc_auc",
            "mann_whitney_p",
            "t_test_p",
            "cohens_d",
        ]:
            if key in eval_metrics:
                lines.append(f"- {key}: {_safe_float(eval_metrics[key])}")
    else:
        lines.append("- Label-aware statistics unavailable for this run.")

    lines.extend(
        [
            "",
            "## Generated Artifacts",
            f"- Top 50 anomaly table: {top50_path.name}",
            f"- Score distribution plot: {score_hist_path.name}",
            f"- Top 20 anomaly plot: {top_plot_path.name}",
        ]
    )

    if "score_by_label" in artifacts:
        lines.append(f"- Label-wise score plot: {artifacts['score_by_label'].name}")

    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "- High oddball_score indicates stronger deviation from expected graph behavior.",
            "- is_anomaly is based on adaptive thresholding over score distribution.",
            "- The per-node z-test was removed; significance is evaluated at the group level.",
            "- For robust conclusions, prefer larger runs (100k rows or full-day files).",
        ]
    )

    summary_path.write_text("\n".join(lines), encoding="utf-8")
    artifacts["summary"] = summary_path

    return artifacts
