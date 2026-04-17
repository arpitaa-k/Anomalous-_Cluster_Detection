from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd


def _safe_float(value: Any) -> str:
    try:
        return f"{float(value):.6g}"
    except (TypeError, ValueError):
        return "n/a"


def generate_artifacts(
    graph: nx.DiGraph,
    df: pd.DataFrame,
    output_file: Path,
    eval_metrics: dict[str, float],
    flow_df: pd.DataFrame | None = None,
    flow_metrics: dict[str, float] | None = None,
) -> dict[str, Path]:
    output_dir = output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    artifacts: dict[str, Path] = {}

    top50_path = output_dir / "top_50_anomalies.csv"
    df.sort_values("oddball_score", ascending=False).head(50).to_csv(top50_path, index=False)
    artifacts["top_50"] = top50_path

    # Plot 0: degree vs total weight in log-log space.
    degree_weight_path = output_dir / "plot_degree_vs_weight.png"
    plt.figure(figsize=(8, 5))
    plt.scatter(df["degree"], df["total_weight"], s=18, alpha=0.55, color="#457b9d")
    plt.xscale("log")
    plt.yscale("log")
    plt.title("Degree vs Total Weight (Log-Log)")
    plt.xlabel("Degree")
    plt.ylabel("Total Weight")
    plt.tight_layout()
    plt.savefig(degree_weight_path, dpi=150)
    plt.close()
    artifacts["degree_vs_weight"] = degree_weight_path

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

    # Plot 2b: attack-family boxplot using majority_label if available.
    if "majority_label" in df.columns and df["majority_label"].notna().any():
        boxplot_path = output_dir / "plot_score_by_attack_type.png"
        plot_df = df[["majority_label", "oddball_score"]].dropna().copy()
        plot_df["majority_label"] = plot_df["majority_label"].astype(str).str.strip()

        benign_labels = [label for label in plot_df["majority_label"].unique() if label.lower() == "benign"]
        attack_labels = sorted([label for label in plot_df["majority_label"].unique() if label.lower() != "benign"])
        label_order = benign_labels + attack_labels

        grouped_scores = [
            plot_df.loc[plot_df["majority_label"] == label, "oddball_score"].astype(float).tolist()
            for label in label_order
        ]

        if grouped_scores:
            plt.figure(figsize=(max(10, len(label_order) * 1.6), 6))
            plt.boxplot(grouped_scores, labels=label_order, showfliers=True)
            plt.xticks(rotation=30, ha="right")
            plt.title("OddBall Score by Attack Type")
            plt.xlabel("Majority Label")
            plt.ylabel("OddBall Score")
            plt.tight_layout()
            plt.savefig(boxplot_path, dpi=150)
            plt.close()
            artifacts["score_by_attack_type_boxplot"] = boxplot_path

    # Plot 2c: flow-level boxplot by original attack label when available.
    if flow_df is not None and "label" in flow_df.columns and flow_df["label"].notna().any():
        flow_boxplot_path = output_dir / "plot_score_by_flow_label.png"
        plot_df = flow_df[["label", "source_oddball_score"]].dropna().copy()
        plot_df["label"] = plot_df["label"].astype(str).str.strip()

        benign_labels = [label for label in plot_df["label"].unique() if label.lower() == "benign"]
        attack_labels = sorted([label for label in plot_df["label"].unique() if label.lower() != "benign"])
        label_order = benign_labels + attack_labels

        grouped_scores = [
            plot_df.loc[plot_df["label"] == label, "source_oddball_score"].astype(float).tolist()
            for label in label_order
        ]

        if grouped_scores:
            plt.figure(figsize=(max(10, len(label_order) * 1.6), 6))
            plt.boxplot(grouped_scores, labels=label_order, showfliers=True)
            plt.xticks(rotation=30, ha="right")
            plt.title("OddBall Score by Flow Label")
            plt.xlabel("Flow Label")
            plt.ylabel("OddBall Score")
            plt.tight_layout()
            plt.savefig(flow_boxplot_path, dpi=150)
            plt.close()
            artifacts["score_by_flow_label_boxplot"] = flow_boxplot_path

    # Plot 3: correlation heatmap across detector scores.
    heatmap_path = output_dir / "plot_score_correlation.png"
    score_cols = [
        "score_edpl_norm",
        "score_ewpl_norm",
        "score_elwpl_norm",
        "score_graph_deviance_norm",
        "score_lof_norm",
        "oddball_score",
    ]
    available_score_cols = [col for col in score_cols if col in df.columns]
    if available_score_cols:
        plt.figure(figsize=(8, 6))
        corr = df[available_score_cols].corr()
        image = plt.imshow(corr.values, cmap="viridis", vmin=-1, vmax=1)
        plt.colorbar(image, fraction=0.046, pad=0.04)
        plt.xticks(range(len(available_score_cols)), available_score_cols, rotation=45, ha="right")
        plt.yticks(range(len(available_score_cols)), available_score_cols)
        for row_index in range(corr.shape[0]):
            for col_index in range(corr.shape[1]):
                plt.text(
                    col_index,
                    row_index,
                    f"{corr.iloc[row_index, col_index]:.2f}",
                    ha="center",
                    va="center",
                    color="white" if abs(corr.iloc[row_index, col_index]) > 0.5 else "black",
                    fontsize=8,
                )
        plt.title("Correlation Between Detector Scores")
        plt.tight_layout()
        plt.savefig(heatmap_path, dpi=150)
        plt.close()
        artifacts["score_correlation"] = heatmap_path

    # Plot 4: top anomalies bar chart.
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

    # Plot 5: top node ego-network.
    top_ego_path = output_dir / "plot_top_egonet.png"
    if not df.empty and graph.number_of_nodes() > 0:
        top_node = str(df.sort_values("oddball_score", ascending=False).iloc[0]["node"])
        if top_node in graph:
            neighborhood = set(graph.predecessors(top_node)).union(set(graph.successors(top_node)))
            neighborhood = set(list(neighborhood)[:24])
            neighborhood.add(top_node)
            subgraph = graph.subgraph(neighborhood).copy()
            plt.figure(figsize=(10, 8))
            pos = nx.spring_layout(subgraph, seed=42, k=0.8)
            node_colors = ["#e63946" if node == top_node else "#457b9d" for node in subgraph.nodes()]
            node_sizes = [900 if node == top_node else 260 for node in subgraph.nodes()]
            edge_widths = [max(float(data.get("weight", 1.0)) / 10000.0, 0.5) for _, _, data in subgraph.edges(data=True)]
            nx.draw_networkx_edges(subgraph, pos, alpha=0.35, width=edge_widths, arrows=False)
            nx.draw_networkx_nodes(subgraph, pos, node_color=node_colors, node_size=node_sizes)
            nx.draw_networkx_labels(subgraph, pos, font_size=7)
            plt.title(f"Ego-Network of Top Anomaly: {top_node}")
            plt.axis("off")
            plt.tight_layout()
            plt.savefig(top_ego_path, dpi=150)
            plt.close()
            artifacts["top_egonet"] = top_ego_path

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
        attack_metric_keys = sorted(
            key for key in eval_metrics.keys() if key.endswith("_auc") or key.endswith("_mann_whitney_p")
        )
        if attack_metric_keys:
            lines.append("")
            lines.append("### Per-Attack Metrics")
            for key in attack_metric_keys:
                lines.append(f"- {key}: {_safe_float(eval_metrics[key])}")
    else:
        lines.append("- Label-aware statistics unavailable for this run.")

    if flow_metrics:
        lines.append("")
        lines.append("### Flow-Level Evaluation")
        for key in [
            "flow_evaluated_flows",
            "flow_malicious_flows",
            "flow_benign_flows",
            "flow_roc_auc",
            "flow_mann_whitney_p",
            "flow_t_test_p",
            "flow_cohens_d",
        ]:
            if key in flow_metrics:
                lines.append(f"- {key}: {_safe_float(flow_metrics[key])}")

        flow_attack_metric_keys = sorted(
            key for key in flow_metrics.keys() if key.endswith("_auc") or key.endswith("_mann_whitney_p")
        )
        if flow_attack_metric_keys:
            lines.append("")
            lines.append("### Flow Per-Attack Metrics")
            for key in flow_attack_metric_keys:
                lines.append(f"- {key}: {_safe_float(flow_metrics[key])}")

    lines.extend(
        [
            "",
            "## Generated Artifacts",
            f"- Top 50 anomaly table: {top50_path.name}",
            f"- Score distribution plot: {score_hist_path.name}",
            f"- Degree/weight plot: {degree_weight_path.name}",
            f"- Top 20 anomaly plot: {top_plot_path.name}",
        ]
    )

    if "score_by_label" in artifacts:
        lines.append(f"- Label-wise score plot: {artifacts['score_by_label'].name}")
    if "score_by_attack_type_boxplot" in artifacts:
        lines.append(f"- Attack-type boxplot: {artifacts['score_by_attack_type_boxplot'].name}")
    if "score_by_flow_label_boxplot" in artifacts:
        lines.append(f"- Flow-label boxplot: {artifacts['score_by_flow_label_boxplot'].name}")
    if "score_correlation" in artifacts:
        lines.append(f"- Score correlation heatmap: {artifacts['score_correlation'].name}")
    if "top_egonet" in artifacts:
        lines.append(f"- Top anomaly ego-network: {artifacts['top_egonet'].name}")

    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "- High oddball_score indicates stronger deviation from expected graph behavior.",
            "- is_anomaly is based on adaptive thresholding over score distribution.",
            "- The per-node z-test was removed; significance is evaluated at the group level.",
            "- Degree/weight, correlation, and ego-network plots help explain the graph structure behind anomalies.",
            "- For robust conclusions, prefer larger runs (100k rows or full-day files).",
        ]
    )

    summary_path.write_text("\n".join(lines), encoding="utf-8")
    artifacts["summary"] = summary_path

    return artifacts
