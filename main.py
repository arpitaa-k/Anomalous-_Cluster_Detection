import argparse
from pathlib import Path

import pandas as pd

from config import PipelineConfig
from data_loader import build_node_majority_labels, load_cicids_folder, standardize_flow_columns
from graph_builder import build_weighted_graph
from oddball import compute_node_features, oddball_score
from reporting import generate_artifacts
from stats import apply_z_test, evaluate_flow_labels, evaluate_with_labels
from thresholding import apply_adaptive_threshold


def parse_args() -> PipelineConfig:
    parser = argparse.ArgumentParser(description="OddBall + hypothesis testing for CICIDS2017")
    parser.add_argument("--input-dir", type=Path, required=True, help="Directory containing CICIDS2017 CSV files")
    parser.add_argument("--output", type=Path, required=True, help="Output CSV path")
    parser.add_argument("--max-rows", type=int, default=None, help="Read at most N rows in total (for quick experiments)")
    parser.add_argument("--alpha", type=float, default=0.01, help="Significance level for p-value filtering")
    parser.add_argument("--z-threshold", type=float, default=3.0, help="Absolute z-score threshold")
    parser.add_argument("--rolling-window", type=int, default=200, help="Rolling window size for adaptive threshold")
    parser.add_argument("--threshold-sigma", type=float, default=2.5, help="Sigma multiplier for adaptive threshold")

    args = parser.parse_args()

    return PipelineConfig(
        input_dir=args.input_dir,
        output_file=args.output,
        max_rows=args.max_rows,
        alpha=args.alpha,
        z_threshold=args.z_threshold,
        rolling_window=args.rolling_window,
        threshold_sigma=args.threshold_sigma,
    )


def run_pipeline(cfg: PipelineConfig) -> None:
    raw_df = load_cicids_folder(cfg.input_dir, max_rows=cfg.max_rows)
    flows = standardize_flow_columns(raw_df)
    node_labels = build_node_majority_labels(flows)

    graph = build_weighted_graph(flows)
    features = compute_node_features(graph)

    scored = oddball_score(features)
    tested = apply_z_test(scored)
    thresholded = apply_adaptive_threshold(
        tested,
        score_col="oddball_score",
        window=cfg.rolling_window,
        sigma=cfg.threshold_sigma,
    )

    if not node_labels.empty:
        thresholded = thresholded.merge(node_labels, how="left", left_on="node", right_on="node")

    eval_metrics = evaluate_with_labels(thresholded, score_col="oddball_score", label_col="is_malicious")

    flow_scored = flows.copy()
    node_score_map = scored.set_index("node")["oddball_score"]
    flow_scored["source_oddball_score"] = flow_scored["src"].map(node_score_map)
    flow_metrics = evaluate_flow_labels(flow_scored, score_col="source_oddball_score", label_col="label")

    thresholded["group_hypothesis_pass"] = bool(eval_metrics.get("group_hypothesis_pass", 0.0) >= 1.0)
    thresholded["passes_hypothesis_test"] = pd.NA

    cfg.output_file.parent.mkdir(parents=True, exist_ok=True)
    thresholded.sort_values(by="oddball_score", ascending=False).to_csv(cfg.output_file, index=False)
    artifacts = generate_artifacts(graph, thresholded, cfg.output_file, eval_metrics, flow_df=flow_scored, flow_metrics=flow_metrics)

    total_nodes = len(thresholded)
    anomalies = int(thresholded["is_anomaly"].sum())
    confirmed = int(bool(eval_metrics.get("group_hypothesis_pass", 0.0) >= 1.0))

    print(f"Processed nodes: {total_nodes}")
    print(f"Adaptive anomalies: {anomalies}")
    print(f"Group-level hypothesis pass: {confirmed}")
    if eval_metrics:
        print("Label-aware evaluation:")
        for key, value in eval_metrics.items():
            print(f"  {key}: {value}")
        attack_metrics = sorted(
            key for key in eval_metrics.keys() if key.endswith("_auc") or key.endswith("_mann_whitney_p")
        )
        if attack_metrics:
            print("Per-attack-family metrics:")
            for key in attack_metrics:
                print(f"  {key}: {eval_metrics[key]}")
    if flow_metrics:
        print("Flow-label evaluation:")
        for key, value in flow_metrics.items():
            print(f"  {key}: {value}")
        flow_attack_metrics = sorted(
            key for key in flow_metrics.keys() if key.endswith("_auc") or key.endswith("_mann_whitney_p")
        )
        if flow_attack_metrics:
            print("Flow per-attack-family metrics:")
            for key in flow_attack_metrics:
                print(f"  {key}: {flow_metrics[key]}")
    print("Generated artifacts:")
    for name, path in artifacts.items():
        print(f"  {name}: {path}")
    print(f"Saved results to: {cfg.output_file}")


def main() -> None:
    cfg = parse_args()
    run_pipeline(cfg)


if __name__ == "__main__":
    main()
