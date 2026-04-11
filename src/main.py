import argparse
from pathlib import Path

from src.config import PipelineConfig
from src.data_loader import load_cicids_folder, standardize_flow_columns
from src.graph_builder import build_weighted_graph
from src.oddball import compute_node_features, oddball_score
from src.stats import apply_z_test
from src.thresholding import apply_adaptive_threshold


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

    thresholded["passes_hypothesis_test"] = (thresholded["p_value"] < cfg.alpha) & (
        thresholded["z_score"].abs() >= cfg.z_threshold
    )

    cfg.output_file.parent.mkdir(parents=True, exist_ok=True)
    thresholded.sort_values(by="oddball_score", ascending=False).to_csv(cfg.output_file, index=False)

    total_nodes = len(thresholded)
    anomalies = int(thresholded["is_anomaly"].sum())
    confirmed = int(thresholded["passes_hypothesis_test"].sum())

    print(f"Processed nodes: {total_nodes}")
    print(f"Adaptive anomalies: {anomalies}")
    print(f"Hypothesis-confirmed anomalies: {confirmed}")
    print(f"Saved results to: {cfg.output_file}")


def main() -> None:
    cfg = parse_args()
    run_pipeline(cfg)


if __name__ == "__main__":
    main()
