from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.neighbors import LocalOutlierFactor


INPUT_PATH = Path("results/oddball_temporal_scores.csv")
OUTPUT_PATH = Path("results/lof_temporal_scores.csv")
FEATURE_COLS = [
    "degree",
    "out_degree",
    "in_degree",
    "total_weight",
    "N_i",
    "E_i",
    "W_i",
    "lambda_w",
    "out_in_degree_ratio",
    "out_degree_share",
]


def _safe_min_max(values: np.ndarray) -> np.ndarray:
    clean = np.nan_to_num(values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
    lo = clean.min(initial=0.0)
    hi = clean.max(initial=0.0)
    if hi <= lo:
        return np.zeros_like(clean)
    return (clean - lo) / (hi - lo)


def _compute_window_lof(window_df: pd.DataFrame) -> pd.DataFrame:
    result = window_df.copy()
    eps = 1e-9
    result["out_in_degree_ratio"] = (result["out_degree"] + 1.0) / (result["in_degree"] + 1.0)
    result["out_degree_share"] = result["out_degree"] / (result["degree"] + eps)
    X = result[FEATURE_COLS].astype(float).to_numpy()
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    lof_score_raw = np.zeros(len(result), dtype=float)
    if len(result) >= 5:
        n_neighbors = min(20, len(result) - 1)
        lof = LocalOutlierFactor(n_neighbors=n_neighbors, metric="euclidean")
        lof.fit(X)
        lof_score_raw = -lof.negative_outlier_factor_

    result["lof_score_raw"] = lof_score_raw
    result["lof_score"] = _safe_min_max(lof_score_raw)
    return result


def main() -> None:
    print("=" * 70)
    print("STEP 3: TEMPORAL LOF SCORING")
    print("=" * 70)

    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Temporal OddBall file not found at {INPUT_PATH}. Run: python oddball_temporal.py"
        )

    df = pd.read_csv(INPUT_PATH)
    if "window_start" not in df.columns or "window_end" not in df.columns:
        raise ValueError("Expected window_start and window_end columns in temporal score file")

    missing_cols = [col for col in FEATURE_COLS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing feature columns in temporal score file: {missing_cols}")

    df["window_start"] = pd.to_datetime(df["window_start"])
    df["window_end"] = pd.to_datetime(df["window_end"])

    results: list[pd.DataFrame] = []
    grouped = df.groupby(["window_start", "window_end"], sort=True, group_keys=False)

    print(f"Processing {grouped.ngroups} time windows...")
    for i, ((window_start, window_end), window_df) in enumerate(grouped, start=1):
        scored_window = _compute_window_lof(window_df)
        results.append(scored_window)

        preview = (
            scored_window.sort_values("lof_score", ascending=False)
            .head(5)[["node", "lof_score"]]
            .to_string(index=False)
        )
        print("\n" + "-" * 60)
        print(f"Window {i}/{grouped.ngroups}: {window_start} to {window_end}")
        print(f"Nodes scored: {len(scored_window)}")
        print("Top 5 suspicious nodes in this window:")
        print(preview)

    output_df = pd.concat(results, ignore_index=True)
    output_df.to_csv(OUTPUT_PATH, index=False)
    print(f"\nSaved temporal LOF scores to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
