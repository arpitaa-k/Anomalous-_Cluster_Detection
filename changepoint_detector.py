from pathlib import Path

import numpy as np
import pandas as pd


INPUT_PATH = Path("results/oddball_temporal_scores.csv")
OUTPUT_CSV = Path("results/changepoint_detection_results.csv")
OUTPUT_MD = Path("results/changepoint_detection_summary.md")


def _mad_scale(values: np.ndarray) -> float:
    median = np.median(values)
    mad = np.median(np.abs(values - median))
    return 1.4826 * mad


def detect_changepoints(series: pd.Series, threshold_sigma: float = 3.0) -> pd.DataFrame:
    values = series.to_numpy(dtype=float)
    delta = np.diff(values, prepend=values[0])
    baseline = _mad_scale(delta)
    if baseline <= 1e-12:
        baseline = np.std(delta) if np.std(delta) > 1e-12 else 1.0

    z_like = np.abs(delta) / baseline
    return pd.DataFrame(
        {
            "value": values,
            "delta": delta,
            "change_score": z_like,
            "is_changepoint": z_like >= threshold_sigma,
        }
    )


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Missing temporal scores file: {INPUT_PATH}")

    df = pd.read_csv(INPUT_PATH)
    df["window_start"] = pd.to_datetime(df["window_start"])
    df["node"] = df["node"].astype(str)

    per_window = (
        df.groupby("window_start", as_index=False)
        .agg(
            mean_oddball_score=("oddball_score", "mean"),
            max_oddball_score=("oddball_score", "max"),
            active_nodes=("node", "nunique"),
        )
        .sort_values("window_start")
        .reset_index(drop=True)
    )

    attacker_df = (
        df[df["node"] == "172.16.0.1"][["window_start", "oddball_score"]]
        .rename(columns={"oddball_score": "attacker_oddball_score"})
        .sort_values("window_start")
    )
    merged = per_window.merge(attacker_df, on="window_start", how="left")
    merged["attacker_oddball_score"] = merged["attacker_oddball_score"].fillna(0.0)

    mean_changes = detect_changepoints(merged["mean_oddball_score"], threshold_sigma=2.5).add_prefix("mean_")
    max_changes = detect_changepoints(merged["max_oddball_score"], threshold_sigma=2.5).add_prefix("max_")
    attacker_changes = detect_changepoints(merged["attacker_oddball_score"], threshold_sigma=2.0).add_prefix("attacker_")

    result = pd.concat([merged, mean_changes, max_changes, attacker_changes], axis=1)
    result["any_changepoint"] = (
        result["mean_is_changepoint"] | result["max_is_changepoint"] | result["attacker_is_changepoint"]
    )
    result.to_csv(OUTPUT_CSV, index=False)

    key_points = result[result["any_changepoint"]].copy()
    lines = [
        "# Changepoint Detection Summary",
        "",
        "This detector uses a robust mean-shift style changepoint score over per-window OddBall statistics.",
        "",
        "## Signals",
        f"- Windows analyzed: {len(result)}",
        f"- Windows flagged as changepoints: {int(result['any_changepoint'].sum())}",
        f"- Strongest mean-score change: {result.loc[result['mean_change_score'].idxmax(), 'window_start']}",
        f"- Strongest max-score change: {result.loc[result['max_change_score'].idxmax(), 'window_start']}",
        f"- Strongest attacker-score change: {result.loc[result['attacker_change_score'].idxmax(), 'window_start']}",
        "",
        "## Flagged Windows",
    ]
    if key_points.empty:
        lines.append("- No windows crossed the changepoint threshold.")
    else:
        for _, row in key_points.iterrows():
            lines.append(
                "- "
                f"{row['window_start']}: "
                f"mean_change={row['mean_change_score']:.3f}, "
                f"max_change={row['max_change_score']:.3f}, "
                f"attacker_change={row['attacker_change_score']:.3f}"
            )

    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"Saved changepoint results to: {OUTPUT_CSV}")
    print(f"Saved changepoint summary to: {OUTPUT_MD}")
    print("\nFlagged windows:")
    if key_points.empty:
        print("None")
    else:
        print(
            key_points[
                ["window_start", "mean_change_score", "max_change_score", "attacker_change_score", "any_changepoint"]
            ].to_string(index=False)
        )


if __name__ == "__main__":
    main()
