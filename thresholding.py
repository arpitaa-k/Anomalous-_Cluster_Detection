import pandas as pd


def apply_adaptive_threshold(
    df: pd.DataFrame,
    score_col: str = "oddball_score",
    window: int = 200,
    sigma: float = 2.5,
    percentile: float = 95.0,
) -> pd.DataFrame:
    result = df.copy().reset_index(drop=True)

    # A rolling threshold is not meaningful without temporal ordering.
    # Use a simple global percentile cutoff until time-sliced snapshots are added.
    threshold = result[score_col].quantile(percentile / 100.0)
    result["adaptive_threshold"] = threshold
    result["is_anomaly"] = result[score_col] > result["adaptive_threshold"]

    return result
