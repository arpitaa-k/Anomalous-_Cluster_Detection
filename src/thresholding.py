import pandas as pd


def apply_adaptive_threshold(
    df: pd.DataFrame,
    score_col: str = "oddball_score",
    window: int = 200,
    sigma: float = 2.5,
) -> pd.DataFrame:
    result = df.copy().reset_index(drop=True)

    rolling_mean = result[score_col].rolling(window=window, min_periods=20).mean()
    rolling_std = result[score_col].rolling(window=window, min_periods=20).std(ddof=0)

    global_mean = result[score_col].mean()
    global_std = result[score_col].std(ddof=0)

    result["adaptive_threshold"] = (rolling_mean + sigma * rolling_std).fillna(global_mean + sigma * global_std)
    result["is_anomaly"] = result[score_col] > result["adaptive_threshold"]

    return result
