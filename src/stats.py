import pandas as pd
from scipy.stats import norm


def apply_z_test(df: pd.DataFrame, score_col: str = "oddball_score") -> pd.DataFrame:
    result = df.copy()

    mean = result[score_col].mean()
    std = result[score_col].std(ddof=0)

    if std == 0:
        result["z_score"] = 0.0
        result["p_value"] = 1.0
        return result

    result["z_score"] = (result[score_col] - mean) / std
    result["p_value"] = 2 * (1 - norm.cdf(result["z_score"].abs()))

    return result
