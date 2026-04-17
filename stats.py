import pandas as pd
from scipy.stats import mannwhitneyu, ttest_ind
from sklearn.metrics import roc_auc_score


def apply_z_test(df: pd.DataFrame, score_col: str = "oddball_score") -> pd.DataFrame:
    result = df.copy()

    mean = result[score_col].mean()
    std = result[score_col].std(ddof=0)

    if std == 0:
        result["z_score"] = 0.0
        result["p_value"] = float("nan")
        return result

    result["z_score"] = (result[score_col] - mean) / std
    # This is descriptive normalization only; group-level significance is handled below.
    result["p_value"] = float("nan")

    return result


def evaluate_with_labels(
    df: pd.DataFrame,
    score_col: str = "oddball_score",
    label_col: str = "is_malicious",
) -> dict[str, float]:
    if label_col not in df.columns:
        return {}

    eval_df = df[[score_col, label_col]].dropna().copy()
    if eval_df.empty:
        return {}

    y_true = eval_df[label_col].astype(bool)
    y_score = eval_df[score_col].astype(float)

    benign = y_score[~y_true]
    attack = y_score[y_true]

    metrics: dict[str, float] = {
        "evaluated_nodes": float(len(eval_df)),
        "malicious_nodes": float(y_true.sum()),
        "benign_nodes": float((~y_true).sum()),
    }

    if y_true.nunique() == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true.astype(int), y_score))

    if len(benign) > 0 and len(attack) > 0:
        _, mw_p = mannwhitneyu(benign, attack, alternative="two-sided")
        if len(benign) > 1 and len(attack) > 1:
            _, t_p = ttest_ind(benign, attack, equal_var=False)
        else:
            t_p = float("nan")

        mean_b = benign.mean()
        mean_a = attack.mean()
        std_b = benign.std(ddof=1) if len(benign) > 1 else 0.0
        std_a = attack.std(ddof=1) if len(attack) > 1 else 0.0
        pooled_denom = ((std_b ** 2) + (std_a ** 2)) / 2.0
        if pooled_denom > 0:
            cohen_d = (mean_a - mean_b) / (pooled_denom ** 0.5)
        else:
            cohen_d = 0.0

        metrics["mann_whitney_p"] = float(mw_p)
        metrics["t_test_p"] = float(t_p)
        metrics["cohens_d"] = float(cohen_d)
        metrics["group_hypothesis_pass"] = float(mw_p < 0.05)

    return metrics
