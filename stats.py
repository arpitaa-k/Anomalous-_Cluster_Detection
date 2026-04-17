import pandas as pd
from scipy.stats import mannwhitneyu, ttest_ind
from sklearn.metrics import roc_auc_score


def _label_key(label: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in str(label).strip())
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned.strip("_") or "Unknown"


def _evaluate_benign_vs_attack(
    df: pd.DataFrame,
    score_col: str,
    label_col: str,
) -> dict[str, float]:
    if label_col not in df.columns:
        return {}

    eval_df = df[[score_col, label_col]].dropna().copy()
    if eval_df.empty:
        return {}

    label_series = eval_df[label_col]

    if pd.api.types.is_bool_dtype(label_series):
        y_true = label_series.astype(bool)
        y_score = eval_df[score_col].astype(float)

        benign_scores = y_score[~y_true]
        attack_scores = y_score[y_true]

        metrics: dict[str, float] = {
            "evaluated_nodes": float(len(eval_df)),
            "malicious_nodes": float(y_true.sum()),
            "benign_nodes": float((~y_true).sum()),
        }

        if y_true.nunique() == 2:
            metrics["roc_auc"] = float(roc_auc_score(y_true.astype(int), y_score))

        if len(benign_scores) > 0 and len(attack_scores) > 0:
            try:
                _, mw_p = mannwhitneyu(benign_scores, attack_scores, alternative="two-sided")
            except ValueError:
                mw_p = float("nan")

            if len(benign_scores) > 1 and len(attack_scores) > 1:
                _, t_p = ttest_ind(benign_scores, attack_scores, equal_var=False)
            else:
                t_p = float("nan")

            mean_b = benign_scores.mean()
            mean_a = attack_scores.mean()
            std_b = benign_scores.std(ddof=1) if len(benign_scores) > 1 else 0.0
            std_a = attack_scores.std(ddof=1) if len(attack_scores) > 1 else 0.0
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

    eval_df[label_col] = label_series.astype(str).str.strip()
    benign_mask = eval_df[label_col].str.lower() == "benign"

    benign_scores = eval_df.loc[benign_mask, score_col].astype(float)
    attack_scores = eval_df.loc[~benign_mask, score_col].astype(float)

    metrics: dict[str, float] = {
        "evaluated_nodes": float(len(eval_df)),
        "malicious_nodes": float((~benign_mask).sum()),
        "benign_nodes": float(benign_mask.sum()),
    }

    if len(benign_scores) > 0 and len(attack_scores) > 0:
        y_true = pd.Series([0] * len(benign_scores) + [1] * len(attack_scores), dtype=int)
        y_score = pd.concat([benign_scores, attack_scores], ignore_index=True)

        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
        except ValueError:
            metrics["roc_auc"] = float("nan")

        try:
            _, mw_p = mannwhitneyu(benign_scores, attack_scores, alternative="two-sided")
        except ValueError:
            mw_p = float("nan")

        if len(benign_scores) > 1 and len(attack_scores) > 1:
            _, t_p = ttest_ind(benign_scores, attack_scores, equal_var=False)
        else:
            t_p = float("nan")

        mean_b = benign_scores.mean()
        mean_a = attack_scores.mean()
        std_b = benign_scores.std(ddof=1) if len(benign_scores) > 1 else 0.0
        std_a = attack_scores.std(ddof=1) if len(attack_scores) > 1 else 0.0
        pooled_denom = ((std_b ** 2) + (std_a ** 2)) / 2.0
        if pooled_denom > 0:
            cohen_d = (mean_a - mean_b) / (pooled_denom ** 0.5)
        else:
            cohen_d = 0.0

        metrics["mann_whitney_p"] = float(mw_p)
        metrics["t_test_p"] = float(t_p)
        metrics["cohens_d"] = float(cohen_d)
        metrics["group_hypothesis_pass"] = float(mw_p < 0.05)

    attack_labels = sorted(eval_df.loc[~benign_mask, label_col].unique().tolist())
    for attack_label in attack_labels:
        attack_subset = eval_df.loc[eval_df[label_col] == attack_label, score_col].astype(float)
        if len(attack_subset) == 0 or len(benign_scores) == 0:
            continue

        pair_scores = pd.concat([
            benign_scores.rename("score"),
            attack_subset.rename("score"),
        ], ignore_index=True)
        pair_truth = pd.Series([0] * len(benign_scores) + [1] * len(attack_subset), dtype=int)

        try:
            auc = float(roc_auc_score(pair_truth, pair_scores))
        except ValueError:
            auc = float("nan")

        try:
            _, mw_pair_p = mannwhitneyu(benign_scores, attack_subset, alternative="two-sided")
            mw_pair_p = float(mw_pair_p)
        except ValueError:
            mw_pair_p = float("nan")

        label_key = _label_key(attack_label)
        metrics[f"{label_key}_auc"] = auc
        metrics[f"{label_key}_mann_whitney_p"] = mw_pair_p

    return metrics


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

    eval_df[label_col] = eval_df[label_col].astype(bool)
    eval_df = eval_df.rename(columns={label_col: "is_malicious"})
    metrics = _evaluate_benign_vs_attack(eval_df, score_col=score_col, label_col="is_malicious")

    if "majority_label" in df.columns:
        label_metrics = _evaluate_benign_vs_attack(df, score_col=score_col, label_col="majority_label")
        for key, value in label_metrics.items():
            if key not in metrics:
                metrics[key] = value

    return metrics


def evaluate_flow_labels(
    df: pd.DataFrame,
    score_col: str = "oddball_score",
    label_col: str = "label",
) -> dict[str, float]:
    metrics = _evaluate_benign_vs_attack(df, score_col=score_col, label_col=label_col)
    flow_metrics = {f"flow_{key}": value for key, value in metrics.items()}
    flow_metrics["flow_evaluated_flows"] = flow_metrics.pop("flow_evaluated_nodes", float("nan"))
    flow_metrics["flow_malicious_flows"] = flow_metrics.pop("flow_malicious_nodes", float("nan"))
    flow_metrics["flow_benign_flows"] = flow_metrics.pop("flow_benign_nodes", float("nan"))
    return flow_metrics
