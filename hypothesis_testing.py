import pandas as pd
from scipy.stats import mannwhitneyu, ttest_ind
from sklearn.metrics import roc_auc_score
import numpy as np

# Load the final ranking CSV
csv_path = "results/final/final_ranked_nodes.csv"
df = pd.read_csv(csv_path)

score_col = "final_score"  # Change to 'consistency_score' if desired

if "is_malicious" in df.columns and df["is_malicious"].notna().any():
    # Convert to boolean if needed, and drop NaN rows
    df = df[df["is_malicious"].notna()].copy()
    df["is_malicious"] = df["is_malicious"].astype(str).map({"True": True, "False": False})
    attack_scores = df[df["is_malicious"] == True][score_col]
    benign_scores = df[df["is_malicious"] == False][score_col]

    # Mann-Whitney U Test
    u_stat, u_p = mannwhitneyu(attack_scores, benign_scores, alternative="greater")
    # T-Test
    t_stat, t_p = ttest_ind(attack_scores, benign_scores, equal_var=False)
    # Cohen's d
    cohend = (attack_scores.mean() - benign_scores.mean()) / np.sqrt(
        (attack_scores.std() ** 2 + benign_scores.std() ** 2) / 2
    )
    # ROC-AUC
    y_true = df["is_malicious"].astype(int)
    auc = roc_auc_score(y_true, df[score_col])

    print(f"Mann-Whitney U: {u_stat:.2f}, p={u_p:.2e}")
    print(f"T-Test: t={t_stat:.2f}, p={t_p:.2e}")
    print(f"Cohen's d: {cohend:.2f}")
    print(f"ROC-AUC: {auc:.3f}")

    # --- Additional Outlier Tests for Single Attacker ---
    print("\n--- Outlierness of Attacker (z-score, empirical p-value) ---")
    if "is_malicious" in df.columns and df["is_malicious"].notna().any():
        attacker_row = df[df["is_malicious"] == True]
        benign_scores = df[df["is_malicious"] == False][score_col]
        if not attacker_row.empty:
            attacker_score = attacker_row[score_col].iloc[0]
            mean = benign_scores.mean()
            std = benign_scores.std(ddof=1)
            z = (attacker_score - mean) / std if std > 0 else float('nan')
            empirical_p = (benign_scores >= attacker_score).mean()
            print(f"Attacker z-score: {z:.2f}")
            print(f"Empirical p-value: {empirical_p:.4f}")
        else:
            print("No attacker found in the data.")
    else:
        print("No ground truth labels available for outlierness test.")
else:
    print("No ground truth labels available. Unsupervised separation can be done by clustering or thresholding, but classic hypothesis tests require labels.")