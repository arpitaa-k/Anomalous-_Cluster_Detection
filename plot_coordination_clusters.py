from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from sklearn.decomposition import PCA


INPUT_PATH = Path("results/coordination_detection_clusters.csv")
OUTPUT_PATH = Path("results/coordination_clusters_plot.png")


def main() -> None:
    df = pd.read_csv(INPUT_PATH)
    feature_cols = [
        col
        for col in df.columns
        if col not in {"node", "cluster_id", "max_score", "mean_score", "attacker_present"}
    ]

    X = df[feature_cols].astype(float).to_numpy()
    coords = PCA(n_components=2, random_state=42).fit_transform(X)

    plot_df = df[["node", "cluster_id", "attacker_present"]].copy()
    plot_df["x"] = coords[:, 0]
    plot_df["y"] = coords[:, 1]

    plt.figure(figsize=(12, 7))
    colors = ["blue", "green", "orange", "purple", "brown", "cyan"]
    for cluster_id in sorted(plot_df["cluster_id"].unique()):
        sub = plot_df[plot_df["cluster_id"] == cluster_id]
        plt.scatter(
            sub["x"],
            sub["y"],
            s=90,
            alpha=0.8,
            color=colors[int(cluster_id) % len(colors)],
            label=f"Cluster {cluster_id}",
        )

    attacker = plot_df[plot_df["attacker_present"] == True]
    if not attacker.empty:
        plt.scatter(
            attacker["x"],
            attacker["y"],
            s=180,
            marker="*",
            color="red",
            edgecolor="black",
            linewidth=1.0,
            label="Attacker 172.16.0.1",
        )
        for _, row in attacker.iterrows():
            plt.annotate(row["node"], (row["x"], row["y"]), xytext=(6, 6), textcoords="offset points")

    plt.xlabel("PCA Component 1")
    plt.ylabel("PCA Component 2")
    plt.title("Coordination Clusters from Temporal OddBall Trajectories")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(OUTPUT_PATH)
    print(f"Saved plot to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
