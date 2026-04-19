from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.cluster import SpectralClustering
from sklearn.metrics.pairwise import rbf_kernel


INPUT_PATH = Path("results/oddball_temporal_scores.csv")
OUTPUT_CSV = Path("results/coordination_detection_clusters.csv")
OUTPUT_MD = Path("results/coordination_detection_summary.md")


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Missing temporal scores file: {INPUT_PATH}")

    df = pd.read_csv(INPUT_PATH)
    df["window_start"] = pd.to_datetime(df["window_start"])
    df["node"] = df["node"].astype(str)

    pivot = (
        df.pivot_table(
            index="node",
            columns="window_start",
            values="oddball_score",
            fill_value=0.0,
            aggfunc="mean",
        )
        .sort_index()
    )

    node_strength = pivot.max(axis=1).sort_values(ascending=False)
    selected_nodes = node_strength.head(min(30, len(node_strength))).index.tolist()
    if "172.16.0.1" in pivot.index and "172.16.0.1" not in selected_nodes:
        if len(selected_nodes) >= min(30, len(node_strength)):
            selected_nodes = selected_nodes[:-1]
        selected_nodes.append("172.16.0.1")
    selected = pivot.loc[selected_nodes].copy()

    if len(selected) < 3:
        raise ValueError("Not enough nodes for spectral clustering.")

    X = selected.to_numpy(dtype=float)
    gamma = 1.0 / max(X.shape[1], 1)
    affinity = rbf_kernel(X, gamma=gamma)

    n_clusters = min(4, max(2, len(selected) // 6))
    model = SpectralClustering(
        n_clusters=n_clusters,
        affinity="precomputed",
        assign_labels="kmeans",
        random_state=42,
    )
    labels = model.fit_predict(affinity)

    cluster_df = selected.copy()
    cluster_df["cluster_id"] = labels
    cluster_df["max_score"] = selected.max(axis=1).to_numpy()
    cluster_df["mean_score"] = selected.mean(axis=1).to_numpy()
    cluster_df["attacker_present"] = cluster_df.index == "172.16.0.1"
    cluster_df = cluster_df.reset_index().rename(columns={"index": "node"})
    cluster_df.to_csv(OUTPUT_CSV, index=False)

    summary = (
        cluster_df.groupby("cluster_id", as_index=False)
        .agg(
            cluster_size=("node", "count"),
            avg_max_score=("max_score", "mean"),
            avg_mean_score=("mean_score", "mean"),
            attacker_nodes=("attacker_present", "sum"),
        )
        .sort_values(["attacker_nodes", "avg_max_score"], ascending=[False, False])
    )

    lines = [
        "# Coordination Detection Summary",
        "",
        "This detector applies spectral clustering to node score trajectories from OddBall temporal outputs.",
        "",
        f"- Nodes clustered: {len(cluster_df)}",
        f"- Clusters formed: {n_clusters}",
        "",
        "## Cluster Summary",
    ]
    for _, row in summary.iterrows():
        members = cluster_df.loc[cluster_df["cluster_id"] == row["cluster_id"], "node"].tolist()[:8]
        lines.append(
            "- "
            f"Cluster {int(row['cluster_id'])}: "
            f"size={int(row['cluster_size'])}, "
            f"avg_max_score={row['avg_max_score']:.4f}, "
            f"attacker_nodes={int(row['attacker_nodes'])}, "
            f"sample_members={members}"
        )

    attacker_row = cluster_df[cluster_df["node"] == "172.16.0.1"]
    lines.extend(["", "## Attacker Placement"])
    if attacker_row.empty:
        lines.append("- Attacker node 172.16.0.1 was not present in the selected clustered set.")
    else:
        cluster_id = int(attacker_row.iloc[0]["cluster_id"])
        members = cluster_df.loc[cluster_df["cluster_id"] == cluster_id, "node"].tolist()
        lines.append(f"- Attacker node 172.16.0.1 is assigned to cluster {cluster_id}.")
        lines.append(f"- Cluster {cluster_id} members: {members}")

    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"Saved coordination clusters to: {OUTPUT_CSV}")
    print(f"Saved coordination summary to: {OUTPUT_MD}")
    print("\nCluster summary:")
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
