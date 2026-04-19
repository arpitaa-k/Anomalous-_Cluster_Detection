from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


SCORES_PATH = Path("results/isolation_forest_temporal_scores.csv")
OUTPUT_PATH = Path("results/isolation_forest_score_timeseries.png")
ATTACKER_NODE = "172.16.0.1"
PREFERRED_NODES = [
    "192.168.10.15",
    "192.168.10.5",
    "192.168.10.9",
    "192.168.10.14",
    "192.168.10.8",
]


def _choose_nodes(df: pd.DataFrame) -> list[str]:
    chosen: list[str] = []
    node_set = set(df["node"].astype(str))

    if ATTACKER_NODE in node_set:
        chosen.append(ATTACKER_NODE)

    for node in PREFERRED_NODES:
        if node in node_set and node not in chosen:
            chosen.append(node)

    top_nodes = (
        df.groupby("node", as_index=False)["isolation_forest_score"]
        .mean()
        .sort_values("isolation_forest_score", ascending=False)["node"]
        .astype(str)
        .tolist()
    )
    for node in top_nodes:
        if node not in chosen:
            chosen.append(node)
        if len(chosen) >= 6:
            break
    return chosen


def main() -> None:
    df = pd.read_csv(SCORES_PATH)
    df["window_start"] = pd.to_datetime(df["window_start"])
    df["node"] = df["node"].astype(str)

    plot_nodes = _choose_nodes(df)

    plt.figure(figsize=(12, 6))
    colors = ["red", "blue", "green", "orange", "purple", "magenta", "brown"]
    for i, node in enumerate(plot_nodes):
        node_df = df[df["node"] == node].sort_values("window_start")
        label = f"Attacker {node}" if node == ATTACKER_NODE else f"Node {node}"
        plt.plot(
            node_df["window_start"],
            node_df["isolation_forest_score"],
            marker="o",
            linewidth=2.2 if node == ATTACKER_NODE else 1.5,
            color=colors[i % len(colors)],
            label=label,
        )

    plt.xlabel("Time Window Start")
    plt.ylabel("Isolation Forest Score")
    plt.title("Isolation Forest Score Over Time for Key Nodes")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(OUTPUT_PATH)
    print(f"Saved plot to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
