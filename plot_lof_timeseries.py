from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


SCORES_PATH = Path("results/lof_temporal_scores.csv")
OUTPUT_PATH = Path("results/lof_score_timeseries.png")
ATTACKER_NODE = "172.16.0.1"
PREFERRED_NODES = [
    "192.168.10.15",
    "192.168.10.5",
    "192.168.10.9",
    "192.168.10.14",
    "192.168.10.8",
]


def get_node_scores(df: pd.DataFrame, node: str):
    node_df = df[df["node"] == node].sort_values("window_start")
    return node_df["window_start"], node_df["lof_score_raw"]


def choose_plot_nodes(df: pd.DataFrame) -> list[str]:
    chosen: list[str] = []

    if ATTACKER_NODE in set(df["node"].astype(str)):
        chosen.append(ATTACKER_NODE)

    for node in PREFERRED_NODES:
        if node in set(df["node"].astype(str)) and node not in chosen:
            chosen.append(node)

    top_nodes = (
        df.groupby("node", as_index=False)["lof_score"]
        .mean()
        .sort_values("lof_score", ascending=False)["node"]
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
    if not SCORES_PATH.exists():
        raise FileNotFoundError(
            f"Temporal LOF file not found at {SCORES_PATH}. Run: python LOF_temporal.py"
        )

    df = pd.read_csv(SCORES_PATH)
    if "window_start" not in df.columns:
        raise ValueError("window_start column not found in LOF temporal CSV")

    df["window_start"] = pd.to_datetime(df["window_start"])
    df["node"] = df["node"].astype(str)

    plot_nodes = choose_plot_nodes(df)
    if not plot_nodes:
        raise ValueError("No nodes available to plot")

    plt.figure(figsize=(12, 6))
    colors = [
        "red",
        "blue",
        "green",
        "orange",
        "purple",
        "magenta",
        "brown",
        "cyan",
        "black",
    ]

    for i, node in enumerate(plot_nodes):
        x_vals, y_vals = get_node_scores(df, node)
        label = f"Attacker {node}" if node == ATTACKER_NODE else f"Node {node}"
        width = 2.2 if node == ATTACKER_NODE else 1.5
        plt.plot(
            x_vals,
            y_vals,
            marker="o",
            label=label,
            linewidth=width,
            color=colors[i % len(colors)],
        )

    plt.xlabel("Time Window Start")
    plt.ylabel("LOF Raw Score (log scale)")
    plt.yscale("log")
    plt.title("LOF Raw Score Over Time for Key Nodes")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(OUTPUT_PATH)
    print(f"Saved plot to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
