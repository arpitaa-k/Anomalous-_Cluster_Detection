"""
Temporal OddBall Scoring: Track node anomaly scores over time windows.

This script splits the Friday dataset into 10-minute windows, builds a graph for each window,
computes OddBall scores for each node in each window, and prints a simple summary showing
how node scores change over time.

- Each window is processed independently (no overlap with static OddBall script).
- Results are printed in a clear, step-by-step way for easy understanding.
- No changes to your existing oddball.py or static scoring files.

"""
from pathlib import Path
import pandas as pd
import networkx as nx
import numpy as np
from oddball import compute_node_features, oddball_score
from data_loader import load_dataframe_pkl


# --- Parameters ---
DATA_PATH = Path("data/friday_flows.pkl")
TIME_COL = "timestamp"
SRC_COL = "src"
DST_COL = "dst"
WEIGHT_COL = "weight"
WINDOW_MINUTES = 10
OUTPUT_DIR = Path("results/temporal/oddball")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
CSV_PATH = OUTPUT_DIR / "scores.csv"
PLOT_PATH = OUTPUT_DIR / "oddball_score_timeseries.png"

# --- Load Data ---
print("\nLoading Friday dataframe ...")
df = load_dataframe_pkl(DATA_PATH)
print(f"Rows loaded: {len(df)}")

# --- Convert time column to pandas datetime ---
df[TIME_COL] = pd.to_datetime(df[TIME_COL], errors="coerce")
df = df.dropna(subset=[TIME_COL])

# --- Set up time windows ---
start_time = df[TIME_COL].min()
end_time = df[TIME_COL].max()
window = pd.Timedelta(minutes=WINDOW_MINUTES)

print(f"\nSplitting into {WINDOW_MINUTES}-minute windows ...")
window_edges = []
cur = start_time
while cur < end_time:
    window_edges.append((cur, cur + window))
    cur += window
print(f"Total windows: {len(window_edges)}")

# --- Process each window ---
results = []
for i, (w_start, w_end) in enumerate(window_edges):
    window_df = df[(df[TIME_COL] >= w_start) & (df[TIME_COL] < w_end)]
    if window_df.empty:
        continue
    # Build directed graph for this window
    G = nx.DiGraph()
    for _, row in window_df.iterrows():
        src = row[SRC_COL]
        dst = row[DST_COL]
        weight = row.get(WEIGHT_COL, 1.0)
        if pd.isna(src) or pd.isna(dst):
            continue
        G.add_edge(src, dst, weight=weight)
    if G.number_of_nodes() == 0:
        continue
    # Compute OddBall scores
    features = compute_node_features(G)
    scored = oddball_score(features)
    scored["window_start"] = w_start
    scored["window_end"] = w_end
    results.append(scored)
    # Print a simple summary for this window
    print("\n" + "-" * 60)
    print(f"Window {i+1}/{len(window_edges)}: {w_start} to {w_end}")
    print(f"Graph nodes: {G.number_of_nodes()}, edges: {G.number_of_edges()}")
    print("Top 5 suspicious nodes in this window:")
    print(scored.sort_values("oddball_score", ascending=False)
              .head(5)[["node", "oddball_score"]].to_string(index=False))

if results:
    summary_md = Path("results/summary_outputs.md")
    all_scores = pd.concat(results, ignore_index=True)
    # Add out_in_degree_ratio and out_degree_share for LOF_temporal compatibility
    eps = 1e-9
    all_scores["out_in_degree_ratio"] = (all_scores["out_degree"] + 1.0) / (all_scores["in_degree"] + 1.0)
    all_scores["out_degree_share"] = all_scores["out_degree"] / (all_scores["degree"] + eps)
    all_scores.to_csv(CSV_PATH, index=False)
    print(f"\n✓ Saved all temporal OddBall scores to: {CSV_PATH}")

    # Only one clear plot: OddBall Score Over Time for top nodes, highlight attacker
    def get_top_nodes(df, score_col, n=4, attacker="172.16.0.1"):
        top = df.groupby("node")[score_col].max().sort_values(ascending=False).head(n).index.tolist()
        if attacker not in top and attacker in df["node"].values:
            top = top[:-1] + [attacker]
        return top

    import matplotlib.pyplot as plt
    import itertools
    plt.figure(figsize=(12, 6))
    top_oddball = get_top_nodes(all_scores, "oddball_score", n=4)
    # Use a color cycle for non-attacker nodes
    color_cycle = itertools.cycle(["crimson", "royalblue", "seagreen", "darkorange", "purple", "teal", "brown"])
    node_colors = {}
    for node in top_oddball:
        if str(node) == "172.16.0.1":
            node_colors[node] = "gold"
        else:
            node_colors[node] = next(color_cycle)
    for node in top_oddball:
        node_df = all_scores[all_scores["node"] == node].sort_values("window_start")
        plt.plot(node_df["window_start"], node_df["oddball_score"], marker='o', label=node, color=node_colors[node])
    plt.xlabel("Time Window Start")
    plt.ylabel("OddBall Score")
    plt.title("Top Nodes: OddBall Score Over Time (Temporal OddBall)\n[Attacker highlighted in gold]")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(PLOT_PATH)
    plt.close()
    print(f"✓ Saved plot to: {PLOT_PATH}")

    # Print concise summary and append to markdown
    summary = []
    summary.append(f"## OddBall Temporal\n")
    summary.append(f"✓ Saved all temporal OddBall scores to: {CSV_PATH}")
    summary.append("\nTop 5 suspicious nodes by max OddBall score:\n")
    summary.append(all_scores.groupby("node")["oddball_score"].max().sort_values(ascending=False).head(5).to_string())
    with open(summary_md, "a", encoding="utf-8") as f:
        f.write("\n".join(summary) + "\n\n---\n")
else:
    print("\nNo results to save (no non-empty windows found)")
