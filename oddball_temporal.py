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
TIME_COL = "timestamp"  # Use the correct column name from the DataFrame
SRC_COL = "src"
DST_COL = "dst"
WEIGHT_COL = "weight"
WINDOW_MINUTES = 10

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

# --- Combine all results for later analysis ---
if results:
    all_scores = pd.concat(results, ignore_index=True)
    out_path = Path("results/oddball_temporal_scores.csv")
    all_scores.to_csv(out_path, index=False)
    print(f"\nSaved all temporal OddBall scores to: {out_path}")
else:
    print("\nNo results to save (no non-empty windows found)")
