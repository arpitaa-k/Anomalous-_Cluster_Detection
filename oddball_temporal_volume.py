"""
Temporal OddBall + Flow Volume Anomaly Detection

- For each time window, computes OddBall scores and flow volume (number of flows, total bytes, total packets) for each node.
- Combines OddBall score and normalized flow volume into a single anomaly score.
- Prints top suspicious nodes per window by combined score.
- Saves all results to CSV for further analysis/plotting.
"""
from pathlib import Path
import pandas as pd
import networkx as nx
import numpy as np
from oddball import compute_node_features, oddball_score
from data_loader import load_dataframe_pkl
import matplotlib.pyplot as plt

# --- Parameters ---
DATA_PATH = Path("data/friday_flows.pkl")
TIME_COL = "timestamp"
SRC_COL = "src"
DST_COL = "dst"
WEIGHT_COL = "weight"
BYTES_COL = "total_length_of_fwd_packets"  # Change if you want to use another bytes column
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
    # Compute flow volume features for each node in this window
    node_flows = window_df.groupby(SRC_COL).agg(
        num_flows=(DST_COL, "count"),
        total_bytes=(BYTES_COL, "sum"),
        total_packets=(WEIGHT_COL, "sum")
    ).reset_index().rename(columns={SRC_COL: "node"})
    # Merge OddBall and flow volume features
    scored = scored.merge(node_flows, on="node", how="left")
    # Normalize flow volume features
    for col in ["num_flows", "total_bytes", "total_packets"]:
        if col in scored.columns:
            vals = scored[col].fillna(0).to_numpy(dtype=float)
            lo, hi = np.min(vals), np.max(vals)
            if hi > lo:
                scored[col + "_norm"] = (vals - lo) / (hi - lo)
            else:
                scored[col + "_norm"] = 0.0
        else:
            scored[col + "_norm"] = 0.0
    # Combine OddBall and flow volume into a single anomaly score
    scored["combined_score"] = (
        scored["oddball_score"] + scored["num_flows_norm"] + scored["total_bytes_norm"] + scored["total_packets_norm"]
    ) / 4.0
    results.append(scored)
    # Print a simple summary for this window
    print("\n" + "-" * 60)
    print(f"Window {i+1}/{len(window_edges)}: {w_start} to {w_end}")
    print(f"Graph nodes: {G.number_of_nodes()}, edges: {G.number_of_edges()}")
    print("Top 5 suspicious nodes by combined score:")
    print(scored.sort_values("combined_score", ascending=False)
              .head(5)[["node", "combined_score", "oddball_score", "num_flows", "total_bytes", "total_packets"]].to_string(index=False))

# --- Combine all results for later analysis ---
if results:
    all_scores = pd.concat(results, ignore_index=True)
    out_path = Path("results/oddball_volume_temporal_scores.csv")
    all_scores.to_csv(out_path, index=False)
    print(f"\nSaved all temporal OddBall+Volume scores to: {out_path}")
else:
    print("\nNo results to save (no non-empty windows found)")

# --- Visualization: Plot combined anomaly score over time for key nodes ---
print("\nPlotting combined anomaly score over time for key nodes...")
top_nodes = set()
for window_df in results:
    top_nodes.update(window_df.sort_values("combined_score", ascending=False).head(3)["node"])
# Always include attacker if present
if "172.16.0.1" in all_scores["node"].values:
    top_nodes.add("172.16.0.1")

plt.figure(figsize=(14, 7))
for node in top_nodes:
    node_df = all_scores[all_scores["node"] == node].sort_values("window_start")
    plt.plot(node_df["window_start"], node_df["combined_score"], marker='o', label=node)
plt.xlabel("Time Window Start")
plt.ylabel("Combined Anomaly Score")
plt.title("Combined OddBall + Flow Volume Anomaly Score Over Time")
plt.legend()
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig("results/oddball_volume_timeseries.png")
plt.show()
print("Saved plot to results/oddball_volume_timeseries.png")

# --- Visualization: Plot top nodes (including attacker) ---
import matplotlib.pyplot as plt

# Helper: get top N nodes by max combined score (always include attacker)
def get_top_nodes(df, score_col, n=4, attacker="172.16.0.1"):
    top = df.groupby("node")[score_col].max().sort_values(ascending=False).head(n).index.tolist()
    if attacker not in top and attacker in df["node"].values:
        top = top[:-1] + [attacker]  # ensure attacker is always included
    return top

# Load all results (if not already loaded)
all_scores = pd.concat(results, ignore_index=True) if results else pd.DataFrame()

# 1. Combined Score Plot
plt.figure(figsize=(12, 6))
top_combined = get_top_nodes(all_scores, "combined_score", n=4)
for node in top_combined:
    node_df = all_scores[all_scores["node"] == node].sort_values("window_start")
    plt.plot(node_df["window_start"], node_df["combined_score"], marker='o', label=node)
plt.xlabel("Time Window Start")
plt.ylabel("Combined Anomaly Score")
plt.title("Combined OddBall + Flow Volume Anomaly Score Over Time")
plt.legend()
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig("results/oddball_volume_timeseries_combined.png")
plt.show()
print("Saved plot to results/oddball_volume_timeseries_combined.png")

# 2. Flow Volume Plot (num_flows)
plt.figure(figsize=(12, 6))
top_flows = get_top_nodes(all_scores, "num_flows", n=4)
for node in top_flows:
    node_df = all_scores[all_scores["node"] == node].sort_values("window_start")
    plt.plot(node_df["window_start"], node_df["num_flows"], marker='o', label=node)
plt.xlabel("Time Window Start")
plt.ylabel("Number of Flows")
plt.title("Flow Volume (Number of Flows) Over Time")
plt.legend()
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig("results/oddball_volume_timeseries_flows.png")
plt.show()
print("Saved plot to results/oddball_volume_timeseries_flows.png")

# 3. OddBall Score Plot
plt.figure(figsize=(12, 6))
top_oddball = get_top_nodes(all_scores, "oddball_score", n=4)
for node in top_oddball:
    node_df = all_scores[all_scores["node"] == node].sort_values("window_start")
    plt.plot(node_df["window_start"], node_df["oddball_score"], marker='o', label=node)
plt.xlabel("Time Window Start")
plt.ylabel("OddBall Score")
plt.title("OddBall Score Over Time")
plt.legend()
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig("results/oddball_volume_timeseries_oddball.png")
plt.show()
print("Saved plot to results/oddball_volume_timeseries_oddball.png")

# --- Plot overall network traffic over time (total flows and total packets per window) ---
if results:
    window_traffic = []
    for window_df in results:
        if not window_df.empty:
            w_start = window_df["window_start"].iloc[0]
            total_flows = window_df["num_flows"].sum()
            total_packets = window_df["total_packets"].sum()
            window_traffic.append({"window_start": w_start, "total_flows": total_flows, "total_packets": total_packets})
    traffic_df = pd.DataFrame(window_traffic)
    plt.figure(figsize=(12, 6))
    plt.plot(traffic_df["window_start"], traffic_df["total_flows"], marker='o', label="Total Flows")
    plt.plot(traffic_df["window_start"], traffic_df["total_packets"], marker='s', label="Total Packets")
    plt.xlabel("Time Window Start")
    plt.ylabel("Count")
    plt.title("Overall Network Traffic Over Time")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig("results/overall_traffic_timeseries.png")
    plt.show()
    print("Saved plot to results/overall_traffic_timeseries.png")
