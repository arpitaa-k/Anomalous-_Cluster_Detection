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
OUTPUT_DIR = Path("results/temporal/oddball_volume")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
CSV_PATH = OUTPUT_DIR / "scores.csv"
PLOT_COMBINED_PATH = OUTPUT_DIR / "combined_score_timeseries.png"
PLOT_FLOWS_PATH = OUTPUT_DIR / "num_flows_timeseries.png"
PLOT_ODDBALL_PATH = OUTPUT_DIR / "oddball_score_timeseries.png"

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

if results:
    summary_md = Path("results/summary_outputs.md")
    all_scores = pd.concat(results, ignore_index=True)
    all_scores.to_csv(CSV_PATH, index=False)
    print(f"\n✓ Saved all temporal OddBall+Volume scores to: {CSV_PATH}")

    # Helper: get top N nodes by max combined score (always include attacker)
    def get_top_nodes(df, score_col, n=4, attacker="172.16.0.1"):
        top = df.groupby("node")[score_col].max().sort_values(ascending=False).head(n).index.tolist()
        if attacker not in top and attacker in df["node"].values:
            top = top[:-1] + [attacker]
        return top

    # Only one clear plot: Combined Score Over Time for top nodes, highlight attacker
    import matplotlib.pyplot as plt
    plt.figure(figsize=(12, 6))
    top_combined = get_top_nodes(all_scores, "combined_score", n=4)
    for node in top_combined:
        node_df = all_scores[all_scores["node"] == node].sort_values("window_start")
        color = "gold" if str(node) == "172.16.0.1" else "purple"
        plt.plot(node_df["window_start"], node_df["combined_score"], marker='o', label=node, color=color)
    plt.xlabel("Time Window Start")
    plt.ylabel("Combined Anomaly Score")
    plt.title("Top Nodes: Combined OddBall + Flow Volume Anomaly Score Over Time\n[Attacker highlighted in gold]")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(PLOT_COMBINED_PATH)
    plt.close()
    print(f"✓ Saved plot to: {PLOT_COMBINED_PATH}")

    # Print concise summary and append to markdown
    summary = []
    summary.append(f"## OddBall+Volume Temporal\n")
    summary.append(f"✓ Saved all temporal OddBall+Volume scores to: {CSV_PATH}")
    summary.append("\nTop 5 suspicious nodes by max combined score:\n")
    summary.append(all_scores.groupby("node")["combined_score"].max().sort_values(ascending=False).head(5).to_string())
    with open(summary_md, "a", encoding="utf-8") as f:
        f.write("\n".join(summary) + "\n\n---\n")
else:
    print("\nNo results to save (no non-empty windows found)")
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
