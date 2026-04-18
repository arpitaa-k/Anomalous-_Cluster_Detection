"""
Plot OddBall scores over time for selected nodes.

- Plots the OddBall score of 172.16.0.1 (attacker) across all time windows.
- Also plots the scores for the most frequent top nodes (e.g., 192.168.10.15, 192.168.10.5).
- Highlights windows where the attacker's score is high.
- Produces a clear, readable line plot.
"""
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# --- Parameters ---
SCORES_PATH = Path("results/oddball_temporal_scores.csv")
ATTACKER_NODE = "172.16.0.1"
TOP_NODES = ["192.168.10.15", "192.168.10.5", "192.168.10.9", "192.168.10.14", "192.168.10.8"]  # Add more if needed

# --- Load data ---
df = pd.read_csv(SCORES_PATH)

# Convert window_start to datetime for plotting
if "window_start" in df.columns:
    df["window_start"] = pd.to_datetime(df["window_start"])
else:
    raise ValueError("window_start column not found in CSV")

# --- Prepare data for plotting ---
def get_node_scores(node):
    node_df = df[df["node"] == node].sort_values("window_start")
    return node_df["window_start"], node_df["oddball_score"]

plt.figure(figsize=(12, 6))

# Plot attacker
x_att, y_att = get_node_scores(ATTACKER_NODE)
plt.plot(x_att, y_att, marker='o', label=f"Attacker {ATTACKER_NODE}", linewidth=2, color='red')

# Plot top frequent nodes
colors = ['blue', 'green', 'orange', 'purple', 'magenta', 'yellow']
for i, node in enumerate(TOP_NODES):
    x, y = get_node_scores(node)
    plt.plot(x, y, marker='o', label=f"Node {node}", linewidth=1.5, color=colors[i % len(colors)])

plt.xlabel("Time Window Start")
plt.ylabel("OddBall Score")
plt.title("OddBall Score Over Time for Key Nodes")
plt.legend()
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.savefig("results/oddball_score_timeseries.png")
plt.show()
print("Saved plot to results/oddball_score_timeseries.png")
