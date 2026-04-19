from pathlib import Path
import pickle

import numpy as np
import pandas as pd
from sklearn.neighbors import LocalOutlierFactor

from oddball import compute_node_features


def _safe_min_max(values: np.ndarray) -> np.ndarray:
    clean = np.nan_to_num(values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
    lo = clean.min(initial=0.0)
    hi = clean.max(initial=0.0)
    if hi <= lo:
        return np.zeros_like(clean)
    return (clean - lo) / (hi - lo)


def _try_load_labels(labels_path: Path) -> pd.DataFrame | None:
    if not labels_path.exists():
        return None

    try:
        with open(labels_path, "rb") as handle:
            labels = pickle.load(handle)
    except Exception as exc:
        print(f"Warning: could not load labels from {labels_path}: {exc}")
        return None

    if not isinstance(labels, pd.DataFrame):
        print(f"Warning: labels file at {labels_path} did not contain a DataFrame.")
        return None

    required_columns = {"node", "majority_label", "is_malicious"}
    missing_columns = required_columns.difference(labels.columns)
    if missing_columns:
        print(f"Warning: labels file missing columns: {sorted(missing_columns)}")
        return None

    return labels


def _load_graph(graph_path: Path):
    with open(graph_path, "rb") as handle:
        graph = pickle.load(handle)

    nodes = graph.number_of_nodes() if hasattr(graph, "number_of_nodes") else 0
    edges = graph.number_of_edges() if hasattr(graph, "number_of_edges") else 0
    print(f"Loaded graph from {graph_path} ({nodes} nodes, {edges} edges)")
    return graph


def compute_lof_scores(feature_df: pd.DataFrame) -> pd.DataFrame:
    df = feature_df.copy()

    eps = 1e-9
    df["out_in_degree_ratio"] = (df["out_degree"] + 1.0) / (df["in_degree"] + 1.0)
    df["out_degree_share"] = df["out_degree"] / (df["degree"] + eps)
    feature_cols = [
        "degree",
        "out_degree",
        "in_degree",
        "total_weight",
        "N_i",
        "E_i",
        "W_i",
        "lambda_w",
        "out_in_degree_ratio",
        "out_degree_share",
    ]
    X = df[feature_cols].astype(float).to_numpy()
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    lof_score = np.zeros(len(df), dtype=float)
    if len(df) >= 5:
        n_neighbors = min(20, len(df) - 1)
        lof = LocalOutlierFactor(n_neighbors=n_neighbors, metric="euclidean")
        lof.fit(X)
        lof_score = -lof.negative_outlier_factor_

    df["lof_score_raw"] = lof_score
    df["lof_score"] = _safe_min_max(lof_score)
    return df


import matplotlib.pyplot as plt

def main() -> None:
    graph_path = Path("data/friday_graph.pkl")
    labels_path = Path("data/friday_labels.pkl")
    output_dir = Path("results/static/lof")
    output_path = output_dir / "scores.csv"
    plot_path = output_dir / "top20_plot.png"
    summary_md = Path("results/summary_outputs.md")

    print("\n[LOF] Scoring nodes...")
    if not graph_path.exists():
        raise FileNotFoundError(f"Graph file not found at {graph_path}. Run: python data_loader.py")

    graph = _load_graph(graph_path)
    features = compute_node_features(graph)
    scored = compute_lof_scores(features)

    labels = _try_load_labels(labels_path)
    if labels is not None:
        scored = scored.merge(labels, on="node", how="left")

    output_dir.mkdir(parents=True, exist_ok=True)
    scored.sort_values("lof_score", ascending=False).to_csv(output_path, index=False)

    # Print concise summary
    summary = []
    summary.append(f"## LOF Static\n")
    summary.append(f"✓ Saved LOF scores to: {output_path}")
    top_nodes = scored.sort_values("lof_score", ascending=False).head(10)
    preview_cols = ["node", "lof_score"]
    if "majority_label" in scored.columns:
        preview_cols.append("majority_label")
    if "is_malicious" in scored.columns:
        preview_cols.append("is_malicious")
    summary.append("\nTop 10 suspicious nodes:\n")
    summary.append(top_nodes[preview_cols].to_markdown(index=False))

    # Append summary to markdown file
    with open(summary_md, "a", encoding="utf-8") as f:
        f.write("\n".join(summary) + "\n\n---\n")

    # Plot top 20 suspicious nodes, highlight attacker if present
    top20 = scored.sort_values("lof_score", ascending=False).head(20)
    attacker = "172.16.0.1"
    colors = ["gold" if str(n) == attacker else "darkorange" for n in top20["node"]]
    plt.figure(figsize=(10, 5))
    plt.bar(top20["node"].astype(str), top20["lof_score"], color=colors)
    plt.xticks(rotation=75, ha="right", fontsize=8)
    plt.ylabel("LOF Score")
    plt.title("Top 20 Suspicious Nodes (LOF)\n[Attacker highlighted in gold]")
    plt.tight_layout()
    plt.savefig(plot_path)
    plt.close()
    print(f"✓ Saved plot to: {plot_path}")

if __name__ == "__main__":
    main()
