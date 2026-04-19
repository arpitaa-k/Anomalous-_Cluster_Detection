from pathlib import Path
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from oddball import compute_node_features


def _safe_min_max(values: np.ndarray) -> np.ndarray:
    clean = np.nan_to_num(values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
    lo = clean.min(initial=0.0)
    hi = clean.max(initial=0.0)
    if hi <= lo:
        return np.zeros_like(clean)
    return (clean - lo) / (hi - lo)


def _load_graph(graph_path: Path):
    with open(graph_path, "rb") as handle:
        graph = pickle.load(handle)

    nodes = graph.number_of_nodes() if hasattr(graph, "number_of_nodes") else 0
    edges = graph.number_of_edges() if hasattr(graph, "number_of_edges") else 0
    print(f"Loaded graph from {graph_path} ({nodes} nodes, {edges} edges)")
    return graph


def compute_isolation_forest_scores(feature_df: pd.DataFrame) -> pd.DataFrame:
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

    model = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=42,
    )
    model.fit(X)

    raw_scores = -model.score_samples(X)
    df["isolation_forest_score_raw"] = raw_scores
    df["isolation_forest_score"] = _safe_min_max(raw_scores)
    return df


def main() -> None:
    graph_path = Path("data/friday_graph.pkl")
    output_path = Path("results/isolation_forest_scores_friday.csv")

    print("=" * 70)
    print("STEP 2: ISOLATION FOREST SCORING")
    print("=" * 70)

    if not graph_path.exists():
        raise FileNotFoundError(f"Graph file not found at {graph_path}.")

    graph = _load_graph(graph_path)

    print("\nComputing node features...")
    features = compute_node_features(graph)
    print(f"Feature rows: {len(features)}")

    print("\nComputing Isolation Forest scores...")
    scored = compute_isolation_forest_scores(features)
    print(f"Scored nodes: {len(scored)}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    scored.sort_values("isolation_forest_score", ascending=False).to_csv(output_path, index=False)

    print(f"\nSaved scores to: {output_path}")
    print("\nTop 20 suspicious nodes:")
    print(
        scored.sort_values("isolation_forest_score", ascending=False)
        .head(20)[["node", "isolation_forest_score_raw", "isolation_forest_score"]]
        .to_string(index=False)
    )


if __name__ == "__main__":
    main()
