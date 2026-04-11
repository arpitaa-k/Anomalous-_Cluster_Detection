import numpy as np
import pandas as pd
import networkx as nx
from sklearn.linear_model import LinearRegression


def compute_node_features(graph: nx.DiGraph) -> pd.DataFrame:
    rows: list[dict[str, float | str]] = []

    for node in graph.nodes:
        out_edges = graph.out_edges(node, data=True)
        in_edges = graph.in_edges(node, data=True)

        out_degree = graph.out_degree(node)
        in_degree = graph.in_degree(node)
        degree = out_degree + in_degree

        out_weight = sum(float(data.get("weight", 1.0)) for _, _, data in out_edges)
        in_weight = sum(float(data.get("weight", 1.0)) for _, _, data in in_edges)
        total_weight = out_weight + in_weight

        neighbors = set(graph.predecessors(node)).union(set(graph.successors(node)))
        local_edges = 0
        if neighbors:
            subgraph = graph.subgraph(neighbors)
            local_edges = subgraph.number_of_edges()

        rows.append(
            {
                "node": node,
                "degree": float(degree),
                "out_degree": float(out_degree),
                "in_degree": float(in_degree),
                "total_weight": float(total_weight),
                "local_edges": float(local_edges),
            }
        )

    return pd.DataFrame(rows)


def oddball_score(feature_df: pd.DataFrame) -> pd.DataFrame:
    df = feature_df.copy()

    # OddBall commonly studies power-law relations like E_w ~ N^alpha.
    # Here we model log(total_weight) against log(degree) and use residuals as anomaly score.
    safe_degree = np.maximum(df["degree"].to_numpy(dtype=float), 1.0)
    safe_weight = np.maximum(df["total_weight"].to_numpy(dtype=float), 1.0)

    x = np.log10(safe_degree).reshape(-1, 1)
    y = np.log10(safe_weight)

    model = LinearRegression()
    model.fit(x, y)
    pred = model.predict(x)

    residual = y - pred
    score = np.abs(residual)

    df["log_degree"] = x.flatten()
    df["log_weight"] = y
    df["oddball_pred"] = pred
    df["oddball_residual"] = residual
    df["oddball_score"] = score

    return df
