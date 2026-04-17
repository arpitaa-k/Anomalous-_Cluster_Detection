import numpy as np
import pandas as pd
import networkx as nx
from sklearn.linear_model import LinearRegression
from sklearn.neighbors import LocalOutlierFactor
from scipy.sparse.linalg import eigs


def _safe_min_max(values: np.ndarray) -> np.ndarray:
    clean = np.nan_to_num(values.astype(float), nan=0.0, posinf=0.0, neginf=0.0)
    lo = clean.min(initial=0.0)
    hi = clean.max(initial=0.0)
    if hi <= lo:
        return np.zeros_like(clean)
    return (clean - lo) / (hi - lo)


def _fit_powerlaw_score(x_vals: np.ndarray, y_vals: np.ndarray) -> np.ndarray:
    x = np.asarray(x_vals, dtype=float)
    y = np.asarray(y_vals, dtype=float)

    valid = (x > 0) & (y > 0) & np.isfinite(x) & np.isfinite(y)
    scores = np.zeros_like(x, dtype=float)

    if valid.sum() < 5:
        return scores

    log_x = np.log10(x[valid]).reshape(-1, 1)
    log_y = np.log10(y[valid])

    model = LinearRegression()
    model.fit(log_x, log_y)
    pred_log_y = model.predict(log_x)
    residuals = log_y - pred_log_y
    obs_y = y[valid]
    raw_score = np.abs(residuals) * np.log1p(obs_y)

    scores[valid] = raw_score
    return scores


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
        egonet_nodes = neighbors.union({node})
        subgraph = graph.subgraph(egonet_nodes)

        n_i = float(subgraph.number_of_nodes())
        e_i = float(subgraph.number_of_edges())
        w_i = float(
            sum(float(data.get("weight", 1.0)) for _, _, data in subgraph.edges(data=True))
        )

        if subgraph.number_of_nodes() > 1:
            if subgraph.number_of_nodes() <= 200:
                w_matrix = nx.to_numpy_array(subgraph, weight="weight", dtype=float)
                eigvals = np.linalg.eigvals(w_matrix)
                lambda_w = float(np.max(np.real(eigvals)))
            else:
                sparse_matrix = nx.to_scipy_sparse_array(subgraph, weight="weight", dtype=float, format="csr")
                try:
                    eigval = eigs(sparse_matrix, k=1, which="LR", return_eigenvectors=False)[0]
                    lambda_w = float(np.real(eigval))
                except Exception:
                    w_matrix = nx.to_numpy_array(subgraph, weight="weight", dtype=float)
                    eigvals = np.linalg.eigvals(w_matrix)
                    lambda_w = float(np.max(np.real(eigvals)))
        else:
            lambda_w = 0.0

        rows.append(
            {
                "node": node,
                "degree": float(degree),
                "out_degree": float(out_degree),
                "in_degree": float(in_degree),
                "total_weight": float(total_weight),
                "N_i": n_i,
                "E_i": e_i,
                "W_i": w_i,
                "lambda_w": lambda_w,
            }
        )

    return pd.DataFrame(rows)


def oddball_score(feature_df: pd.DataFrame) -> pd.DataFrame:
    df = feature_df.copy()

    n_vals = np.maximum(df["N_i"].to_numpy(dtype=float), 1e-9)
    e_vals = np.maximum(df["E_i"].to_numpy(dtype=float), 1e-9)
    w_vals = np.maximum(df["W_i"].to_numpy(dtype=float), 1e-9)
    l_vals = np.maximum(df["lambda_w"].to_numpy(dtype=float), 1e-9)

    score_edpl = _fit_powerlaw_score(n_vals, e_vals)
    score_ewpl = _fit_powerlaw_score(e_vals, w_vals)
    score_elwpl = _fit_powerlaw_score(w_vals, l_vals)

    feats = np.column_stack([n_vals, e_vals, w_vals, l_vals])
    means = feats.mean(axis=0)
    stds = feats.std(axis=0)
    stds[stds == 0] = 1.0
    z = (feats - means) / stds
    score_graph_deviance = np.abs(z).sum(axis=1)

    lof_score = np.zeros(len(df), dtype=float)
    if len(df) >= 5:
        n_neighbors = min(20, len(df) - 1)
        lof = LocalOutlierFactor(n_neighbors=n_neighbors, metric="euclidean")
        lof.fit(feats)
        lof_score = -lof.negative_outlier_factor_

    df["score_edpl"] = score_edpl
    df["score_ewpl"] = score_ewpl
    df["score_elwpl"] = score_elwpl
    df["score_graph_deviance"] = score_graph_deviance
    df["score_lof"] = lof_score

    df["score_edpl_norm"] = _safe_min_max(score_edpl)
    df["score_ewpl_norm"] = _safe_min_max(score_ewpl)
    df["score_elwpl_norm"] = _safe_min_max(score_elwpl)
    df["score_graph_deviance_norm"] = _safe_min_max(score_graph_deviance)
    df["score_lof_norm"] = _safe_min_max(lof_score)

    df["oddball_score"] = (
        df["score_edpl_norm"]
        + df["score_ewpl_norm"]
        + df["score_elwpl_norm"]
        + df["score_graph_deviance_norm"]
        + df["score_lof_norm"]
    ) / 5.0

    return df
