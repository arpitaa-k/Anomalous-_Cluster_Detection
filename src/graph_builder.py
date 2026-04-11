import networkx as nx
import pandas as pd


def build_weighted_graph(flow_df: pd.DataFrame) -> nx.DiGraph:
    graph = nx.DiGraph()

    grouped = (
        flow_df.groupby(["src", "dst"], as_index=False)["weight"]
        .sum()
        .rename(columns={"weight": "edge_weight"})
    )

    for row in grouped.itertuples(index=False):
        graph.add_edge(row.src, row.dst, weight=float(row.edge_weight))

    return graph
