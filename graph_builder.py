import networkx as nx
import pandas as pd


def build_weighted_graph(flow_df: pd.DataFrame) -> nx.DiGraph:
    grouped = (
        flow_df.groupby(["src", "dst"], as_index=False)["weight"]
        .sum()
        .rename(columns={"weight": "weight"})
    )

    return nx.from_pandas_edgelist(
        grouped,
        source="src",
        target="dst",
        edge_attr="weight",
        create_using=nx.DiGraph(),
    )
