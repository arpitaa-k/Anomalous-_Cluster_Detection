from pathlib import Path

import pandas as pd
import numpy as np
import pickle


DEFAULT_SOURCE_COLUMNS = [
    "Source IP",
    "Src IP",
    "src_ip",
    "source_ip",
]

DEFAULT_DEST_COLUMNS = [
    "Destination IP",
    "Dst IP",
    "dst_ip",
    "destination_ip",
]

DEFAULT_WEIGHT_COLUMNS = [
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Flow Bytes/s",
    "Flow Packets/s",
]

DEFAULT_SOURCE_PORT_COLUMNS = [
    "Source Port",
    "Src Port",
    "src_port",
]

DEFAULT_DEST_PORT_COLUMNS = [
    "Destination Port",
    "Dst Port",
    "dst_port",
]

DEFAULT_PROTOCOL_COLUMNS = [
    "Protocol",
    "protocol",
]

DEFAULT_LABEL_COLUMNS = [
    "Label",
    "label",
    "Class",
    "class",
]


def _normalize_column_name(name: str) -> str:
    return " ".join(name.strip().lower().split())


def _find_column(candidates: list[str], columns: list[str]) -> str | None:
    lower_map = {_normalize_column_name(c): c for c in columns}
    for candidate in candidates:
        normalized = _normalize_column_name(candidate)
        if normalized in lower_map:
            return lower_map[normalized]
    return None


def load_cicids_folder(input_dir: Path, max_rows: int | None = None) -> pd.DataFrame:
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    # Search recursively because CICIDS2017 is often extracted into nested folders.
    csv_files = sorted(input_dir.rglob("*.csv"))
    parquet_files = sorted(input_dir.rglob("*.parquet"))

    # Prefer CSV when available, because many parquet mirrors are no-metadata variants.
    input_files = csv_files if csv_files else parquet_files
    if not input_files:
        raise FileNotFoundError(f"No CSV or Parquet files found in: {input_dir}")

    frames: list[pd.DataFrame] = []
    rows_left = max_rows

    for file_path in input_files:
        if rows_left is not None and rows_left <= 0:
            break

        if file_path.suffix.lower() == ".csv":
            if rows_left is None:
                frame = pd.read_csv(file_path, low_memory=False)
            else:
                frame = pd.read_csv(file_path, nrows=rows_left, low_memory=False)
        else:
            # Parquet does not support nrows during read; trim after loading.
            frame = pd.read_parquet(file_path)
            if rows_left is not None:
                frame = frame.head(rows_left)

        frames.append(frame)

        if rows_left is not None:
            rows_left -= len(frame)

    data = pd.concat(frames, ignore_index=True)
    return data


def standardize_flow_columns(df: pd.DataFrame) -> pd.DataFrame:
    src_col = _find_column(DEFAULT_SOURCE_COLUMNS, df.columns.tolist())
    dst_col = _find_column(DEFAULT_DEST_COLUMNS, df.columns.tolist())
    weight_col = _find_column(DEFAULT_WEIGHT_COLUMNS, df.columns.tolist())
    label_col = _find_column(DEFAULT_LABEL_COLUMNS, df.columns.tolist())

    # Additional columns for temporal and network analysis
    time_col = None
    for c in df.columns:
        if c.strip().lower() == "timestamp":
            time_col = c
            break
    protocol_col = _find_column(DEFAULT_PROTOCOL_COLUMNS, df.columns.tolist())
    src_port_col = _find_column(DEFAULT_SOURCE_PORT_COLUMNS, df.columns.tolist())
    dst_port_col = _find_column(DEFAULT_DEST_PORT_COLUMNS, df.columns.tolist())

    standardized = pd.DataFrame()

    if src_col is not None and dst_col is not None:
        standardized["src"] = df[src_col].astype(str)
        standardized["dst"] = df[dst_col].astype(str)
    else:
        raise ValueError(
            "Source/Destination IP columns not found. Check column names in your CSV."
        )

    if weight_col is None:
        standardized["weight"] = 1.0
    else:
        numeric_weight = pd.to_numeric(df[weight_col], errors="coerce")
        numeric_weight = numeric_weight.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        standardized["weight"] = numeric_weight.clip(lower=0)

    if label_col is not None:
        standardized["label"] = df[label_col].astype(str).str.strip()

    # Add time column if present
    if time_col is not None:
        standardized["timestamp"] = pd.to_datetime(df[time_col], errors="coerce")

    # Add protocol and ports if present
    if protocol_col is not None:
        standardized["protocol"] = df[protocol_col].astype(str)
    if src_port_col is not None:
        standardized["src_port"] = pd.to_numeric(df[src_port_col], errors="coerce")
    if dst_port_col is not None:
        standardized["dst_port"] = pd.to_numeric(df[dst_port_col], errors="coerce")

    # Add flow duration if present
    flow_duration_col = None
    for c in df.columns:
        if c.strip().lower() == "flow duration":
            flow_duration_col = c
            break
    if flow_duration_col is not None:
        standardized["flow_duration"] = pd.to_numeric(df[flow_duration_col], errors="coerce")

    # Add total packets/bytes if present
    for colname in ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets"]:
        if colname in df.columns:
            standardized[colname.strip().lower().replace(" ", "_")] = pd.to_numeric(df[colname], errors="coerce")

    return standardized[(standardized["src"] != "") & (standardized["dst"] != "")]


def build_node_majority_labels(flow_df: pd.DataFrame) -> pd.DataFrame:
    if "label" not in flow_df.columns:
        return pd.DataFrame(columns=["node", "majority_label", "is_malicious"])

    labeled = flow_df[["src", "label"]].copy()
    labeled = labeled[labeled["label"].str.len() > 0]
    if labeled.empty:
        return pd.DataFrame(columns=["node", "majority_label", "is_malicious"])

    src_labels = labeled[["src", "label"]].rename(columns={"src": "node"})
    node_labels = src_labels

    majority = (
        node_labels.groupby("node")["label"]
        .agg(lambda x: x.value_counts().index[0])
        .rename("majority_label")
        .reset_index()
    )

    lower_label = majority["majority_label"].str.lower().str.strip()
    majority["is_malicious"] = lower_label != "benign"
    return majority


def save_dataframe_pkl(df: pd.DataFrame, output_path: Path) -> None:
    """Save dataframe to pickle file"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'wb') as f:
        pickle.dump(df, f)
    print(f"✓ Saved dataframe to {output_path} ({output_path.stat().st_size / 1e6:.2f} MB)")


def load_dataframe_pkl(pkl_path: Path) -> pd.DataFrame:
    """Load dataframe from pickle file"""
    with open(pkl_path, 'rb') as f:
        df = pickle.load(f)
    print(f"✓ Loaded dataframe from {pkl_path} ({len(df)} rows)")
    return df


def save_graph_pkl(graph, output_path: Path) -> None:
    """Save NetworkX graph to pickle file"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'wb') as f:
        pickle.dump(graph, f)
    size_mb = output_path.stat().st_size / 1e6
    nodes = graph.number_of_nodes() if hasattr(graph, 'number_of_nodes') else 0
    edges = graph.number_of_edges() if hasattr(graph, 'number_of_edges') else 0
    print(f"✓ Saved graph to {output_path} ({nodes} nodes, {edges} edges, {size_mb:.2f} MB)")


def load_graph_pkl(pkl_path: Path):
    """Load NetworkX graph from pickle file"""
    with open(pkl_path, 'rb') as f:
        graph = pickle.load(f)
    nodes = graph.number_of_nodes() if hasattr(graph, 'number_of_nodes') else 0
    edges = graph.number_of_edges() if hasattr(graph, 'number_of_edges') else 0
    print(f"✓ Loaded graph from {pkl_path} ({nodes} nodes, {edges} edges)")
    return graph


if __name__ == "__main__":
    from graph_builder import build_weighted_graph
    
    print("=" * 70)
    print("STEP 1: LOAD FRIDAY DATA")
    print("=" * 70)
    
    data_dir = Path("data")
    flows = standardize_flow_columns(load_cicids_folder(data_dir))
    print(f"✓ Loaded {len(flows)} flows")
    
    labels = build_node_majority_labels(flows)
    print(f"✓ Built labels for {len(labels)} nodes")
    
    print("\n" + "=" * 70)
    print("BUILDING GRAPH")
    print("=" * 70)
    
    from graph_builder import build_weighted_graph
    graph = build_weighted_graph(flows)
    print(f"✓ Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    
    print("\n" + "=" * 70)
    print("SAVING TO PICKLE")
    print("=" * 70)
    
    save_dataframe_pkl(flows, Path("data/friday_flows.pkl"))
    save_dataframe_pkl(labels, Path("data/friday_labels.pkl"))
    save_graph_pkl(graph, Path("data/friday_graph.pkl"))
    
    print("\n" + "=" * 70)
    print("✓✓✓ DONE - Run: python main.py --input-dir data --output results/friday.csv")
    print("=" * 70)
