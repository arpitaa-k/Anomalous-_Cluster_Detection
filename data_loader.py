from pathlib import Path

import pandas as pd
import numpy as np


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

    label_col = _find_column(DEFAULT_LABEL_COLUMNS, df.columns.tolist())
    if label_col is not None:
        standardized["label"] = df[label_col].astype(str).str.strip()

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
