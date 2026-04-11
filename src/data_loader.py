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
    "Flow Bytes/s",
    "Total Length of Fwd Packets",
    "Flow Packets/s",
    "Total Fwd Packets",
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
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {input_dir}")

    frames: list[pd.DataFrame] = []
    rows_left = max_rows

    for file_path in csv_files:
        if rows_left is not None and rows_left <= 0:
            break

        if rows_left is None:
            frame = pd.read_csv(file_path, low_memory=False)
        else:
            frame = pd.read_csv(file_path, nrows=rows_left, low_memory=False)

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
        # Some CICIDS2017 variants remove IP fields. Fall back to a port-based graph.
        src_port_col = _find_column(DEFAULT_SOURCE_PORT_COLUMNS, df.columns.tolist())
        dst_port_col = _find_column(DEFAULT_DEST_PORT_COLUMNS, df.columns.tolist())
        protocol_col = _find_column(DEFAULT_PROTOCOL_COLUMNS, df.columns.tolist())

        if dst_port_col is None:
            raise ValueError(
                "Could not find source/destination IP columns, and no destination port column was found either"
            )

        dst_port = df[dst_port_col].astype(str).str.strip()

        if src_port_col is not None:
            src_port = df[src_port_col].astype(str).str.strip()
            if protocol_col is not None:
                proto = df[protocol_col].astype(str).str.strip()
                standardized["src"] = "proto:" + proto + "|sport:" + src_port
                standardized["dst"] = "proto:" + proto + "|dport:" + dst_port
            else:
                standardized["src"] = "sport:" + src_port
                standardized["dst"] = "dport:" + dst_port
        else:
            row_ids = df.index.to_series().astype(str)
            standardized["src"] = "flow:" + row_ids
            if protocol_col is not None:
                proto = df[protocol_col].astype(str).str.strip()
                standardized["dst"] = "proto:" + proto + "|dport:" + dst_port
            else:
                standardized["dst"] = "dport:" + dst_port

    if weight_col is None:
        standardized["weight"] = 1.0
    else:
        numeric_weight = pd.to_numeric(df[weight_col], errors="coerce")
        numeric_weight = numeric_weight.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        standardized["weight"] = numeric_weight

    return standardized[(standardized["src"] != "") & (standardized["dst"] != "")]
