from dataclasses import dataclass
from pathlib import Path


@dataclass
class PipelineConfig:
    input_dir: Path
    output_file: Path
    max_rows: int | None = None
    alpha: float = 0.01
    z_threshold: float = 3.0
    rolling_window: int = 200
    threshold_sigma: float = 2.5
