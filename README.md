# Anomalous Cluster Detection in Network Traffic

This repository contains a starter implementation of:
1. OddBall-inspired graph anomaly scoring on CICIDS2017 traffic.
2. Z-test based statistical validation for suspicious nodes.
3. Adaptive thresholding to reduce false alarms under changing traffic volume.

## Project Structure
- `src/main.py`: Pipeline entry point.
- `src/data_loader.py`: Dataset loading and schema handling.
- `src/graph_builder.py`: Flow-to-graph conversion.
- `src/oddball.py`: OddBall-inspired feature extraction and outlier scoring.
- `src/stats.py`: Z-test validation.
- `src/thresholding.py`: Adaptive thresholding on score streams.
- `docs/proposal.md`: Proposal text in repository form.
- `data/`: Place CICIDS2017 CSV files here.
- `results/`: Generated outputs (anomaly tables and optional plots).

## Quick Start
1. Create a virtual environment and install dependencies:
   - Windows PowerShell:
     - `python -m venv .venv`
     - `.venv\Scripts\Activate.ps1`
     - `pip install -r requirements.txt`

2. Put CICIDS2017 CSV files under `data/cicids2017`.

3. Run the pipeline:
   - `python -m src.main --input-dir data/cicids2017 --output results/anomalies.csv`

## Expected Output
The output CSV includes node-level metrics such as:
- graph features (degree, edge weight, neighborhood metrics)
- oddball score and z-score
- p-value
- adaptive flag (`is_anomaly`)

## Next Work
- Tune feature engineering for specific attack families.
- Add labels from CICIDS2017 to compute precision/recall.
- Add temporal graph snapshots for time-aware anomaly detection.
