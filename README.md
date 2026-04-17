# Anomalous Cluster Detection in Network Traffic

Dataset - https://www.kaggle.com/datasets/dhoogla/cicids2017/versions/1?select=DoS-Wednesday-WorkingHours.pcap_ISCX.csv


This repository contains a starter implementation of:
1. OddBall-inspired graph anomaly scoring on CICIDS2017 traffic.
2. Additional unsupervised detectors (LOF and graph deviance) for robust scoring.
3. Z-test based statistical validation for suspicious nodes.
4. Adaptive thresholding to reduce false alarms under changing traffic volume.
5. Optional label-aware evaluation (ROC-AUC, Mann-Whitney U, t-test, Cohen's d).

## Project Structure
- `main.py`: Pipeline entry point.
- `data_loader.py`: Dataset loading and schema handling.
- `graph_builder.py`: Flow-to-graph conversion.
- `oddball.py`: OddBall-inspired feature extraction and outlier scoring.
- `stats.py`: Statistical validation and evaluation.
- `thresholding.py`: Adaptive thresholding on score streams.
- `data/`: Place CICIDS2017 CSV or Parquet files here.
- `results/`: Generated outputs (anomaly tables and optional plots).

## Quick Start
1. Create a virtual environment and install dependencies:
   - Windows PowerShell:
     - `python -m venv .venv`
     - `.venv\Scripts\Activate.ps1`
     - `pip install -r requirements.txt`

2. Put CICIDS2017 CSV/Parquet files under `data` or a subfolder.

3. Run the pipeline:
   - `python main.py --input-dir data --output results/anomalies.csv`

   - Optional Monday baseline run for null statistics:
     - `python main.py --input-dir "data/day-wise csv" --baseline-input-dir "data/monday csv" --output results/anomalies_wed_baseline.csv --max-rows 100000`

## Expected Output
The output CSV includes node-level metrics such as:
- graph/egonet features (`N_i`, `E_i`, `W_i`, `lambda_w`)
- detector scores (OddBall pair scores, LOF, graph deviance)
- combined anomaly score (`oddball_score`) and z-score
- p-value
- adaptive flag (`is_anomaly`)
- optional node labels and statistical evaluation fields when labels are available
- explicit false-positive rate and per-attack AUC breakdown when label data exists

## Next Work
- Tune feature engineering for specific attack families.
- Add a Monday benign-only baseline directory for stronger null hypothesis testing.
- Add temporal graph snapshots for time-aware anomaly detection.

## Additional Work
Your proposal's goal is anomaly detection on CICIDS2017. CICIDS2017 has multiple attack types by design. Showing that OddBall detects DDoS well (star pattern = high out-degree = exactly what OddBall looks for) but struggles with Infiltration (low footprint, looks like normal traffic) is a direct, meaningful finding about your own method — not a detour.
It also directly justifies why you used a graph-based approach in the first place. The proposal argues graph structure reveals attack patterns. Showing which patterns get caught and which don't is the proof of that claim.
It's ~15 lines of code, takes no extra data, and makes your results section significantly stronger than the reference project.
Add one line to your proposal methodology — something like: "We additionally evaluate detection performance per attack category to assess which structural patterns OddBall captures most effectively." That's enough to make it consistent with your proposal.


Multi attack is for - Graph-based anomaly detection across multiple CICIDS2017 attack families
And if we keep single day then - “Graph-based anomaly detection on CICIDS2017 traffic”
not “multi-attack detection across CICIDS2017”
