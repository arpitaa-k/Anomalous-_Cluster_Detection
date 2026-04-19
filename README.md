# Anomalous Cluster Detection

This repository contains scripts and utilities for detecting anomalous clusters and nodes in network flow data using various graph-based and machine learning methods. The workflow is modular, with clear separation between static and temporal analysis, and all results are organized for easy review.

## Directory Structure

```
.
├── changepoint_detector.py
├── config.py
├── coordination_detector.py
├── data_loader.py
├── final_ranking.py
├── friday_eda.ipynb
├── graph_builder.py
├── isolation_forest.py
├── isolation_forest_temporal.py
├── LOF.py
├── LOF_temporal.py
├── main.py
├── oddball.py
├── oddball_temporal.py
├── oddball_temporal_volume.py
├── reporting.py
├── requirements.txt
├── stats.py
├── thresholding.py
├── data/
│   └── DDoS-Friday-WorkingHours-Afternoon.pcap_ISCX.csv
├── results/
│   ├── summary_outputs.md
│   ├── final/
│   │   └── [final ranking outputs]
│   ├── static/
│   │   ├── oddball/scores.csv
│   │   ├── lof/scores.csv
│   │   └── isolation_forest/scores.csv
│   └── temporal/
│       ├── oddball/scores.csv
│       ├── lof/scores.csv
│       └── isolation_forest/scores.csv
```

## File Descriptions

### Main Detection Scripts
- **oddball.py**: Static OddBall anomaly detection on the full graph. Saves scores and a plot of top suspicious nodes.
- **LOF.py**: Static Local Outlier Factor (LOF) anomaly detection. Saves scores and a plot of top nodes.
- **isolation_forest.py**: Static Isolation Forest anomaly detection. Saves scores and a plot of top nodes.
- **oddball_temporal.py**: Temporal OddBall detection over time windows. Saves time series scores and a plot (attacker highlighted in gold).
- **LOF_temporal.py**: Temporal LOF detection over time windows. Uses features from OddBall temporal output. Saves time series scores and a plot.
- **isolation_forest_temporal.py**: Temporal Isolation Forest detection over time windows. Saves time series scores and a plot.
- **oddball_temporal_volume.py**: Combines OddBall and flow volume for temporal anomaly detection. Saves combined scores and a plot.

### Coordination and Change Point Detection
- **changepoint_detector.py**: Detects change points in temporal OddBall scores. Uses results/temporal/oddball/scores.csv as input.
- **coordination_detector.py**: Detects coordinated anomalous behavior using temporal OddBall scores.

### Utilities and Support
- **data_loader.py**: Functions for loading and preprocessing data and graphs.
- **config.py**: Configuration settings for the project.
- **graph_builder.py**: Utilities for building graphs from flow data.
- **reporting.py**: Functions for generating reports and summaries.
- **stats.py**: Statistical utilities.
- **thresholding.py**: Thresholding utilities for anomaly scores.
- **main.py**: (Optional) Entry point for running the full pipeline.

### Analysis and Output
- **final_ranking.py**: Aggregates static and temporal results, computes a final ranking, and saves outputs/plots in results/final/.
- **friday_eda.ipynb**: Exploratory data analysis notebook for the Friday dataset.

### Results and Data
- **data/**: Contains raw and preprocessed data files.
- **results/**: All outputs, plots, and summaries are saved here.
    - **summary_outputs.md**: Aggregated summary of all main outputs.
    - **final/**: Final ranking CSV and plots.
    - **static/**: Static detection results for each method.
    - **temporal/**: Temporal detection results for each method.

### Requirements
- **requirements.txt**: Python dependencies for the project.

---

For step-by-step usage and running instructions, see the top of summary_outputs.md or ask for a quickstart guide!
