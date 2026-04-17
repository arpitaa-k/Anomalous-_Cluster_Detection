# Assignment Results Summary

## Run Overview
- Input output file: anomalies_wed_100k.csv
- Total processed nodes: 3872
- Adaptive anomalies: 194
- Group-level hypothesis pass: False

## Statistical Evaluation
- evaluated_nodes: 1963
- malicious_nodes: 1
- benign_nodes: 1962
- false_positive_count: 149
- false_positive_rate: 0.0759429
- roc_auc: 0.995923
- mann_whitney_p: 0.0861279
- t_test_p: nan
- cohens_d: 12.2715

### Per-Attack AUC Breakdown
- DoS Hulk: 0.995923

## Generated Artifacts
- Top 50 anomaly table: top_50_anomalies.csv
- Score distribution plot: plot_score_distribution.png
- Top 20 anomaly plot: plot_top_20_anomalies.png
- Label-wise score plot: plot_score_by_label.png

## Interpretation Notes
- High oddball_score indicates stronger deviation from expected graph behavior.
- is_anomaly is based on adaptive thresholding over score distribution.
- The per-node z-test was removed; significance is evaluated at the group level.
- False positive rate is reported explicitly when benign labels are available.
- Per-attack AUC highlights which attack families are easiest or hardest to detect.
- For robust conclusions, prefer larger runs (100k rows or full-day files).