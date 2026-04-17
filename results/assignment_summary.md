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
- roc_auc: 0.995923
- mann_whitney_p: 0.0861279
- t_test_p: nan
- cohens_d: 12.2715

### Per-Attack Metrics
- DoS_Hulk_auc: 0.995923
- DoS_Hulk_mann_whitney_p: 0.0861279
- roc_auc: 0.995923

### Flow-Level Evaluation
- flow_evaluated_flows: 100000
- flow_malicious_flows: 35659
- flow_benign_flows: 64341
- flow_roc_auc: 0.576833
- flow_mann_whitney_p: 0
- flow_t_test_p: 0
- flow_cohens_d: 0.230337

### Flow Per-Attack Metrics
- flow_DoS_Hulk_auc: 0.576833
- flow_DoS_Hulk_mann_whitney_p: 1.88741e-281
- flow_DoS_Slowhttptest_auc: 0.576833
- flow_DoS_Slowhttptest_mann_whitney_p: 6.56503e-81
- flow_DoS_slowloris_auc: 0.576833
- flow_DoS_slowloris_mann_whitney_p: 8.07645e-85
- flow_mann_whitney_p: 0
- flow_roc_auc: 0.576833

## Generated Artifacts
- Top 50 anomaly table: top_50_anomalies.csv
- Score distribution plot: plot_score_distribution.png
- Degree/weight plot: plot_degree_vs_weight.png
- Top 20 anomaly plot: plot_top_20_anomalies.png
- Label-wise score plot: plot_score_by_label.png
- Attack-type boxplot: plot_score_by_attack_type.png
- Flow-label boxplot: plot_score_by_flow_label.png
- Score correlation heatmap: plot_score_correlation.png
- Top anomaly ego-network: plot_top_egonet.png

## Interpretation Notes
- High oddball_score indicates stronger deviation from expected graph behavior.
- is_anomaly is based on adaptive thresholding over score distribution.
- The per-node z-test was removed; significance is evaluated at the group level.
- Degree/weight, correlation, and ego-network plots help explain the graph structure behind anomalies.
- For robust conclusions, prefer larger runs (100k rows or full-day files).