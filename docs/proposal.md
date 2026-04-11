# Anomalous Cluster Detection in Network Traffic using OddBall and Hypothesis Testing

## Abstract
This project detects network anomalies using the OddBall algorithm on the CICIDS2017 dataset. Traffic is modeled as a graph to find suspicious patterns, such as stars and cliques. Statistical tests (Z-tests) validate flagged anomalies, and adaptive thresholding reduces false alarms by adjusting sensitivity to real-time traffic changes.

Keywords: Network Security, OddBall, Anomaly Detection, Hypothesis Testing

## 1. Introduction
Standard security tools often miss novel cyber-attacks. Graph-based detection is useful because it captures interaction structure among devices. This project uses the OddBall algorithm to identify unusual graph behavior and adaptive thresholding to maintain accuracy during both high and low traffic periods.

## 2. Related Work
Many intrusion detection systems rely on fixed thresholds, which can increase false positives. While OddBall is known for fraud and social graph analysis, it is less explored in network intrusion datasets. This work adds statistical validation to improve reliability.

## 3. Methodology
- Graph analysis: Detect node-level structural irregularities (for example, star-like communication hubs).
- Statistical testing: Apply Z-tests to distinguish true anomalies from random fluctuations.
- Adaptive thresholding: Dynamically shift decision thresholds based on rolling score distributions.

## 4. Implementation Details
- Dataset: CICIDS2017 with multiple attack families (for example, DDoS and Brute Force).
- Tools: NetworkX for graph modeling, Pandas for data handling, SciPy for hypothesis testing.
- Compute: Designed to run on CPU first; can be extended to GPU-enabled graph/data libraries for scale.

## 5. Timeline
1. Week 1: Dataset exploration and literature review.
2. Week 2: Build network graph from traffic flows.
3. Week 3: Run OddBall-inspired outlier scoring.
4. Week 4: Validate with statistical testing, adaptive thresholding, and final evaluation.

## References
1. Leman Akoglu, Mary McGlohon, and Christos Faloutsos. 2010. OddBall: Spotting Anomalies in Weighted Graphs. Pacific-Asia Conference on Knowledge Discovery and Data Mining (PAKDD).
2. Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani. 2018. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. International Conference on Information Systems Security and Privacy (ICISSP).
