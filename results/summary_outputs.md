# Anomaly Detection Pipeline Outputs

This file will collect the main terminal outputs and summaries from all detection scripts (OddBall, LOF, Isolation Forest, and their temporal variants).

---
## OddBall Static

✓ Saved OddBall scores to: results\static\oddball\scores.csv

Top 10 suspicious nodes:

| node          |   oddball_score | majority_label   | is_malicious   |
|:--------------|----------------:|:-----------------|:---------------|
| 192.168.10.15 |        0.633573 | BENIGN           | False          |
| 192.168.10.5  |        0.596907 | BENIGN           | False          |
| 192.168.10.9  |        0.584639 | BENIGN           | False          |
| 192.168.10.14 |        0.548077 | BENIGN           | False          |
| 172.16.0.1    |        0.507483 | DDoS             | True           |
| 192.168.10.8  |        0.499561 | BENIGN           | False          |
| 192.168.10.50 |        0.487474 | BENIGN           | False          |
| 192.168.10.16 |        0.378966 | BENIGN           | False          |
| 192.168.10.17 |        0.277749 | BENIGN           | False          |
| 192.168.10.12 |        0.26435  | BENIGN           | False          |

---
## LOF Static

✓ Saved LOF scores to: results\static\lof\scores.csv

Top 10 suspicious nodes:

| node            |   lof_score | majority_label   |   is_malicious |
|:----------------|------------:|:-----------------|---------------:|
| 23.194.101.148  |    1        | BENIGN           |              0 |
| 54.235.219.125  |    0.93057  | BENIGN           |              0 |
| 210.160.193.168 |    0.93057  | BENIGN           |              0 |
| 156.154.200.36  |    0.791254 | BENIGN           |              0 |
| 52.71.196.79    |    0.776384 | BENIGN           |              0 |
| 52.84.26.218    |    0.622369 | BENIGN           |              0 |
| 91.189.89.198   |    0.613128 | nan              |            nan |
| 198.50.139.209  |    0.613128 | nan              |            nan |
| 104.196.26.242  |    0.588138 | BENIGN           |              0 |
| 35.185.44.103   |    0.588138 | BENIGN           |              0 |

---
## Isolation Forest Static

✓ Saved Isolation Forest scores to: results\static\isolation_forest\scores.csv

Top 10 suspicious nodes:

| node          |   isolation_forest_score |
|:--------------|-------------------------:|
| 192.168.10.15 |                 1        |
| 192.168.10.5  |                 0.995949 |
| 192.168.10.9  |                 0.991019 |
| 192.168.10.14 |                 0.985003 |
| 192.168.10.16 |                 0.974837 |
| 192.168.10.8  |                 0.960218 |
| 192.168.10.17 |                 0.956975 |
| 192.168.10.12 |                 0.952239 |
| 192.168.10.50 |                 0.938381 |
| 192.168.10.19 |                 0.938337 |

---
## OddBall Temporal

✓ Saved all temporal OddBall scores to: results\temporal\oddball\scores.csv

Top 5 suspicious nodes by max OddBall score:

node
192.168.10.15    0.698549
192.168.10.5     0.621744
192.168.10.9     0.618387
192.168.10.16    0.598020
192.168.10.12    0.577229

---
## OddBall Temporal

✓ Saved all temporal OddBall scores to: results\temporal\oddball\scores.csv

Top 5 suspicious nodes by max OddBall score:

node
192.168.10.15    0.698549
192.168.10.5     0.621744
192.168.10.9     0.618387
192.168.10.16    0.598020
192.168.10.12    0.577229

---
## OddBall Temporal

✓ Saved all temporal OddBall scores to: results\temporal\oddball\scores.csv

Top 5 suspicious nodes by max OddBall score:

node
192.168.10.15    0.698549
192.168.10.5     0.621744
192.168.10.9     0.618387
192.168.10.16    0.598020
192.168.10.12    0.577229

---
## LOF Temporal

✓ Saved temporal LOF scores to: results\temporal\lof\scores.csv

Top 5 suspicious nodes by max LOF score:

node
99.224.25.39       1.0
207.210.46.249     1.0
144.217.164.10     1.0
144.217.240.204    1.0
54.69.227.52       1.0

---
## Isolation Forest Temporal

✓ Saved temporal Isolation Forest scores to: results\temporal\isolation_forest\scores.csv

Top 5 suspicious nodes by max Isolation Forest score:

node
192.168.10.16    1.000000
192.168.10.15    1.000000
192.168.10.12    1.000000
192.168.10.5     1.000000
192.168.10.9     0.985225

---
## OddBall+Volume Temporal

✓ Saved all temporal OddBall+Volume scores to: results\temporal\oddball_volume\scores.csv

Top 5 suspicious nodes by max combined score:

node
192.168.10.9     0.904597
192.168.10.5     0.902303
192.168.10.15    0.902152
192.168.10.25    0.763632
192.168.10.16    0.745314

---
