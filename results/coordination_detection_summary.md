# Coordination Detection Summary

This detector applies spectral clustering to node score trajectories from OddBall temporal outputs.

- Nodes clustered: 30
- Clusters formed: 4

## Cluster Summary
- Cluster 2: size=8, avg_max_score=0.3155, attacker_nodes=1, sample_members=['192.168.10.14', '172.217.11.46', '192.168.10.50', '23.208.165.24', '23.52.155.27', '23.208.94.86', '192.168.10.25', '172.16.0.1']
- Cluster 0: size=5, avg_max_score=0.6117, attacker_nodes=0, sample_members=['192.168.10.15', '192.168.10.5', '192.168.10.9', '192.168.10.16', '192.168.10.17']
- Cluster 3: size=8, avg_max_score=0.3941, attacker_nodes=0, sample_members=['192.168.10.12', '192.168.10.8', '192.168.10.19', '172.217.10.142', '192.168.10.255', '192.168.10.3', '23.54.187.27', '68.67.178.243']
- Cluster 1: size=9, avg_max_score=0.2844, attacker_nodes=0, sample_members=['192.95.33.215', '153.149.96.48', '104.97.128.248', '52.208.59.61', '158.255.65.22', '198.41.214.184', '195.248.250.109', '52.51.222.188']

## Attacker Placement
- Attacker node 172.16.0.1 is assigned to cluster 2.
- Cluster 2 members: ['192.168.10.14', '172.217.11.46', '192.168.10.50', '23.208.165.24', '23.52.155.27', '23.208.94.86', '192.168.10.25', '172.16.0.1']