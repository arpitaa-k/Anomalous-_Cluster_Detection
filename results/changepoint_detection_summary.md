# Changepoint Detection Summary

This detector uses a robust mean-shift style changepoint score over per-window OddBall statistics.

## Signals
- Windows analyzed: 10
- Windows flagged as changepoints: 6
- Strongest mean-score change: 2017-07-07 03:40:00
- Strongest max-score change: 2017-07-07 04:30:00
- Strongest attacker-score change: 2017-07-07 04:20:00

## Flagged Windows
- 2017-07-07 03:50:00: mean_change=0.565, max_change=0.817, attacker_change=7.688
- 2017-07-07 04:00:00: mean_change=0.165, max_change=1.916, attacker_change=3.457
- 2017-07-07 04:10:00: mean_change=0.529, max_change=0.715, attacker_change=7.609
- 2017-07-07 04:20:00: mean_change=1.260, max_change=0.270, attacker_change=8.716
- 2017-07-07 04:30:00: mean_change=1.380, max_change=3.185, attacker_change=0.103
- 2017-07-07 04:40:00: mean_change=0.042, max_change=3.091, attacker_change=0.222