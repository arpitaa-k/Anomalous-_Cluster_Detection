# Results Folder

- The pipeline now generates these local artifacts automatically after each run:
	- output anomaly table (for example `anomalies_wed_quick.csv`)
	- `top_50_anomalies.csv`
	- `plot_score_distribution.png`
	- `plot_top_20_anomalies.png`
	- `plot_score_by_label.png` (only when labels are available)
	- `assignment_summary.md`

- Large CSV/PNG outputs are excluded by `.gitignore` because they can be large.

To regenerate sample from full output:

```powershell
python -c "import pandas as pd; df=pd.read_csv('results/anomalies.csv'); df.head(50).to_csv('results/anomalies_top50_sample.csv', index=False)"
```
