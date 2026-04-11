# Results Folder

- `anomalies_top50_sample.csv` contains a 50-row sample for GitHub preview.
- Full result files (for example `anomalies.csv`) are excluded by `.gitignore` because they can be large.

To regenerate sample from full output:

```powershell
python -c "import pandas as pd; df=pd.read_csv('results/anomalies.csv'); df.head(50).to_csv('results/anomalies_top50_sample.csv', index=False)"
```
