param(
    [string]$InputDir = "data/cicids2017",
    [string]$Output = "results/anomalies.csv",
    [int]$MaxRows = 0
)

$maxArg = ""
if ($MaxRows -gt 0) {
    $maxArg = "--max-rows $MaxRows"
}

python -m src.main --input-dir $InputDir --output $Output $maxArg
