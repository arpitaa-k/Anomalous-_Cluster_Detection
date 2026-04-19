from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


INPUT_PATH = Path("results/changepoint_detection_results.csv")
OUTPUT_PATH = Path("results/changepoint_detection_plot.png")


def main() -> None:
    df = pd.read_csv(INPUT_PATH)
    df["window_start"] = pd.to_datetime(df["window_start"])

    plt.figure(figsize=(13, 7))
    plt.plot(df["window_start"], df["mean_oddball_score"], marker="o", label="Mean OddBall Score", color="blue")
    plt.plot(df["window_start"], df["max_oddball_score"], marker="s", label="Max OddBall Score", color="orange")
    plt.plot(
        df["window_start"],
        df["attacker_oddball_score"],
        marker="^",
        label="Attacker OddBall Score",
        color="red",
    )

    flagged = df[df["any_changepoint"]]
    for _, row in flagged.iterrows():
        plt.axvline(row["window_start"], color="black", linestyle="--", alpha=0.25)

    plt.xlabel("Time Window Start")
    plt.ylabel("Score")
    plt.title("Changepoint Detection Over Temporal OddBall Signals")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(OUTPUT_PATH)
    print(f"Saved plot to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
