from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


RESULTS_DIR = Path("results/final")
ATTACKER_NODE = "172.16.0.1"

STATIC_SOURCES = {
    "OddBall": (Path("results/static/oddball/scores.csv"), "oddball_score"),
    "LOF": (Path("results/static/lof/scores.csv"), "lof_score"),
    "IsolationForest": (Path("results/static/isolation_forest/scores.csv"), "isolation_forest_score"),
}

TEMPORAL_SOURCES = {
    "OddBall": (Path("results/temporal/oddball/scores.csv"), "oddball_score"),
    "LOF": (Path("results/temporal/lof/scores.csv"), "lof_score"),
    "IsolationForest": (Path("results/temporal/isolation_forest/scores.csv"), "isolation_forest_score"),
}


def load_static_ranks() -> tuple[pd.DataFrame, pd.DataFrame]:
    rank_frames: list[pd.DataFrame] = []
    label_frame: pd.DataFrame | None = None

    for algo_name, (path, score_col) in STATIC_SOURCES.items():
        df = pd.read_csv(path)
        df["node"] = df["node"].astype(str)
        df[f"{algo_name}_rank"] = df[score_col].rank(method="min", ascending=False)
        rank_frames.append(df[["node", f"{algo_name}_rank"]].copy())

        if label_frame is None and {"majority_label", "is_malicious"}.issubset(df.columns):
            label_frame = df[["node", "majority_label", "is_malicious"]].copy()

    merged = rank_frames[0]
    for frame in rank_frames[1:]:
        merged = merged.merge(frame, on="node", how="outer")

    rank_cols = [col for col in merged.columns if col.endswith("_rank")]
    merged[rank_cols] = merged[rank_cols].fillna(len(merged) + 1)
    merged["static_avg_rank"] = merged[rank_cols].mean(axis=1)

    if label_frame is None:
        label_frame = pd.DataFrame(
            {
                "node": merged["node"],
                "majority_label": pd.NA,
                "is_malicious": pd.NA,
            }
        )

    return merged, label_frame


def load_temporal_consistency() -> tuple[pd.DataFrame, list[pd.Timestamp], pd.DataFrame]:
    top_hits: list[pd.DataFrame] = []
    temporal_scores: list[pd.DataFrame] = []
    all_windows: list[pd.Timestamp] = []

    for algo_name, (path, score_col) in TEMPORAL_SOURCES.items():
        df = pd.read_csv(path)
        df["node"] = df["node"].astype(str)
        df["window_start"] = pd.to_datetime(df["window_start"])
        all_windows.extend(df["window_start"].drop_duplicates().tolist())

        top20 = (
            df.sort_values(["window_start", score_col], ascending=[True, False])
            .groupby("window_start", group_keys=False)
            .head(20)[["node", "window_start"]]
            .copy()
        )
        top20["hit"] = 1
        top_hits.append(top20)

        score_frame = df[["node", "window_start", score_col]].copy().rename(columns={score_col: algo_name})
        temporal_scores.append(score_frame)

    hits = pd.concat(top_hits, ignore_index=True)
    consistency = hits.groupby("node", as_index=False)["hit"].sum().rename(columns={"hit": "top20_hits"})
    max_possible = len(TEMPORAL_SOURCES) * len(pd.Index(all_windows).unique())
    consistency["consistency_score"] = consistency["top20_hits"] / max_possible

    merged_scores = temporal_scores[0]
    for frame in temporal_scores[1:]:
        merged_scores = merged_scores.merge(frame, on=["node", "window_start"], how="outer")

    score_cols = list(TEMPORAL_SOURCES.keys())
    merged_scores[score_cols] = merged_scores[score_cols].fillna(0.0)
    merged_scores["avg_temporal_score"] = merged_scores[score_cols].mean(axis=1)

    window_order = sorted(pd.Index(all_windows).unique())
    return consistency, window_order, merged_scores


def save_top20_plot(final_df: pd.DataFrame) -> None:
    top20 = final_df.head(20).copy().iloc[::-1]
    colors = ["red" if value is True else "blue" for value in top20["is_malicious"].tolist()]

    plt.figure(figsize=(12, 8))
    plt.barh(top20["node"], top20["final_score"], color=colors)
    plt.xlabel("Final Score")
    plt.ylabel("Node")
    plt.title("Top 20 Nodes by Final Suspicion Score")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "final_ranking_top20.png")
    plt.close()


def save_scatter_plot(final_df: pd.DataFrame) -> None:
    plot_df = final_df.copy()
    plot_df["inverse_static_rank"] = 1.0 / plot_df["static_avg_rank"]

    plt.figure(figsize=(14, 10))
    normal = plot_df["node"] != ATTACKER_NODE
    plt.scatter(
        plot_df.loc[normal, "consistency_score"],
        plot_df.loc[normal, "inverse_static_rank"],
        color="steelblue",
        alpha=0.7,
        s=35,
    )

    attacker = plot_df[plot_df["node"] == ATTACKER_NODE]
    if not attacker.empty:
        plt.scatter(
            attacker["consistency_score"],
            attacker["inverse_static_rank"],
            color="red",
            s=100,
            label=f"Attacker {ATTACKER_NODE}",
            zorder=3,
        )

    for _, row in plot_df.iterrows():
        color = "red" if row["node"] == ATTACKER_NODE else "black"
        plt.annotate(
            row["node"],
            (row["consistency_score"], row["inverse_static_rank"]),
            xytext=(3, 3),
            textcoords="offset points",
            fontsize=6,
            color=color,
            alpha=0.85,
        )

    plt.xlabel("Consistency Score")
    plt.ylabel("1 / Static Average Rank")
    plt.title("Consistency vs Static Suspicion Strength")
    if not attacker.empty:
        plt.legend()
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "consistency_vs_static.png")
    plt.close()


def save_heatmap(final_df: pd.DataFrame, window_order: list[pd.Timestamp], temporal_scores: pd.DataFrame) -> None:
    top_nodes = final_df.head(20)["node"].tolist()
    heatmap_df = (
        temporal_scores[temporal_scores["node"].isin(top_nodes)][["node", "window_start", "avg_temporal_score"]]
        .pivot(index="node", columns="window_start", values="avg_temporal_score")
        .reindex(index=top_nodes, columns=window_order)
        .fillna(0.0)
    )

    plt.figure(figsize=(14, 8))
    image = plt.imshow(heatmap_df.to_numpy(), aspect="auto", cmap="YlOrRd")
    plt.colorbar(image, fraction=0.046, pad=0.04, label="Average Temporal Score")
    plt.yticks(range(len(heatmap_df.index)), heatmap_df.index)
    plt.xticks(
        range(len(heatmap_df.columns)),
        [pd.Timestamp(col).strftime("%H:%M") for col in heatmap_df.columns],
        rotation=45,
        ha="right",
    )
    plt.xlabel("Time Window")
    plt.ylabel("Top 20 Nodes")
    plt.title("Temporal Heatmap for Final Top 20 Nodes")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "temporal_heatmap.png")
    plt.close()


def main() -> None:
    static_ranks, labels = load_static_ranks()
    consistency, window_order, temporal_scores = load_temporal_consistency()

    final_df = static_ranks.merge(consistency[["node", "consistency_score"]], on="node", how="left")
    final_df = final_df.merge(labels, on="node", how="left")
    final_df["consistency_score"] = final_df["consistency_score"].fillna(0.0)
    final_df["final_score"] = 0.5 * (1.0 / final_df["static_avg_rank"]) + 0.5 * final_df["consistency_score"]
    final_df = final_df.sort_values(["final_score", "static_avg_rank"], ascending=[False, True]).reset_index(drop=True)
    final_df["final_rank"] = np.arange(1, len(final_df) + 1)

    output_cols = [
        "final_rank",
        "node",
        "final_score",
        "static_avg_rank",
        "consistency_score",
        "majority_label",
        "is_malicious",
    ]
    final_df[output_cols].to_csv(RESULTS_DIR / "final_ranked_nodes.csv", index=False)

    save_top20_plot(final_df)
    save_scatter_plot(final_df)
    save_heatmap(final_df, window_order, temporal_scores)

    print("Top 20 final ranked nodes:")
    print(final_df[output_cols].head(20).to_string(index=False))

    attacker = final_df[final_df["node"] == ATTACKER_NODE]
    if attacker.empty:
        print(f"\nNode {ATTACKER_NODE} was not found in final ranking.")
    else:
        row = attacker.iloc[0]
        print(
            f"\nNode {ATTACKER_NODE} rank: {int(row['final_rank'])} "
            f"with final_score={row['final_score']:.6f}, "
            f"static_avg_rank={row['static_avg_rank']:.3f}, "
            f"consistency_score={row['consistency_score']:.3f}"
        )


if __name__ == "__main__":
    main()
