#!/usr/bin/env python3
import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


def mean_std(values):
    if not values:
        return None, None

    if len(values) == 1:
        return statistics.mean(values), 0.0

    return statistics.mean(values), statistics.stdev(values)


def load_rows(path):
    rows = []

    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("status") != "ok":
                continue

            try:
                row["files"] = int(row["files"])
                row["runtime_s"] = float(row["runtime_s"])
                row["precision"] = float(row["precision"])
                row["recall"] = float(row["recall"])
                row["f1"] = float(row["f1"])
            except Exception:
                continue

            rows.append(row)

    return rows


def summarize(rows):
    grouped = defaultdict(list)

    for row in rows:
        grouped[(row["tool"], row["case"], row["files"])].append(row)

    summary_rows = []

    for (tool, case, files), items in sorted(grouped.items(), key=lambda x: (x[0][0], x[0][2])):
        item = {
            "tool": tool,
            "case": case,
            "files": files,
            "runs": len(items),
        }

        for metric in ("runtime_s", "precision", "recall", "f1"):
            mean, std = mean_std([x[metric] for x in items])
            item[f"{metric}_mean"] = mean
            item[f"{metric}_std"] = std

        summary_rows.append(item)

    return summary_rows


def write_summary_csv(summary_rows, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "tool",
        "case",
        "files",
        "runs",
        "runtime_s_mean",
        "runtime_s_std",
        "precision_mean",
        "precision_std",
        "recall_mean",
        "recall_std",
        "f1_mean",
        "f1_std",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in summary_rows:
            writer.writerow(row)


def plot_metric(summary_rows, metric, ylabel, output_path):
    by_tool = defaultdict(list)

    for row in summary_rows:
        by_tool[row["tool"]].append(row)

    plt.figure()

    for tool, items in sorted(by_tool.items()):
        items = sorted(items, key=lambda x: x["files"])

        xs = [x["files"] for x in items]
        ys = [x[f"{metric}_mean"] for x in items]
        es = [x[f"{metric}_std"] for x in items]

        plt.errorbar(
            xs,
            ys,
            yerr=es,
            marker="o",
            capsize=4,
            label=tool,
        )

    plt.xlabel("Number of files")
    plt.ylabel(ylabel)
    plt.title(f"{ylabel} by scale")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--out-dir", required=True)

    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_rows(args.csv)
    summary_rows = summarize(rows)

    write_summary_csv(
        summary_rows,
        out_dir / "summary_by_scale.csv",
    )

    plot_metric(
        summary_rows,
        "runtime_s",
        "Runtime (seconds)",
        out_dir / "runtime_by_scale.png",
    )

    plot_metric(
        summary_rows,
        "precision",
        "Precision",
        out_dir / "precision_by_scale.png",
    )

    plot_metric(
        summary_rows,
        "recall",
        "Recall",
        out_dir / "recall_by_scale.png",
    )

    plot_metric(
        summary_rows,
        "f1",
        "F1-score",
        out_dir / "f1_by_scale.png",
    )

    print(f"[OK] Summary written to: {out_dir / 'summary_by_scale.csv'}")
    print(f"[OK] Plots written to: {out_dir}")


if __name__ == "__main__":
    main()
