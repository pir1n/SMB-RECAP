#!/usr/bin/env python3
import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

plt = None


def require_matplotlib():
    global plt
    if plt is not None:
        return
    try:
        import matplotlib.pyplot as pyplot
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "matplotlib is required for plotting. Install it in the active environment, "
            "for example: python -m pip install matplotlib"
        ) from exc
    plt = pyplot


LOSS_ORDER = [
    ("scale_1000_mixed_loss_01", 1, "1%"),
    ("scale_1000_mixed_loss_05", 5, "5%"),
    ("scale_1000_mixed_loss_10", 10, "10%"),
]


def loss_info(case):
    for known_case, rate, label in LOSS_ORDER:
        if case == known_case:
            return rate, label
    return None, case


def mean_std(values):
    values = list(values)
    if not values:
        return "", ""
    if len(values) == 1:
        return statistics.mean(values), 0.0
    return statistics.mean(values), statistics.stdev(values)


def read_runtime(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("status") != "ok":
                continue
            try:
                row["runtime_s"] = float(row["runtime_s"])
                row["precision"] = float(row["precision"])
                row["recall"] = float(row["recall"])
                row["f1"] = float(row["f1"])
            except Exception:
                continue
            rate, label = loss_info(row["case"])
            if rate is None:
                continue
            row["loss_rate"] = rate
            row["loss_label"] = label
            rows.append(row)
    return rows


def read_robustness(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rate, label = loss_info(row.get("case"))
            if rate is None:
                continue
            parsed = {
                "case": row["case"],
                "condition": row["condition"],
                "loss_rate": rate,
                "loss_label": label,
            }
            for field in ("complete", "partial", "hollow", "missing"):
                parsed[field] = int(row.get(field) or 0)
            for field in ("precision", "recall", "f1"):
                try:
                    parsed[field] = float(row.get(field) or 0.0)
                except Exception:
                    parsed[field] = 0.0
            rows.append(parsed)
    return rows


def summarize_runtime(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["tool"], row["case"], row["loss_rate"], row["loss_label"])].append(row)

    summary = []
    for (tool, case, rate, label), items in grouped.items():
        item = {
            "tool": tool,
            "case": case,
            "loss_rate": rate,
            "loss_label": label,
            "runs": len(items),
        }
        for metric in ("runtime_s", "precision", "recall", "f1"):
            mean, std = mean_std(row[metric] for row in items)
            item[f"{metric}_mean"] = mean
            item[f"{metric}_std"] = std
        summary.append(item)
    return sorted(summary, key=lambda x: (x["tool"], x["loss_rate"]))


def summarize_robustness(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["case"], row["loss_rate"], row["loss_label"])].append(row)

    summary = []
    for (case, rate, label), items in grouped.items():
        item = {
            "tool": "smbmount",
            "case": case,
            "loss_rate": rate,
            "loss_label": label,
            "robustness_runs": len(items),
        }
        for field in ("complete", "partial", "hollow", "missing"):
            mean, std = mean_std(row[field] for row in items)
            item[f"{field}_mean"] = mean
            item[f"{field}_std"] = std
        summary.append(item)
    return sorted(summary, key=lambda x: x["loss_rate"])


def write_summary_csv(runtime_summary, robustness_summary, output_path):
    by_key = {
        (row["tool"], row["case"]): dict(row)
        for row in runtime_summary
    }
    for row in robustness_summary:
        key = ("smbmount", row["case"])
        by_key.setdefault(key, {}).update(row)

    fieldnames = [
        "tool", "case", "loss_rate", "loss_label", "runs",
        "runtime_s_mean", "runtime_s_std",
        "precision_mean", "precision_std",
        "recall_mean", "recall_std",
        "f1_mean", "f1_std",
        "robustness_runs",
        "complete_mean", "complete_std",
        "partial_mean", "partial_std",
        "hollow_mean", "hollow_std",
        "missing_mean", "missing_std",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in sorted(by_key.values(), key=lambda x: (x.get("loss_rate", 0), x.get("tool", ""))):
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def plot_tool_metric(summary, metric, ylabel, title, output_path):
    by_tool = defaultdict(list)
    for row in summary:
        by_tool[row["tool"]].append(row)

    plt.figure(figsize=(7, 4))
    for tool, items in sorted(by_tool.items()):
        items = sorted(items, key=lambda x: x["loss_rate"])
        xs = [row["loss_rate"] for row in items]
        ys = [row[f"{metric}_mean"] for row in items]
        es = [row[f"{metric}_std"] for row in items]
        plt.errorbar(xs, ys, yerr=es, marker="o", capsize=4, label=tool)

    plt.xticks([rate for _, rate, _ in LOSS_ORDER], [label for _, _, label in LOSS_ORDER])
    plt.xlabel("Loss rate")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def plot_robustness_states(summary, output_path):
    summary = sorted(summary, key=lambda x: x["loss_rate"])
    labels = [row["loss_label"] for row in summary]
    states = ["complete", "partial", "hollow", "missing"]
    bottoms = [0.0] * len(summary)

    plt.figure(figsize=(7, 4))
    for state in states:
        values = [row[f"{state}_mean"] for row in summary]
        plt.bar(labels, values, bottom=bottoms, label=state)
        bottoms = [bottom + value for bottom, value in zip(bottoms, values)]

    plt.xlabel("Loss rate")
    plt.ylabel("Files")
    plt.title("SMBmount reconstruction states under packet loss")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-csv", default="outputs/loss_benchmark/runtime_metrics.csv")
    parser.add_argument("--robustness-csv", default="outputs/loss_benchmark/robustness/robustness_summary.csv")
    parser.add_argument("--out-dir", default="outputs/loss_benchmark/plots")
    args = parser.parse_args()
    require_matplotlib()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    runtime_summary = summarize_runtime(read_runtime(args.runtime_csv))
    robustness_summary = summarize_robustness(read_robustness(args.robustness_csv))

    write_summary_csv(runtime_summary, robustness_summary, out_dir / "loss_summary.csv")
    plot_tool_metric(runtime_summary, "runtime_s", "Runtime (seconds)", "Runtime by loss rate", out_dir / "loss_runtime.png")
    plot_tool_metric(runtime_summary, "f1", "F1-score", "F1 by loss rate", out_dir / "loss_f1.png")
    plot_robustness_states(robustness_summary, out_dir / "loss_robustness_states.png")

    print(f"[OK] Wrote plots and summary to {out_dir}")


if __name__ == "__main__":
    main()
