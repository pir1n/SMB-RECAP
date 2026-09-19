#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import statistics
from pathlib import Path


REPEATED_RUN_IDS = {
    "cmd": [
        "cmd_repeat1_scale520_live2",
        "cmd_repeat2_scale520_live3",
        "cmd_repeat3_scale520_live3",
        "cmd_repeat4_scale520_live3",
        "cmd_repeat5_scale520_live3",
    ],
    "powershell": [
        "powershell_repeat1_scale520_live",
        "powershell_repeat2_scale520_live",
        "powershell_repeat3_scale520_live",
        "powershell_repeat4_scale520_live",
        "powershell_repeat5_scale520_live",
    ],
}

SCALE_RUNS = [
    ("cmd", 520, "cmd_repeat1_scale520_live2"),
    ("cmd", 1001, "cmd_scale1000_live"),
    ("cmd", 5005, "cmd_scale5000_live"),
    ("powershell", 520, "powershell_repeat1_scale520_live"),
    ("powershell", 1001, "powershell_scale1000_live"),
    ("powershell", 5005, "powershell_scale5000_live"),
]


def load_json(path):
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def mean(values):
    return statistics.mean(values) if values else None


def stdev(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def summarize_repeated(root):
    rows = []
    for client, run_ids in REPEATED_RUN_IDS.items():
        for run_id in run_ids:
            runtime_path = root / "logs" / f"{run_id}.runtime.json"
            if not runtime_path.exists():
                continue
            row = load_json(runtime_path)
            rows.append(row)

    summary = {}
    for client in sorted({row["client"] for row in rows}):
        group = [row for row in rows if row["client"] == client]
        summary[client] = {
            "runs": len(group),
            "workload_seconds_mean": mean([float(row["workload_seconds"]) for row in group if row.get("workload_seconds") is not None]),
            "workload_seconds_std": stdev([float(row["workload_seconds"]) for row in group if row.get("workload_seconds") is not None]),
            "scf_seconds_mean": mean([float(row["scf_seconds"]) for row in group if row.get("scf_seconds") is not None]),
            "scf_seconds_std": stdev([float(row["scf_seconds"]) for row in group if row.get("scf_seconds") is not None]),
            "precision_mean": mean([float(row["precision"]) for row in group]),
            "precision_std": stdev([float(row["precision"]) for row in group]),
            "recall_mean": mean([float(row["recall"]) for row in group]),
            "recall_std": stdev([float(row["recall"]) for row in group]),
            "f1_mean": mean([float(row["f1"]) for row in group]),
            "f1_std": stdev([float(row["f1"]) for row in group]),
        }
    return {"runs": rows, "summary": summary}


def summarize_scale(root):
    rows = []
    for client, scale, run_id in SCALE_RUNS:
        runtime_path = root / "logs" / f"{run_id}.runtime.json"
        metrics_path = root / "metrics" / run_id / "metrics.json"
        if not runtime_path.exists() or not metrics_path.exists():
            continue
        runtime = load_json(runtime_path)
        metrics = load_json(metrics_path)
        pcap_path = Path(runtime["pcap"])
        if not pcap_path.is_absolute():
            pcap_path = Path.cwd() / pcap_path
        packet_count = runtime.get("packet_count", "")
        try:
            capinfos = subprocess.check_output(
                ["capinfos", "-M", "-c", "-s", str(pcap_path)],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            for line in capinfos.splitlines():
                if line.startswith("Number of packets:"):
                    packet_count = int(line.split(":", 1)[1].strip())
                    break
        except Exception:
            pass
        rows.append({
            "client": client,
            "scale": scale,
            "run_id": run_id,
            "pcap_bytes": pcap_path.stat().st_size if pcap_path.exists() else "",
            "packet_count": packet_count,
            "workload_seconds": runtime.get("workload_seconds", ""),
            "scf_seconds": runtime.get("scf_seconds", ""),
            "precision": metrics["overall"]["precision"],
            "recall": metrics["overall"]["recall"],
            "f1": metrics["overall"]["f1"],
            "fp": metrics["overall"]["fp"],
            "fn": metrics["overall"]["fn"],
            "tp": metrics["overall"]["tp"],
        })
    return rows


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def plot_svg(path, rows, metric, ylabel):
    width, height = 780, 460
    left, right, top, bottom = 80, 25, 34, 70
    plot_w = width - left - right
    plot_h = height - top - bottom
    xs_all = [int(row["scale"]) for row in rows]
    ys_all = [float(row[metric]) for row in rows if row[metric] not in ("", None)]
    if not xs_all or not ys_all:
        return

    x_min, x_max = min(xs_all), max(xs_all)
    y_min, y_max = min(ys_all), max(ys_all)
    if metric == "f1":
        y_min = max(0.0, min(0.85, y_min - 0.02))
        y_max = 1.0
    elif y_min == y_max:
        y_min, y_max = 0, y_max + 1
    else:
        pad = (y_max - y_min) * 0.1
        y_min, y_max = max(0, y_min - pad), y_max + pad

    def x_pos(value):
        return left + ((value - x_min) / (x_max - x_min or 1)) * plot_w

    def y_pos(value):
        return top + (1 - ((value - y_min) / (y_max - y_min or 1))) * plot_h

    colors = {"cmd": "#2563eb", "powershell": "#dc2626"}
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{width / 2}" y="22" text-anchor="middle" font-family="Arial" font-size="16">{ylabel} by scale</text>',
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#111827"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#111827"/>',
    ]

    for i in range(6):
        y = top + (plot_h * i / 5)
        value = y_max - ((y_max - y_min) * i / 5)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="#e5e7eb"/>')
        parts.append(f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" font-family="Arial" font-size="11">{value:.3g}</text>')

    for scale in sorted(set(xs_all)):
        x = x_pos(scale)
        parts.append(f'<line x1="{x:.1f}" y1="{top + plot_h}" x2="{x:.1f}" y2="{top + plot_h + 5}" stroke="#111827"/>')
        parts.append(f'<text x="{x:.1f}" y="{top + plot_h + 22}" text-anchor="middle" font-family="Arial" font-size="11">{scale}</text>')

    for client in sorted({row["client"] for row in rows}):
        group = sorted([row for row in rows if row["client"] == client], key=lambda row: int(row["scale"]))
        points = [(x_pos(int(row["scale"])), y_pos(float(row[metric]))) for row in group if row[metric] not in ("", None)]
        if not points:
            continue
        point_text = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        color = colors.get(client, "#111827")
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{point_text}"/>')
        for x, y in points:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{color}"/>')

    legend_x = left + plot_w - 150
    for idx, client in enumerate(sorted({row["client"] for row in rows})):
        y = top + 22 + idx * 22
        color = colors.get(client, "#111827")
        parts.append(f'<rect x="{legend_x}" y="{y - 10}" width="12" height="12" fill="{color}"/>')
        parts.append(f'<text x="{legend_x + 18}" y="{y}" font-family="Arial" font-size="12">{client}</text>')

    parts.append(f'<text x="{left + plot_w / 2}" y="{height - 18}" text-anchor="middle" font-family="Arial" font-size="13">Measured operations</text>')
    parts.append(f'<text x="18" y="{top + plot_h / 2}" transform="rotate(-90 18 {top + plot_h / 2})" text-anchor="middle" font-family="Arial" font-size="13">{ylabel}</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def plot_scale(root, rows):

    fig_dir = root / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    for metric, ylabel in [
        ("scf_seconds", "SCF runtime seconds"),
        ("f1", "F1 score"),
    ]:
        plot_svg(fig_dir / f"{metric}_by_scale_cmd_powershell.svg", rows, metric, ylabel)
    return "ok"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", default="outputs/exp_2026_07_supplement")
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()

    root = Path(args.campaign_dir)
    repeated = summarize_repeated(root)
    (root / "repeated_run_summary_cmd_powershell.json").write_text(
        json.dumps(repeated, indent=2),
        encoding="utf-8",
    )

    scale_rows = summarize_scale(root)
    write_csv(root / "scale_summary_cmd_powershell.csv", scale_rows)
    plot_status = plot_scale(root, scale_rows) if args.plot else "skipped"

    print(json.dumps({
        "repeated_summary": repeated["summary"],
        "scale_rows": scale_rows,
        "plot_status": plot_status,
    }, indent=2))


if __name__ == "__main__":
    main()
