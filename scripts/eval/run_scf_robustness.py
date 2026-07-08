#!/usr/bin/env python3
import argparse
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path


CASE_SPECS = {
    "packet_loss_1pct": (0.01, None),
    "packet_loss_5pct": (0.05, None),
    "packet_loss_10pct": (0.10, None),
    "truncated_50pct": (None, 0.50),
}


DEFAULT_RUN_IDS = {
    "cmd": "cmd_scale1000_live",
    "powershell": "powershell_scale1000_live",
}


def count_packets(path):
    output = subprocess.check_output(
        ["capinfos", "-M", "-c", str(path)],
        stderr=subprocess.DEVNULL,
        text=True,
    )
    for line in output.splitlines():
        if line.startswith("Number of packets:"):
            return int(line.split(":", 1)[1].strip())
    raise RuntimeError(f"cannot read packet count from {path}")


def run_quiet(command):
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def create_packet_loss_variant(src, dst, total, loss_rate, seed):
    rng = random.Random(seed)
    drop_frames = [
        frame_number
        for frame_number in range(1, total + 1)
        if rng.random() < loss_rate
    ]
    if not drop_frames:
        shutil.copyfile(src, dst)
        return 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    current = Path(src)
    temp_files = []
    batch_size = 500
    batches = [
        drop_frames[index:index + batch_size]
        for index in range(0, len(drop_frames), batch_size)
    ]

    # Delete high frame numbers first. Lower frame numbers remain stable after
    # previous batches delete only frames above them.
    for batch_index, batch in enumerate(reversed(batches), start=1):
        out = dst if batch_index == len(batches) else dst.with_suffix(f".tmp{batch_index}.pcapng")
        temp_files.append(out)
        frames = [str(frame) for frame in sorted(batch, reverse=True)]
        run_quiet(["editcap", str(current), str(out), *frames])
        current = out

    if current != dst:
        shutil.move(str(current), str(dst))

    for temp in temp_files:
        if temp != dst and temp.exists():
            temp.unlink()

    return len(drop_frames)


def create_truncated_variant(src, dst, total, truncate_ratio):
    dst.parent.mkdir(parents=True, exist_ok=True)
    keep = max(1, int(total * truncate_ratio))
    run_quiet(["tshark", "-r", str(src), "-c", str(keep), "-w", str(dst)])
    return total - keep


def write_variant(src, dst, *, loss_rate=None, truncate_ratio=None, seed=1337):
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    total = count_packets(src)
    if loss_rate is not None:
        dropped = create_packet_loss_variant(src, dst, total, loss_rate, seed)
    elif truncate_ratio is not None:
        dropped = create_truncated_variant(src, dst, total, truncate_ratio)
    else:
        shutil.copyfile(src, dst)
        dropped = 0
    kept = count_packets(dst)

    return {
        "src": str(src),
        "dst": str(dst),
        "total_packets": total,
        "kept_packets": kept,
        "dropped_packets": dropped,
        "loss_rate": loss_rate,
        "truncate_ratio": truncate_ratio,
    }


def run_command(command):
    print("+ " + " ".join(str(part) for part in command))
    subprocess.run(command, check=True)


def load_metrics(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", default="outputs/exp_2026_07_supplement")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--time-before", type=float, default=1.0)
    parser.add_argument("--time-after", type=float, default=3.0)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--clients", nargs="+", default=["cmd", "powershell"], choices=sorted(DEFAULT_RUN_IDS))
    parser.add_argument("--cmd-run-id", default=DEFAULT_RUN_IDS["cmd"])
    parser.add_argument("--powershell-run-id", default=DEFAULT_RUN_IDS["powershell"])
    parser.add_argument(
        "--cases",
        nargs="+",
        default=["packet_loss_1pct", "packet_loss_5pct", "packet_loss_10pct", "truncated_50pct"],
        choices=sorted(CASE_SPECS),
        help="Robustness variants to run.",
    )
    args = parser.parse_args()

    root = Path(args.campaign_dir)
    run_ids = {
        "cmd": args.cmd_run_id,
        "powershell": args.powershell_run_id,
    }
    runs = {
        client: {
            "run_id": run_id,
            "pcap": str(root / "pcaps" / f"{run_id}.pcapng"),
            "rules": f"rules/{client}_rules.json",
            "ground_truth": f"data/eval/generated/ground_truth/{run_id}.jsonl",
        }
        for client, run_id in run_ids.items()
    }
    pcap_dir = root / "robustness" / "pcaps"
    timeline_dir = root / "robustness" / "timelines"
    metrics_root = root / "robustness" / "metrics"
    summary_rows = []

    for client in args.clients:
        cfg = runs[client]
        src_pcap = Path(cfg["pcap"])
        for case_name in args.cases:
            loss_rate, truncate_ratio = CASE_SPECS[case_name]
            variant_id = f"{cfg['run_id']}_{case_name}"
            variant_pcap = pcap_dir / f"{variant_id}.pcapng"
            timeline = timeline_dir / f"{variant_id}_timeline.json"
            metric_dir = metrics_root / variant_id

            variant_info = write_variant(
                src_pcap,
                variant_pcap,
                loss_rate=loss_rate,
                truncate_ratio=truncate_ratio,
                seed=args.seed,
            )

            run_command([
                args.python,
                "-m",
                "smbmount",
                "scf",
                str(variant_pcap),
                cfg["rules"],
                str(timeline),
                "--no-print-table",
                "--no-progress",
            ])
            run_command([
                args.python,
                "scripts/eval/score_timeline.py",
                "--ground-truth",
                cfg["ground_truth"],
                "--timeline",
                str(timeline),
                "--out-dir",
                str(metric_dir),
                "--time-before",
                str(args.time_before),
                "--time-after",
                str(args.time_after),
            ])

            metrics = load_metrics(metric_dir / "metrics.json")
            row = {
                "client": client,
                "source_run_id": cfg["run_id"],
                "case": case_name,
                **variant_info,
                "precision": metrics["overall"]["precision"],
                "recall": metrics["overall"]["recall"],
                "f1": metrics["overall"]["f1"],
                "tp": metrics["overall"]["tp"],
                "fp": metrics["overall"]["fp"],
                "fn": metrics["overall"]["fn"],
                "timeline": str(timeline),
                "metrics": str(metric_dir / "metrics.json"),
            }
            summary_rows.append(row)

    out_json = root / "robustness" / "robustness_summary_cmd_powershell.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(summary_rows, indent=2), encoding="utf-8")
    print(json.dumps(summary_rows, indent=2))


if __name__ == "__main__":
    main()
