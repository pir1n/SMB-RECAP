#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from common import normalize_path, write_json
from generate_operation_scale import run_root


def run(command, *, cwd=None, check=True):
    print("+ " + " ".join(str(part) for part in command))
    return subprocess.run(command, cwd=cwd, check=check)


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json_file(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_timeline(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    return json.loads(text)


def path_in_root(event, root):
    root_norm = normalize_path(root)
    for key in ("path", "target_path"):
        value = normalize_path(event.get(key))
        if value and (value == root_norm or value.startswith(root_norm + "/")):
            return True
    return False


def filter_timeline_by_root(src, dst, root, *, client, run_id):
    events = []
    for event in load_timeline(src):
        if not path_in_root(event, root):
            continue
        item = dict(event)
        item["client"] = client
        item["run_id"] = run_id
        events.append(item)
    write_json_file(dst, events)
    return len(events)


def combine_timelines(dst, timeline_paths):
    events = []
    for path in timeline_paths:
        events.extend(load_timeline(path))
    events.sort(key=lambda row: (row.get("timestamp") is None, row.get("timestamp") or 0, (row.get("frames") or [0])[0] if row.get("frames") else 0))
    write_json_file(dst, events)
    return len(events)


def make_app_agnostic_rules(dst, rule_paths):
    merged = {
        "application": "app_agnostic_cmd_powershell",
        "source": "mixed cmd+powershell app-agnostic experiment",
        "format": "smbmount-semantic-scf-v2",
        "rules": [],
    }
    for rule_path in rule_paths:
        data = load_json(rule_path)
        app = data.get("application") or Path(rule_path).stem.replace("_rules", "")
        for rule in data.get("rules", []):
            item = dict(rule)
            item["id"] = f"{app}:{item.get('id')}"
            item["source_application"] = app
            item.pop("application", None)
            merged["rules"].append(item)
    write_json_file(dst, merged)
    return dst


def annotate_app_agnostic(src, dst, roots):
    counts = {
        "total": 0,
        "cmd_root": 0,
        "powershell_root": 0,
        "unknown_root": 0,
        "cmd_rule_on_powershell_root": 0,
        "powershell_rule_on_cmd_root": 0,
    }
    events = []
    for event in load_timeline(src):
        item = dict(event)
        rule_id = str(item.get("rule_id") or "")
        rule_app = rule_id.split(":", 1)[0] if ":" in rule_id else ""
        if path_in_root(item, roots["cmd"]):
            root_app = "cmd"
            counts["cmd_root"] += 1
        elif path_in_root(item, roots["powershell"]):
            root_app = "powershell"
            counts["powershell_root"] += 1
        else:
            root_app = "unknown"
            counts["unknown_root"] += 1
        item["predicted_rule_application"] = rule_app
        item["path_root_application"] = root_app
        if rule_app == "cmd" and root_app == "powershell":
            counts["cmd_rule_on_powershell_root"] += 1
        if rule_app == "powershell" and root_app == "cmd":
            counts["powershell_rule_on_cmd_root"] += 1
        counts["total"] += 1
        events.append(item)
    write_json_file(dst, events)
    return counts


def score(python_exe, ground_truth, timeline, out_dir, before, after):
    if Path(out_dir).exists():
        shutil.rmtree(out_dir)
    run([
        python_exe,
        "scripts/eval/score_timeline.py",
        "--ground-truth",
        *[str(path) for path in ground_truth],
        "--timeline",
        str(timeline),
        "--out-dir",
        str(out_dir),
        "--time-before",
        str(before),
        "--time-after",
        str(after),
    ])
    return load_json(Path(out_dir) / "metrics.json")


def main():
    parser = argparse.ArgumentParser(description="Run a real mixed CMD+PowerShell SCF experiment in one live tshark capture.")
    parser.add_argument("--count-per-operation", type=int, default=40)
    parser.add_argument("--campaign-dir", default="outputs/exp_2026_07_mixed_cmd_powershell")
    parser.add_argument("--server-ip", default="192.168.106.131")
    parser.add_argument("--interface", default="9")
    parser.add_argument("--drive", default="Z")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--time-before", type=float, default=1.0)
    parser.add_argument("--time-after", type=float, default=3.0)
    parser.add_argument("--run-tag", default="")
    args = parser.parse_args()

    stamp = args.run_tag or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    cmd_run = f"mixed_cmd_scale{args.count_per_operation * 13}_{stamp}"
    ps_run = f"mixed_powershell_scale{args.count_per_operation * 13}_{stamp}"
    case_id = f"mixed_cmd_powershell_scale{args.count_per_operation * 13}_{stamp}"

    root = Path(args.campaign_dir)
    pcap_dir = root / "pcaps"
    timeline_dir = root / "timelines"
    metrics_dir = root / "metrics"
    rule_dir = root / "rules"
    log_dir = root / "logs"
    for directory in [pcap_dir, timeline_dir, metrics_dir, rule_dir, log_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    for client, run_id in [("cmd", cmd_run), ("powershell", ps_run)]:
        run([
            args.python,
            "scripts/eval/generate_operation_scale.py",
            "--client",
            client,
            "--count-per-operation",
            str(args.count_per_operation),
            "--run-id",
            run_id,
            "--render",
            "--drive",
            args.drive,
            "--fast-workload",
            "--progress-every",
            "100",
        ])

    pcap = pcap_dir / f"{case_id}.pcapng"
    tshark = subprocess.Popen([
        "tshark",
        "-i",
        str(args.interface),
        "-f",
        f"host {args.server_ip} and tcp port 445",
        "-w",
        str(pcap),
    ])
    print(f"Started tshark pid={tshark.pid}, pcap={pcap}")
    time.sleep(2)
    started = time.time()

    cmd_workload = Path("data/eval/generated/workloads/cmd") / f"{cmd_run}.cmd"
    ps_workload = Path("data/eval/generated/workloads/powershell") / f"{ps_run}.ps1"
    cmd_proc = subprocess.Popen(["cmd.exe", "/c", str(cmd_workload)])
    ps_proc = subprocess.Popen([
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ps_workload),
    ])
    cmd_code = cmd_proc.wait()
    ps_code = ps_proc.wait()
    workload_seconds = time.time() - started
    time.sleep(2)
    tshark.terminate()
    try:
        tshark.wait(timeout=10)
    except subprocess.TimeoutExpired:
        tshark.kill()
        tshark.wait(timeout=10)

    if cmd_code != 0 or ps_code != 0:
        raise SystemExit(f"workload failed: cmd={cmd_code} powershell={ps_code}")

    cmd_timeline_raw = timeline_dir / f"{cmd_run}_cmd_rules_raw_timeline.json"
    ps_timeline_raw = timeline_dir / f"{ps_run}_powershell_rules_raw_timeline.json"
    agnostic_rules = make_app_agnostic_rules(
        rule_dir / "app_agnostic_cmd_powershell_rules.json",
        ["rules/cmd_rules.json", "rules/powershell_rules.json"],
    )
    app_agnostic_raw = timeline_dir / f"{case_id}_app_agnostic_raw_timeline.json"
    app_agnostic_annotated = timeline_dir / f"{case_id}_app_agnostic_timeline.json"

    run([args.python, "-m", "smbmount", "scf", str(pcap), "rules/cmd_rules.json", str(cmd_timeline_raw), "--no-print-table", "--no-progress"])
    run([args.python, "-m", "smbmount", "scf", str(pcap), "rules/powershell_rules.json", str(ps_timeline_raw), "--no-print-table", "--no-progress"])
    run([args.python, "-m", "smbmount", "scf", str(pcap), str(agnostic_rules), str(app_agnostic_raw), "--no-print-table", "--no-progress"])

    roots = {"cmd": run_root(cmd_run), "powershell": run_root(ps_run)}
    cmd_timeline = timeline_dir / f"{cmd_run}_application_aware_timeline.json"
    ps_timeline = timeline_dir / f"{ps_run}_application_aware_timeline.json"
    app_aware = timeline_dir / f"{case_id}_application_aware_timeline.json"
    filtered_counts = {
        "cmd": filter_timeline_by_root(cmd_timeline_raw, cmd_timeline, roots["cmd"], client="cmd", run_id=cmd_run),
        "powershell": filter_timeline_by_root(ps_timeline_raw, ps_timeline, roots["powershell"], client="powershell", run_id=ps_run),
    }
    app_aware_count = combine_timelines(app_aware, [cmd_timeline, ps_timeline])
    agnostic_counts = annotate_app_agnostic(app_agnostic_raw, app_agnostic_annotated, roots)

    gt_cmd = Path("data/eval/generated/ground_truth") / f"{cmd_run}.jsonl"
    gt_ps = Path("data/eval/generated/ground_truth") / f"{ps_run}.jsonl"
    metrics = {
        "application_aware": score(args.python, [gt_cmd, gt_ps], app_aware, metrics_dir / f"{case_id}_application_aware", args.time_before, args.time_after),
        "app_agnostic": score(args.python, [gt_cmd, gt_ps], app_agnostic_annotated, metrics_dir / f"{case_id}_app_agnostic", args.time_before, args.time_after),
        "application_aware_cmd_only": score(args.python, [gt_cmd], cmd_timeline, metrics_dir / f"{case_id}_application_aware_cmd_only", args.time_before, args.time_after),
        "application_aware_powershell_only": score(args.python, [gt_ps], ps_timeline, metrics_dir / f"{case_id}_application_aware_powershell_only", args.time_before, args.time_after),
    }

    summary = {
        "case_id": case_id,
        "count_per_operation": args.count_per_operation,
        "measured_operations_per_client": args.count_per_operation * 13,
        "workload_seconds": workload_seconds,
        "cmd_run_id": cmd_run,
        "powershell_run_id": ps_run,
        "roots": roots,
        "pcap": str(pcap),
        "ground_truth": [str(gt_cmd), str(gt_ps)],
        "timelines": {
            "application_aware": str(app_aware),
            "app_agnostic": str(app_agnostic_annotated),
            "cmd_rules_raw": str(cmd_timeline_raw),
            "powershell_rules_raw": str(ps_timeline_raw),
            "app_agnostic_raw": str(app_agnostic_raw),
        },
        "filtered_event_counts": filtered_counts,
        "application_aware_event_count": app_aware_count,
        "app_agnostic_event_counts": agnostic_counts,
        "metrics": {
            key: value["overall"]
            for key, value in metrics.items()
        },
    }
    summary_path = root / f"{case_id}_summary.json"
    write_json(summary_path, summary)

    md_path = root / f"{case_id}_summary.md"
    lines = [
        f"# Mixed CMD + PowerShell SCF Experiment",
        "",
        f"- Case: `{case_id}`",
        f"- CMD run: `{cmd_run}` root `{roots['cmd']}`",
        f"- PowerShell run: `{ps_run}` root `{roots['powershell']}`",
        f"- Workload seconds: `{workload_seconds:.3f}`",
        f"- PCAP: `{pcap}`",
        "",
        "| Variant | Precision | Recall | F1 | FP | FN |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for key in ["application_aware", "app_agnostic", "application_aware_cmd_only", "application_aware_powershell_only"]:
        row = summary["metrics"][key]
        lines.append(f"| {key} | {row['precision']:.4f} | {row['recall']:.4f} | {row['f1']:.4f} | {row['fp']} | {row['fn']} |")
    lines.extend([
        "",
        "## App-Agnostic Cross-Rule Counts",
        "",
        "```json",
        json.dumps(agnostic_counts, indent=2),
        "```",
    ])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print(f"summary: {summary_path}")
    print(f"markdown: {md_path}")


if __name__ == "__main__":
    main()
