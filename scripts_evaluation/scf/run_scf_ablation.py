#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path


CLIENT_RULES = {
    "cmd": "rules/cmd_rules.json",
    "powershell": "rules/powershell_rules.json",
}


VARIANTS = ["full", "app_agnostic", "no_context", "no_max_gap", "no_excluded_noise"]


def load_rule_file(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return {"format": "smbmount-semantic-scf-v2", "rules": data}
    return data


def write_rule_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def make_app_agnostic(rule_paths):
    merged = {
        "application": "app_agnostic_cmd_powershell",
        "source": "ablation merged cmd+powershell rules",
        "format": "smbmount-semantic-scf-v2",
        "rules": [],
    }
    for rule_path in rule_paths:
        data = load_rule_file(rule_path)
        app = data.get("application") or Path(rule_path).stem.replace("_rules", "")
        for rule in data.get("rules", []):
            item = dict(rule)
            item["id"] = f"{app}:{item.get('id')}"
            item["source_application"] = app
            item.pop("application", None)
            merged["rules"].append(item)
    return merged


def make_variant(src_path, variant):
    data = load_rule_file(src_path)
    data = json.loads(json.dumps(data))
    data["source"] = f"{data.get('source', '')} ablation={variant}".strip()
    for rule in data.get("rules", []):
        rule["id"] = f"{rule.get('id')}__{variant}"
        if variant == "no_context":
            for step in rule.get("pattern", []):
                step.pop("features", None)
                step.pop("contains", None)
        elif variant == "no_max_gap":
            rule.pop("max_gap", None)
        elif variant == "no_excluded_noise":
            removed = False
            for key in ["excluded", "excluded_patterns", "exclude_patterns", "noise", "noise_patterns", "support_commands"]:
                if key in rule:
                    removed = True
                    rule.pop(key, None)
            rule["ablation_removed_noise_keys"] = removed
        else:
            raise ValueError(variant)
    return data


def run_command(command):
    print("+ " + " ".join(str(part) for part in command))
    subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", default="outputs/exp_2026_07_supplement")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--clients", nargs="+", choices=sorted(CLIENT_RULES), default=["cmd", "powershell"])
    parser.add_argument("--cmd-run-id", default="cmd_scale1000_live")
    parser.add_argument("--powershell-run-id", default="powershell_scale1000_live")
    parser.add_argument("--time-before", type=float, default=1.0)
    parser.add_argument("--time-after", type=float, default=3.0)
    args = parser.parse_args()

    root = Path(args.campaign_dir)
    rule_dir = root / "ablation" / "rules"
    timeline_dir = root / "ablation" / "timelines"
    metrics_dir = root / "ablation" / "metrics"
    rule_dir.mkdir(parents=True, exist_ok=True)
    timeline_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)

    app_agnostic_path = rule_dir / "app_agnostic_cmd_powershell_rules.json"
    write_rule_file(app_agnostic_path, make_app_agnostic([CLIENT_RULES["cmd"], CLIENT_RULES["powershell"]]))

    run_ids = {
        "cmd": args.cmd_run_id,
        "powershell": args.powershell_run_id,
    }
    client_configs = {
        client: {
            "run_id": run_ids[client],
            "pcap": str(root / "pcaps" / f"{run_ids[client]}.pcapng"),
            "rule": CLIENT_RULES[client],
            "ground_truth": f"data/eval/generated/ground_truth/{run_ids[client]}.jsonl",
        }
        for client in CLIENT_RULES
    }

    generated_rules = {"app_agnostic": app_agnostic_path}
    for client in args.clients:
        for variant in ["no_context", "no_max_gap", "no_excluded_noise"]:
            out = rule_dir / f"{client}_{variant}.json"
            write_rule_file(out, make_variant(client_configs[client]["rule"], variant))
            generated_rules[(client, variant)] = out

    summary = []
    for client in args.clients:
        cfg = client_configs[client]
        for variant in VARIANTS:
            if variant == "full":
                rule_path = Path(cfg["rule"])
            elif variant == "app_agnostic":
                rule_path = app_agnostic_path
            else:
                rule_path = generated_rules[(client, variant)]

            case_id = f"{cfg['run_id']}_{variant}"
            timeline = timeline_dir / f"{case_id}_timeline.json"
            metric_out = metrics_dir / case_id
            if timeline.exists():
                timeline.unlink()
            if metric_out.exists():
                import shutil
                shutil.rmtree(metric_out)

            run_command([
                args.python,
                "-m",
                "smbmount",
                "scf",
                cfg["pcap"],
                str(rule_path),
                str(timeline),
                "--no-print-table",
                "--no-progress",
            ])
            run_command([
                args.python,
                "scripts/scf/score_timeline.py",
                "--ground-truth",
                cfg["ground_truth"],
                "--timeline",
                str(timeline),
                "--out-dir",
                str(metric_out),
                "--time-before",
                str(args.time_before),
                "--time-after",
                str(args.time_after),
            ])

            with (metric_out / "metrics.json").open("r", encoding="utf-8") as handle:
                metrics = json.load(handle)
            summary.append({
                "client": client,
                "variant": variant,
                "rule_file": str(rule_path),
                "timeline": str(timeline),
                "metrics": str(metric_out / "metrics.json"),
                **metrics["overall"],
            })

    out = root / "ablation" / "ablation_summary_cmd_powershell.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
