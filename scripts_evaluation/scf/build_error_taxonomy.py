#!/usr/bin/env python3
import argparse
import csv
import json
from collections import Counter
from pathlib import Path


RUN_IDS = ["cmd_scale1000_live", "powershell_scale1000_live"]


def normalize_path(value):
    if value is None:
        return ""
    return str(value).replace("\\", "/").strip("/").lower()


def classify(item):
    error_type = item.get("error_type")
    gt = item.get("ground_truth") or {}
    pred = item.get("prediction") or {}
    nearest = item.get("nearest_predictions") or []

    expected = item.get("expected_event") or gt.get("event")
    predicted = item.get("predicted_event") or pred.get("event")
    gt_path = normalize_path(gt.get("path"))
    pred_path = normalize_path(pred.get("path"))

    if error_type == "MISCLASS":
        if gt_path and pred_path and gt_path != pred_path:
            return "path_mismatch"
        return "rule_ambiguity"

    if error_type == "FP":
        rule_id = str(pred.get("rule_id") or "").lower()
        action = str(pred.get("action") or "").lower()
        if "directory" in action or "listing" in action or "query" in " ".join(pred.get("commands") or []).lower():
            return "support_command_noise"
        if predicted in {"create_file", "create_directory"} and not item.get("ground_truth"):
            return "support_command_noise"
        return "rule_ambiguity"

    if error_type == "FN":
        if not nearest:
            return "missing_packet_or_unmatched_sequence"
        nearest_same_event = [row for row in nearest if row.get("event") == expected]
        if nearest_same_event:
            same_path = [
                row for row in nearest_same_event
                if normalize_path(row.get("path")) == gt_path
            ]
            if same_path:
                return "time_window_mismatch"
            return "path_mismatch"
        return "rule_ambiguity"

    return "unclassified"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", default="outputs/exp_2026_07_supplement")
    parser.add_argument("--run-ids", nargs="+", default=RUN_IDS)
    args = parser.parse_args()

    root = Path(args.campaign_dir)
    out_dir = root / "error_taxonomy"
    out_dir.mkdir(parents=True, exist_ok=True)

    all_rows = []
    summary = Counter()
    for run_id in args.run_ids:
        path = root / "metrics" / run_id / "fp_fn_debug.json"
        if not path.exists():
            continue
        client = "powershell" if run_id.startswith("powershell") else "cmd"
        rows = json.loads(path.read_text(encoding="utf-8"))
        annotated = []
        for index, item in enumerate(rows, start=1):
            taxonomy = classify(item)
            record = {
                "error_id": f"{run_id}_{index:05d}",
                "run_id": run_id,
                "client": client,
                "error_type": item.get("error_type"),
                "expected_event": item.get("expected_event") or (item.get("ground_truth") or {}).get("event"),
                "predicted_event": item.get("predicted_event") or (item.get("prediction") or {}).get("event"),
                "taxonomy": taxonomy,
                "ground_truth_path": (item.get("ground_truth") or {}).get("path"),
                "prediction_path": (item.get("prediction") or {}).get("path"),
                "prediction_rule_id": (item.get("prediction") or {}).get("rule_id"),
                "frames": (item.get("prediction") or {}).get("frames"),
            }
            annotated.append({**record, "raw": item})
            all_rows.append(record)
            summary[(client, record["error_type"], taxonomy)] += 1
        (out_dir / f"{run_id}_taxonomy.json").write_text(json.dumps(annotated, indent=2), encoding="utf-8")

    csv_path = out_dir / "error_taxonomy_summary_cmd_powershell.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["client", "error_type", "taxonomy", "count"])
        writer.writeheader()
        for (client, error_type, taxonomy), count in sorted(summary.items()):
            writer.writerow({
                "client": client,
                "error_type": error_type,
                "taxonomy": taxonomy,
                "count": count,
            })

    (out_dir / "error_taxonomy_records_cmd_powershell.json").write_text(
        json.dumps(all_rows, indent=2),
        encoding="utf-8",
    )
    print(json.dumps({
        "records": len(all_rows),
        "summary_csv": str(csv_path),
        "summary": [
            {"client": client, "error_type": error_type, "taxonomy": taxonomy, "count": count}
            for (client, error_type, taxonomy), count in sorted(summary.items())
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
