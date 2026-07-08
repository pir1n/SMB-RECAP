#!/usr/bin/env python3
import argparse
import csv
import importlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def norm_path(path):
    if not path:
        return "unknown"
    return str(path).replace("/", "\\").strip("\\")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def version_md5(version):
    return version.get("md5") or version.get("hash")


def version_size(version):
    size = version.get("size")

    if size is None:
        size = (version.get("metadata") or {}).get("size")

    try:
        return int(size)
    except Exception:
        return 0


def content_counter(file_item):
    counter = Counter()

    for version in file_item.get("versions", []):
        md5 = version_md5(version)

        if not md5:
            continue

        counter[(md5, version_size(version))] += 1

    return counter


def classify_files(gt, pred):
    pred_by_path = {
        norm_path(item.get("path")): item
        for item in pred.get("files", [])
        if not item.get("is_dir")
    }

    counts = Counter()
    details = []

    for gt_file in gt.get("files", []):
        if gt_file.get("is_dir"):
            continue

        gt_path = norm_path(gt_file.get("path"))
        gt_versions = content_counter(gt_file)

        if not gt_versions:
            continue

        pred_file = pred_by_path.get(gt_path)

        if pred_file is None:
            state = "missing"
            counts[state] += 1
            details.append({
                "path": gt_path,
                "state": state,
                "expected_versions": sum(gt_versions.values()),
                "matched_versions": 0,
                "predicted_versions": 0,
            })
            continue

        pred_versions = content_counter(pred_file)

        if not pred_versions:
            state = "hollow"
            counts[state] += 1
            details.append({
                "path": gt_path,
                "state": state,
                "expected_versions": sum(gt_versions.values()),
                "matched_versions": 0,
                "predicted_versions": 0,
            })
            continue

        matched = gt_versions & pred_versions
        missing = gt_versions - pred_versions

        if sum(missing.values()) == 0:
            state = "complete"
        else:
            state = "partial"

        counts[state] += 1

        details.append({
            "path": gt_path,
            "state": state,
            "expected_versions": sum(gt_versions.values()),
            "matched_versions": sum(matched.values()),
            "predicted_versions": sum(pred_versions.values()),
            "missing_versions": sum(missing.values()),
        })

    return counts, details


def append_csv(path, row):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    exists = path.exists()

    with path.open("a", newline="", encoding="utf-8") as f:
        fieldnames = [
            "case",
            "condition",
            "complete",
            "partial",
            "hollow",
            "missing",
            "precision",
            "recall",
            "f1",
            "details_json",
        ]

        writer = csv.DictWriter(f, fieldnames=fieldnames)

        if not exists:
            writer.writeheader()

        writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="Classify reconstructed files as complete/partial/hollow/missing."
    )

    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--prediction-json", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--condition", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--details-json", required=True)

    parser.add_argument(
        "--bench-pkg",
        default=os.environ.get("BENCH_PKG", "smbmount.benchmark_parsepcap"),
        help="Benchmark package. Example: smbmount.benchmark_parsepcap or smbmount.benchmark",
    )

    args = parser.parse_args()

    normalize_ours = importlib.import_module(
        f"{args.bench_pkg}.normalize_ours"
    ).normalize_ours

    score_versions = importlib.import_module(
        f"{args.bench_pkg}.metrics"
    ).score_versions

    gt = load_json(args.ground_truth)
    pred = normalize_ours(args.prediction_json)

    metrics = score_versions(gt, pred)
    strict = metrics.get("strict_path_content") or {}

    counts, details = classify_files(gt, pred)

    details_path = Path(args.details_json)
    details_path.parent.mkdir(parents=True, exist_ok=True)

    details_payload = {
        "case": args.case,
        "condition": args.condition,
        "counts": dict(counts),
        "metrics": strict,
        "details": details,
    }

    with details_path.open("w", encoding="utf-8") as f:
        json.dump(details_payload, f, indent=2, ensure_ascii=False)

    row = {
        "case": args.case,
        "condition": args.condition,
        "complete": counts.get("complete", 0),
        "partial": counts.get("partial", 0),
        "hollow": counts.get("hollow", 0),
        "missing": counts.get("missing", 0),
        "precision": strict.get("precision", ""),
        "recall": strict.get("recall", ""),
        "f1": strict.get("f1", ""),
        "details_json": str(details_path),
    }

    append_csv(args.out_csv, row)

    print(json.dumps(row, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
