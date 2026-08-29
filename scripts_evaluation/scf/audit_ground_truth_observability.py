#!/usr/bin/env python3
"""Classify unmatched ground truth by evidence observable in an SCF dump."""

import argparse
import json
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from smbmount.shared.evaluation import normalize_event, normalize_path, read_json_or_jsonl, read_jsonl, write_json, write_jsonl


MINIMUM_COMMANDS = {
    "create_file": ({"CREATE"},),
    "create_directory": ({"CREATE"},),
    "read_file": ({"CREATE", "READ"},),
    "download_file": ({"CREATE", "READ"},),
    "write_file": ({"CREATE", "WRITE"},),
    "upload_file": ({"CREATE", "WRITE"},),
    "append_file": ({"CREATE", "WRITE"},),
    "overwrite_file": ({"CREATE", "WRITE"},),
    "directory_listing": ({"CREATE", "QUERY_DIRECTORY"},),
    "rename_file": ({"SET_INFO"},),
    "delete_file": ({"CREATE"}, {"SET_INFO"}),
    "delete_directory": ({"CREATE"}, {"SET_INFO"}),
}


def parse_timestamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def record_paths(record):
    return {
        path
        for path in (
            normalize_path(record.get("path")),
            normalize_path(record.get("target_path")),
        )
        if path
    }


def ground_truth_paths(row):
    return {
        path
        for path in (
            normalize_path(row.get("path")),
            normalize_path(row.get("target_path")),
        )
        if path
    }


def paths_overlap(row, record):
    expected = ground_truth_paths(row)
    observed = record_paths(record)
    return bool(expected & observed)


def estimate_clock_offset(ground_truth, records):
    offsets = []
    for row in ground_truth:
        candidates = [record for record in records if paths_overlap(row, record)]
        if not candidates:
            continue
        start = parse_timestamp(row["start_time"])
        nearest = min(candidates, key=lambda record: abs(float(record["timestamp"]) - start))
        offsets.append(float(nearest["timestamp"]) - start)
    return statistics.median(offsets) if offsets else 0.0, offsets


def has_minimum_evidence(event, commands):
    alternatives = MINIMUM_COMMANDS.get(event, ())
    return any(required.issubset(commands) for required in alternatives)


def audit(ground_truth, records, timeline=None, clock_offset=None, before=0.5, after=1.0):
    estimated_offset, samples = estimate_clock_offset(ground_truth, records)
    offset = estimated_offset if clock_offset is None else float(clock_offset)
    output = []
    used_predictions = set()

    for row in ground_truth:
        start = parse_timestamp(row["start_time"]) + offset
        end = parse_timestamp(row["end_time"]) + offset
        path_records = [record for record in records if paths_overlap(row, record)]
        candidates = [
            record for record in path_records
            if start - before <= float(record.get("timestamp", 0)) <= end + after
        ]
        commands = {str(record.get("command") or "") for record in candidates}
        minimum = has_minimum_evidence(row.get("event"), commands)

        prediction_candidates = []
        for prediction_idx, prediction in enumerate(timeline or []):
            if prediction_idx in used_predictions:
                continue
            predicted_event = normalize_event(prediction.get("event") or prediction.get("action"))
            if predicted_event != row.get("event") or not paths_overlap(row, prediction):
                continue
            prediction_ts = float(prediction.get("timestamp", 0))
            if start - before <= prediction_ts <= end + after:
                prediction_candidates.append((prediction_idx, prediction))

        matching_predictions = []
        if prediction_candidates:
            prediction_idx, prediction = min(
                prediction_candidates,
                key=lambda item: abs(float(item[1].get("timestamp", 0)) - start),
            )
            used_predictions.add(prediction_idx)
            matching_predictions.append(prediction)

        if matching_predictions:
            classification = "detected"
        elif minimum:
            classification = "observable_rule_miss"
        elif candidates:
            classification = "partial_capture"
        elif path_records:
            classification = "clock_alignment_error"
        else:
            classification = "no_wire_evidence"

        output.append({
            "run_id": row.get("run_id"),
            "op_id": row.get("op_id"),
            "event": row.get("event"),
            "path": row.get("path"),
            "target_path": row.get("target_path"),
            "classification": classification,
            "minimum_evidence_present": minimum,
            "candidate_frames": [record.get("frame_number") for record in candidates],
            "prediction_frames": [
                prediction.get("frames", []) for prediction in matching_predictions
            ],
            "commands": sorted(commands - {""}),
            "channels": sorted({record.get("src_port") for record in candidates if record.get("src_port")}),
            "session_ids": sorted({str(record.get("session_id")) for record in candidates if record.get("session_id")}),
            "tree_ids": sorted({str(record.get("tree_id")) for record in candidates if record.get("tree_id")}),
            "clock_offset_seconds": offset,
        })

    summary = Counter((row["event"], row["classification"]) for row in output)
    return output, {
        "clock_offset_seconds": offset,
        "clock_offset_sample_count": len(samples),
        "clock_offset_median_absolute_deviation_seconds": (
            statistics.median(abs(value - estimated_offset) for value in samples)
            if samples else None
        ),
        "records": len(output),
        "classification_counts": dict(Counter(row["classification"] for row in output)),
        "per_event": [
            {"event": event, "classification": classification, "count": count}
            for (event, classification), count in sorted(summary.items())
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--scf-dump", required=True)
    parser.add_argument("--timeline")
    parser.add_argument("--clock-offset", default="auto")
    parser.add_argument("--before", type=float, default=0.5)
    parser.add_argument("--after", type=float, default=1.0)
    parser.add_argument("--out", required=True)
    parser.add_argument("--summary")
    args = parser.parse_args()

    ground_truth = read_jsonl(args.ground_truth)
    records = read_json_or_jsonl(args.scf_dump)
    timeline = read_json_or_jsonl(args.timeline) if args.timeline else []
    clock_offset = None if args.clock_offset == "auto" else float(args.clock_offset)
    audited, summary = audit(
        ground_truth,
        records,
        timeline=timeline,
        clock_offset=clock_offset,
        before=args.before,
        after=args.after,
    )
    write_jsonl(args.out, audited)
    summary_path = args.summary or str(Path(args.out).with_suffix(".summary.json"))
    write_json(summary_path, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
