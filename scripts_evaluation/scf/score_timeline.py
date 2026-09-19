#!/usr/bin/env python3
import argparse
import csv
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from smbmount.shared.evaluation import (
    CANONICAL_EVENTS,
    ensure_dir,
    normalize_event,
    normalize_path,
    read_json_or_jsonl,
    write_json,
)


def parse_time(value):
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc).timestamp()
    except ValueError:
        return None


def infer_run_id(path):
    stem = Path(path).stem
    for suffix in ["_timeline", "_scf_timeline", "_events"]:
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def load_ground_truth(paths, case_sensitive):
    rows = []
    run_to_client = {}
    for path in paths:
        for row in read_json_or_jsonl(path):
            if row.get("status") not in (None, "success"):
                continue
            event = normalize_event(row.get("event"))
            if event not in CANONICAL_EVENTS:
                continue
            item = dict(row)
            item["_event"] = event
            item["_path"] = normalize_path(row.get("path"), case_sensitive)
            item["_target_path"] = normalize_path(row.get("target_path"), case_sensitive)
            item["_start"] = parse_time(row.get("start_time"))
            item["_end"] = parse_time(row.get("end_time"))
            item["_matched"] = False
            item["_source"] = str(path)
            rows.append(item)
            if row.get("run_id") and row.get("client"):
                run_to_client[row["run_id"]] = row["client"]
    return rows, run_to_client


def load_observability_records(paths, gt_rows, session_trees=None):
    """Load raw scf-dump rows used only to audit wire observability."""
    records = []
    gt_run_ids = {row.get("run_id") for row in gt_rows if row.get("run_id")}
    single_gt_run = next(iter(gt_run_ids)) if len(gt_run_ids) == 1 else None
    allowed_session_trees = set(session_trees or [])

    for path in paths:
        explicit_run_id = None
        path_text = str(path)
        if "=" in path_text and not Path(path_text).exists():
            explicit_run_id, path_text = path_text.split("=", 1)
        run_id = explicit_run_id or (
            single_gt_run if len(paths) == 1 and single_gt_run
            else infer_run_id(path_text)
        )
        for row in read_json_or_jsonl(path_text):
            session_tree = (str(row.get("session_id")), str(row.get("tree_id")))
            if allowed_session_trees and session_tree not in allowed_session_trees:
                continue
            records.append({
                "_run_id": row.get("run_id") or run_id,
                "_time": parse_time(row.get("timestamp")),
                "command": str(row.get("command") or row.get("smb2_command_name") or "").upper(),
                "frame_number": row.get("frame_number"),
                "session_id": row.get("session_id"),
                "tree_id": row.get("tree_id"),
            })
    return records


def partition_cached_directory_listings(gt_rows, records, before, after):
    """Exclude relaxed-only listings with no QUERY_DIRECTORY wire evidence.

    Any QUERY_DIRECTORY in the same run and command window keeps the row
    scoreable, even if its path is unavailable. This keeps the policy
    conservative: detector misses remain FN whenever enumeration is on wire.
    """
    scoreable = []
    excluded = []
    for row in gt_rows:
        if row.get("_event") != "directory_listing":
            scoreable.append(row)
            continue
        start = row.get("_start")
        end = row.get("_end")
        if start is None or end is None:
            scoreable.append(row)
            continue
        run_id = row.get("run_id")
        queries = [
            record for record in records
            if record.get("command") == "QUERY_DIRECTORY"
            and record.get("_time") is not None
            and (not run_id or record.get("_run_id") == run_id)
            and start - before <= record["_time"] <= end + after
        ]
        if queries:
            scoreable.append(row)
            continue
        excluded.append({
            "reason": "directory_listing_not_observable_no_query_directory",
            "ground_truth": compact_ground_truth(row),
        })
    return scoreable, excluded


def parse_session_tree_values(values):
    parsed = set()
    for value in values or []:
        if ":" not in value:
            raise ValueError(f"Expected SESSION_ID:TREE_ID, got {value!r}")
        parsed.add(tuple(value.rsplit(":", 1)))
    return parsed


def prediction_event(row):
    action_event = normalize_event(row.get("action"))
    if action_event in CANONICAL_EVENTS:
        return action_event

    rule_event = normalize_event(row.get("rule_id"))
    if rule_event in CANONICAL_EVENTS:
        return rule_event

    return None


def load_predictions(paths, case_sensitive, gt_rows):
    rows = []
    single_gt_run = None
    if len({row.get("run_id") for row in gt_rows if row.get("run_id")}) == 1:
        single_gt_run = next(row.get("run_id") for row in gt_rows if row.get("run_id"))

    for path in paths:
        explicit_run_id = None
        path_text = str(path)
        if "=" in path_text and not Path(path_text).exists():
            explicit_run_id, path_text = path_text.split("=", 1)

        run_id = explicit_run_id or (single_gt_run if len(paths) == 1 and single_gt_run else infer_run_id(path_text))
        for row in read_json_or_jsonl(path_text):
            if row.get("success") is False:
                continue
            event = prediction_event(row)
            if event not in CANONICAL_EVENTS:
                continue
            item = dict(row)
            item["_event"] = event
            item["_path"] = normalize_path(row.get("path"), case_sensitive)
            item["_target_path"] = normalize_path(row.get("target_path"), case_sensitive)
            item["_time"] = parse_time(row.get("timestamp"))
            item["_matched"] = False
            item["_run_id"] = row.get("run_id") or run_id
            item["_source"] = str(path_text)
            rows.append(item)
    return rows


def time_matches(gt, pred, before, after):
    start = gt.get("_start")
    end = gt.get("_end")
    pred_time = pred.get("_time")
    if start is None or end is None or pred_time is None:
        return True
    return (start - before) <= pred_time <= (end + after)


def path_matches(gt, pred):
    gt_path = gt.get("_path")
    pred_path = pred.get("_path")
    event = gt.get("_event")
    if event == "rename_file" and not pred_path and target_matches(gt, pred):
        return True
    if event == "directory_listing" and not pred_path:
        return gt_path in (None, "")
    if not gt_path or not pred_path:
        return gt_path == pred_path or event == "directory_listing"
    return gt_path == pred_path


def target_matches(gt, pred):
    gt_target = gt.get("_target_path")
    pred_target = pred.get("_target_path")
    if gt.get("_event") != "rename_file":
        return True
    if not gt_target or not pred_target:
        return gt_target == pred_target
    return gt_target == pred_target


def candidate_score(gt, pred):
    gt_start = gt.get("_start")
    pred_time = pred.get("_time")
    if gt_start is None or pred_time is None:
        return abs((gt.get("op_id") or 0) - (pred.get("frames") or [0])[0])
    return abs(pred_time - gt_start)


def event_matches(gt, pred, require_same_event, relaxed=False):
    if not require_same_event:
        return True

    gt_event = gt.get("_event")
    pred_event = pred.get("_event")
    if gt_event == pred_event:
        return True

    # PowerShell Set-Content and smbclient put-overwrite commonly emit the same
    # SMB CREATE(opened)+WRITE shape as append/write. Ground truth still marks
    # these workload commands as overwrite, so scoring treats the lossy SMB
    # write signal as compatible inside the overwrite command window.
    if (
        relaxed
        and gt_event == "overwrite_file"
        and pred_event == "write_file"
        and gt.get("client") in {"powershell", "smbclient"}
    ):
        return True

    return False


def find_candidate(gt, predictions, before, after, require_same_event, relaxed=False):
    candidates = []
    for idx, pred in enumerate(predictions):
        if pred["_matched"]:
            continue
        if not event_matches(gt, pred, require_same_event, relaxed=relaxed):
            continue
        if not time_matches(gt, pred, before, after):
            continue
        if not path_matches(gt, pred):
            continue
        if not target_matches(gt, pred):
            continue
        candidates.append((candidate_score(gt, pred), idx, pred))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][1], candidates[0][2]


def compact_prediction(pred):
    return {
        "run_id": pred.get("_run_id"),
        "event": pred.get("_event"),
        "rule_id": pred.get("rule_id"),
        "action": pred.get("action"),
        "timestamp": pred.get("timestamp"),
        "path": pred.get("path"),
        "target_path": pred.get("target_path"),
        "frames": pred.get("frames"),
        "commands": pred.get("commands"),
        "features": pred.get("features"),
    }


def compact_ground_truth(gt):
    return {
        "run_id": gt.get("run_id"),
        "op_id": gt.get("op_id"),
        "client": gt.get("client"),
        "event": gt.get("_event"),
        "path": gt.get("path"),
        "target_path": gt.get("target_path"),
        "start_time": gt.get("start_time"),
        "end_time": gt.get("end_time"),
        "command": gt.get("command"),
    }


def nearest_predictions(gt, predictions, limit=5):
    scored = []
    for pred in predictions:
        score = candidate_score(gt, pred)
        if math.isnan(score):
            score = 0
        scored.append((score, pred))
    scored.sort(key=lambda item: item[0])
    return [compact_prediction(pred) for _, pred in scored[:limit]]


def safe_div(num, den):
    return num / den if den else 0.0


def score(gt_rows, predictions, before, after, relaxed=False):
    gt_rows = sorted(gt_rows, key=lambda row: (row.get("_start") is None, row.get("_start") or 0, row.get("op_id") or 0))
    predictions = sorted(predictions, key=lambda row: (row.get("_time") is None, row.get("_time") or 0, (row.get("frames") or [0])[0] if row.get("frames") else 0))

    tp = Counter()
    fp = Counter()
    fn = Counter()
    confusion = defaultdict(Counter)
    matches = []
    errors = []

    for gt in gt_rows:
        found = find_candidate(
            gt,
            predictions,
            before,
            after,
            require_same_event=True,
            relaxed=relaxed,
        )
        if not found:
            continue
        _, pred = found
        gt["_matched"] = True
        pred["_matched"] = True
        event = gt["_event"]
        tp[event] += 1
        confusion[event][event] += 1
        matches.append({
            "type": "TP",
            "ground_truth": compact_ground_truth(gt),
            "prediction": compact_prediction(pred),
        })

    for gt in gt_rows:
        if gt["_matched"]:
            continue
        found = find_candidate(gt, predictions, before, after, require_same_event=False)
        if not found:
            continue
        _, pred = found
        gt["_matched"] = True
        pred["_matched"] = True
        true_event = gt["_event"]
        pred_event = pred["_event"]
        fn[true_event] += 1
        fp[pred_event] += 1
        confusion[true_event][pred_event] += 1
        errors.append({
            "error_type": "MISCLASS",
            "expected_event": true_event,
            "predicted_event": pred_event,
            "ground_truth": compact_ground_truth(gt),
            "prediction": compact_prediction(pred),
        })

    for gt in gt_rows:
        if gt["_matched"]:
            continue
        event = gt["_event"]
        fn[event] += 1
        confusion[event]["__missing__"] += 1
        errors.append({
            "error_type": "FN",
            "expected_event": event,
            "ground_truth": compact_ground_truth(gt),
            "nearest_predictions": nearest_predictions(gt, predictions),
        })

    for pred in predictions:
        if pred["_matched"]:
            continue
        event = pred["_event"]
        fp[event] += 1
        confusion["__extra__"][event] += 1
        errors.append({
            "error_type": "FP",
            "predicted_event": event,
            "prediction": compact_prediction(pred),
        })

    return tp, fp, fn, confusion, matches, errors


def metric_table(tp, fp, fn):
    labels = sorted(set(CANONICAL_EVENTS) | set(tp) | set(fp) | set(fn))
    per_class = {}
    for label in labels:
        precision = safe_div(tp[label], tp[label] + fp[label])
        recall = safe_div(tp[label], tp[label] + fn[label])
        f1 = safe_div(2 * precision * recall, precision + recall)
        per_class[label] = {
            "tp": tp[label],
            "fp": fp[label],
            "fn": fn[label],
            "support": tp[label] + fn[label],
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    total_tp = sum(tp.values())
    total_fp = sum(fp.values())
    total_fn = sum(fn.values())
    precision = safe_div(total_tp, total_tp + total_fp)
    recall = safe_div(total_tp, total_tp + total_fn)
    f1 = safe_div(2 * precision * recall, precision + recall)

    macro_f1 = safe_div(sum(row["f1"] for row in per_class.values()), len(per_class))
    support_total = sum(row["support"] for row in per_class.values())
    weighted_f1 = safe_div(sum(row["f1"] * row["support"] for row in per_class.values()), support_total)

    return {
        "overall": {
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
        },
        "per_class": per_class,
    }


def metrics_by_client(gt_rows, predictions, before, after, relaxed=False):
    clients = sorted({row.get("client") for row in gt_rows if row.get("client")})
    output = {}
    for client in clients:
        client_gt = [dict(row, _matched=False) for row in gt_rows if row.get("client") == client]
        run_ids = {row.get("run_id") for row in client_gt if row.get("run_id")}
        client_predictions = [dict(row, _matched=False) for row in predictions if row.get("_run_id") in run_ids]
        tp, fp, fn, _, _, _ = score(
            client_gt,
            client_predictions,
            before,
            after,
            relaxed=relaxed,
        )
        output[client] = metric_table(tp, fp, fn)["overall"]
    return output


def write_confusion_csv(path, confusion):
    labels = sorted(set(confusion.keys()) | {col for row in confusion.values() for col in row.keys()})
    ensure_dir(Path(path).parent)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["actual\\predicted"] + labels)
        for actual in labels:
            writer.writerow([actual] + [confusion.get(actual, {}).get(pred, 0) for pred in labels])


def score_once(gt_rows, predictions, before, after, relaxed):
    clean_gt = [dict(row, _matched=False) for row in gt_rows]
    clean_predictions = [dict(row, _matched=False) for row in predictions]
    tp, fp, fn, confusion, matches, errors = score(
        clean_gt,
        clean_predictions,
        before,
        after,
        relaxed=relaxed,
    )
    metrics = metric_table(tp, fp, fn)
    metrics["scoring_policy"] = "relaxed" if relaxed else "strict"
    metrics["per_client"] = metrics_by_client(
        gt_rows,
        predictions,
        before,
        after,
        relaxed=relaxed,
    )
    return metrics, confusion, matches, errors


def write_score_artifacts(out_dir, metrics, confusion, matches, errors):
    write_json(out_dir / "metrics.json", metrics)
    write_json(out_dir / "confusion_matrix.json", {actual: dict(cols) for actual, cols in confusion.items()})
    write_confusion_csv(out_dir / "confusion_matrix.csv", confusion)
    write_json(out_dir / "matches.json", matches)
    write_json(out_dir / "fp_fn_debug.json", errors)
    write_json(out_dir / "fp_debug.json", [err for err in errors if err["error_type"] in {"FP", "MISCLASS"}])
    write_json(out_dir / "fn_debug.json", [err for err in errors if err["error_type"] in {"FN", "MISCLASS"}])


def main():
    parser = argparse.ArgumentParser(description="Score SMBmount SCF timeline JSON against ground-truth JSONL.")
    parser.add_argument("--ground-truth", nargs="+", required=True)
    parser.add_argument("--timeline", nargs="+", required=True, help="Timeline JSON files. Use run_id=path to force run id.")
    parser.add_argument("--out-dir", default="outputs/eval/metrics")
    parser.add_argument("--time-before", type=float, default=1.0)
    parser.add_argument("--time-after", type=float, default=3.0)
    parser.add_argument("--case-sensitive", action="store_true")
    parser.add_argument(
        "--relaxed-ignore-cached-listings",
        action="store_true",
        help="In relaxed metrics only, exclude listing GT windows with no raw QUERY_DIRECTORY evidence.",
    )
    parser.add_argument(
        "--scf-dump",
        nargs="+",
        help="Raw scf-dump JSON for listing observability. Use run_id=path when needed.",
    )
    parser.add_argument(
        "--observability-session-tree",
        action="append",
        default=[],
        metavar="SESSION_ID:TREE_ID",
        help="Restrict observability evidence to an SMB SessionId:TreeId. Repeat when needed.",
    )
    args = parser.parse_args()

    gt_rows, _ = load_ground_truth(args.ground_truth, args.case_sensitive)
    predictions = load_predictions(args.timeline, args.case_sensitive, gt_rows)
    relaxed_gt_rows = gt_rows
    cached_listing_exclusions = []
    if args.relaxed_ignore_cached_listings:
        if not args.scf_dump:
            parser.error("--relaxed-ignore-cached-listings requires --scf-dump")
        try:
            session_trees = parse_session_tree_values(args.observability_session_tree)
        except ValueError as exc:
            parser.error(str(exc))
        observability_records = load_observability_records(
            args.scf_dump,
            gt_rows,
            session_trees=session_trees,
        )
        relaxed_gt_rows, cached_listing_exclusions = partition_cached_directory_listings(
            gt_rows,
            observability_records,
            args.time_before,
            args.time_after,
        )
    common_inputs = {
        "ground_truth": args.ground_truth,
        "timeline": args.timeline,
        "time_before": args.time_before,
        "time_after": args.time_after,
        "case_sensitive": args.case_sensitive,
        "relaxed_ignore_cached_listings": args.relaxed_ignore_cached_listings,
        "scf_dump": args.scf_dump,
        "observability_session_tree": args.observability_session_tree,
    }

    strict = score_once(gt_rows, predictions, args.time_before, args.time_after, relaxed=False)
    relaxed = score_once(relaxed_gt_rows, predictions, args.time_before, args.time_after, relaxed=True)
    strict_metrics, strict_confusion, strict_matches, strict_errors = strict
    relaxed_metrics, relaxed_confusion, relaxed_matches, relaxed_errors = relaxed
    strict_metrics["inputs"] = dict(common_inputs)
    relaxed_metrics["inputs"] = dict(common_inputs)
    relaxed_metrics["observability"] = {
        "original_ground_truth_count": len(gt_rows),
        "scoreable_ground_truth_count": len(relaxed_gt_rows),
        "excluded_cached_directory_listings": len(cached_listing_exclusions),
        "policy": "exclude directory_listing only when raw SCF dump has no QUERY_DIRECTORY in its window",
    }
    strict_metrics["relaxed_companion"] = "relaxed/metrics.json"

    out_dir = Path(args.out_dir)
    write_score_artifacts(
        out_dir,
        strict_metrics,
        strict_confusion,
        strict_matches,
        strict_errors,
    )
    write_score_artifacts(
        out_dir / "relaxed",
        relaxed_metrics,
        relaxed_confusion,
        relaxed_matches,
        relaxed_errors,
    )
    write_json(
        out_dir / "relaxed" / "not_observable_cached_listings.json",
        cached_listing_exclusions,
    )
    write_json(out_dir / "strict_vs_relaxed.json", {
        "strict": strict_metrics["overall"],
        "relaxed": relaxed_metrics["overall"],
        "relaxed_compatibility": {
            "overwrite_file": ["write_file"],
            "clients": ["powershell", "smbclient"],
            "cached_directory_listing": (
                "excluded only with --relaxed-ignore-cached-listings and no raw QUERY_DIRECTORY"
            ),
        },
    })

    strict_overall = strict_metrics["overall"]
    relaxed_overall = relaxed_metrics["overall"]
    print(
        f"strict: precision={strict_overall['precision']:.4f} "
        f"recall={strict_overall['recall']:.4f} f1={strict_overall['f1']:.4f}"
    )
    print(
        f"relaxed: precision={relaxed_overall['precision']:.4f} "
        f"recall={relaxed_overall['recall']:.4f} f1={relaxed_overall['f1']:.4f}"
    )
    print(f"wrote {out_dir}")


if __name__ == "__main__":
    main()
