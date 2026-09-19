from collections import Counter
from typing import Tuple


def f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def file_key(item: dict) -> str:
    return str(item.get("path") or "unknown").replace("/", "\\").strip("\\")


def version_md5(version: dict):
    return version.get("md5") or version.get("hash")


def version_size(version: dict):
    size = version.get("size")

    if size is None:
        size = (version.get("metadata") or {}).get("size")

    try:
        return int(size)
    except Exception:
        return 0


def version_op(version: dict):
    return version.get("op")


def is_observed_version(version: dict) -> bool:
    if version.get("version_kind") == "observed":
        return True

    return version_op(version) in ("read", "observed_read")


def is_mutation_version(version: dict) -> bool:
    if version.get("version_kind") == "mutation":
        return True

    op = version_op(version)

    if op in ("write", "truncate", "append", "overwrite"):
        return True

    # pcapFS không có op, xem như content version chung, không ép vào mutation.
    return False


def include_version(version: dict, kind_filter=None) -> bool:
    if kind_filter is None or kind_filter == "all":
        return True

    if kind_filter == "observed":
        return is_observed_version(version)

    if kind_filter == "mutation":
        return is_mutation_version(version)

    if kind_filter == "non_observed":
        return not is_observed_version(version)

    return True


def content_version_key(file_item: dict, version: dict, path_sensitive=True) -> Tuple:
    md5 = version_md5(version) or ""
    size = version_size(version)

    if path_sensitive:
        return file_key(file_item), md5, size

    return md5, size


def flatten_content_versions(
    data: dict,
    path_sensitive=True,
    kind_filter=None,
) -> Counter:
    result = Counter()

    for file_item in data.get("files", []):
        if bool(file_item.get("is_dir", False)):
            continue

        for version in file_item.get("versions", []):
            if not include_version(version, kind_filter=kind_filter):
                continue

            md5 = version_md5(version)
            if not md5:
                continue

            result[content_version_key(
                file_item,
                version,
                path_sensitive=path_sensitive,
            )] += 1

    return result


def score_counter(gt_counter: Counter, pred_counter: Counter, path_sensitive=True):
    matched = gt_counter & pred_counter
    missing = gt_counter - pred_counter
    extra = pred_counter - gt_counter

    tp = sum(matched.values())
    fp = sum(extra.values())
    fn = sum(missing.values())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    def item_to_dict(item):
        if path_sensitive:
            path, md5, size = item
            return {
                "path": path,
                "md5": md5,
                "size": size,
            }

        md5, size = item
        return {
            "md5": md5,
            "size": size,
        }

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1(precision, recall),
        "missing": [
            item_to_dict(item)
            for item in sorted(missing.elements())
        ],
        "extra": [
            item_to_dict(item)
            for item in sorted(extra.elements())
        ],
    }


def flatten_index_versions(data: dict):
    result = {}

    for file_item in data.get("files", []):
        if bool(file_item.get("is_dir", False)):
            continue

        for version in file_item.get("versions", []):
            key = (
                file_key(file_item),
                int(version.get("version", 0)),
            )

            result[key] = {
                "path": file_key(file_item),
                "version": int(version.get("version", 0)),
                "md5": version_md5(version),
                "size": version_size(version),
                "op": version_op(version),
                "version_kind": version.get("version_kind"),
            }

    return result


def score_index_debug(ground_truth: dict, prediction: dict):
    gt = flatten_index_versions(ground_truth)
    pred = flatten_index_versions(prediction)

    gt_keys = set(gt)
    pred_keys = set(pred)

    matched = gt_keys & pred_keys
    missing = gt_keys - pred_keys
    extra = pred_keys - gt_keys

    hash_correct = 0
    size_correct = 0
    wrong_hash = []

    for key in matched:
        gt_hash = gt[key].get("md5")
        pred_hash = pred[key].get("md5")

        if gt_hash and pred_hash and gt_hash == pred_hash:
            hash_correct += 1
        else:
            wrong_hash.append({
                "path": key[0],
                "version": key[1],
                "expected_md5": gt_hash,
                "predicted_md5": pred_hash,
            })

        if gt[key].get("size") == pred[key].get("size"):
            size_correct += 1

    return {
        "index_version_tp": len(matched),
        "index_version_fp": len(extra),
        "index_version_fn": len(missing),
        "index_content_hash_accuracy": (
            hash_correct / len(matched) if matched else 0.0
        ),
        "index_size_accuracy": (
            size_correct / len(matched) if matched else 0.0
        ),
        "index_missing_versions": [
            {"path": path, "version": version}
            for path, version in sorted(missing)
        ],
        "index_extra_versions": [
            {"path": path, "version": version}
            for path, version in sorted(extra)
        ],
        "index_wrong_hash": wrong_hash,
    }


def score_versions(ground_truth: dict, prediction: dict) -> dict:
    """
    Benchmark nhiều góc nhìn:

    Primary:
    - strict_path_content: (path, md5, size)

    Fair content-only:
    - content_only: (md5, size), bỏ qua path

    Semantic split:
    - mutation_content: chỉ write/truncate
    - observed_content: chỉ read baseline
    """
    strict_gt = flatten_content_versions(
        ground_truth,
        path_sensitive=True,
        kind_filter="all",
    )
    strict_pred = flatten_content_versions(
        prediction,
        path_sensitive=True,
        kind_filter="all",
    )

    strict_score = score_counter(
        strict_gt,
        strict_pred,
        path_sensitive=True,
    )

    content_only_gt = flatten_content_versions(
        ground_truth,
        path_sensitive=False,
        kind_filter="all",
    )
    content_only_pred = flatten_content_versions(
        prediction,
        path_sensitive=False,
        kind_filter="all",
    )

    content_only_score = score_counter(
        content_only_gt,
        content_only_pred,
        path_sensitive=False,
    )

    mutation_gt = flatten_content_versions(
        ground_truth,
        path_sensitive=True,
        kind_filter="mutation",
    )
    mutation_pred = flatten_content_versions(
        prediction,
        path_sensitive=True,
        kind_filter="mutation",
    )

    mutation_score = score_counter(
        mutation_gt,
        mutation_pred,
        path_sensitive=True,
    )

    observed_gt = flatten_content_versions(
        ground_truth,
        path_sensitive=True,
        kind_filter="observed",
    )
    observed_pred = flatten_content_versions(
        prediction,
        path_sensitive=True,
        kind_filter="observed",
    )

    observed_score = score_counter(
        observed_gt,
        observed_pred,
        path_sensitive=True,
    )
    
    if (
        observed_score.get("tp", 0) == 0
        and observed_score.get("fp", 0) == 0
        and observed_score.get("fn", 0) == 0
    ):
        observed_score = {
            "applicable": False,
            "note": "This scenario has no observed/read baseline versions.",
        }

    index_score = score_index_debug(
        ground_truth,
        prediction,
    )

    result = {
        # Backward-compatible primary metric.
        "version_tp": strict_score["tp"],
        "version_fp": strict_score["fp"],
        "version_fn": strict_score["fn"],
        "version_precision": strict_score["precision"],
        "version_recall": strict_score["recall"],
        "version_f1": strict_score["f1"],
        "content_hash_accuracy": strict_score["recall"],
        "size_accuracy": strict_score["recall"],
        "version_count_error": sum(strict_pred.values()) - sum(strict_gt.values()),

        "missing_versions": strict_score["missing"],
        "extra_versions": strict_score["extra"],
        "wrong_hash": [],

        # New metrics.
        "strict_path_content": strict_score,
        "content_only": content_only_score,
        "mutation_content": mutation_score,
        "observed_content": observed_score,
    }

    result.update(index_score)

    return result


def event_confusion(ground_truth: dict, prediction: dict) -> dict:
    gt_events = [
        (e.get("op"), file_key(e))
        for e in ground_truth.get("events", [])
    ]

    pred_events = []

    for file_item in prediction.get("files", []):
        for event in file_item.get("events", []):
            pred_events.append((
                event.get("op"),
                file_key({
                    "path": event.get("path") or file_item.get("path")
                }),
            ))

    matrix = Counter()
    used_pred = set()

    for gt_op, gt_path in gt_events:
        matched_idx = None
        matched_op = None

        for idx, (pred_op, pred_path) in enumerate(pred_events):
            if idx in used_pred:
                continue

            if pred_path == gt_path:
                matched_idx = idx
                matched_op = pred_op
                break

        if matched_idx is None:
            matrix[(gt_op, "missing")] += 1
        else:
            used_pred.add(matched_idx)
            matrix[(gt_op, matched_op)] += 1

    for idx, (pred_op, pred_path) in enumerate(pred_events):
        if idx not in used_pred:
            matrix[("none", pred_op)] += 1

    return {
        "labels": sorted(set([x for pair in matrix for x in pair])),
        "matrix": [
            {
                "expected": k[0],
                "predicted": k[1],
                "count": v,
            }
            for k, v in sorted(matrix.items())
        ],
    }