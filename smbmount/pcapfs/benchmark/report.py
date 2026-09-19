import csv
import json
from pathlib import Path


def write_json(data, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_confusion_csv(confusion, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = confusion.get("matrix", [])

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["expected", "predicted", "count"],
        )
        writer.writeheader()
        writer.writerows(rows)


def fmt(value):
    if isinstance(value, float):
        return f"{value:.4f}"
    return value


def metrics_table(metrics):
    keys = [
        "version_tp",
        "version_fp",
        "version_fn",
        "version_precision",
        "version_recall",
        "version_f1",
        "content_hash_accuracy",
        "size_accuracy",
        "version_count_error",
        "index_content_hash_accuracy",
    ]

    lines = [
        "| Metric | Value |",
        "|---|---:|",
    ]

    for key in keys:
        lines.append(f"| `{key}` | {fmt(metrics.get(key))} |")

    return "\n".join(lines)


def nested_score_table(title, metrics, key):
    score = metrics.get(key) or {}

    if score.get("applicable") is False:
        return "\n".join([
            f"### {title}",
            "",
            f"Not applicable: {score.get('note')}",
            "",
        ])

    rows = [
        f"### {title}",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| `tp` | {score.get('tp')} |",
        f"| `fp` | {score.get('fp')} |",
        f"| `fn` | {score.get('fn')} |",
        f"| `precision` | {fmt(score.get('precision'))} |",
        f"| `recall` | {fmt(score.get('recall'))} |",
        f"| `f1` | {fmt(score.get('f1'))} |",
        "",
    ]

    return "\n".join(rows)


def metric_sections(metrics):
    return "\n".join([
        nested_score_table(
            "Strict path content score `(path, md5, size)`",
            metrics,
            "strict_path_content",
        ),
        nested_score_table(
            "Content-only score `(md5, size)`",
            metrics,
            "content_only",
        ),
        nested_score_table(
            "Mutation content score",
            metrics,
            "mutation_content",
        ),
        nested_score_table(
            "Observed/read baseline score",
            metrics,
            "observed_content",
        ),
    ])


def write_markdown_report(
    out_path,
    ours_metrics,
    pcapfs_metrics,
    ours_confusion=None,
    pcapfs_confusion=None,
):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    content = f"""# SMB Reconstruction Benchmark Report

## 1. Tool của tôi: smbmount

{metrics_table(ours_metrics)}

{metric_sections(ours_metrics)}

## 2. Tool gốc: pcapFS

{metrics_table(pcapfs_metrics)}

{metric_sections(pcapfs_metrics)}

## 3. Cách đọc metric

- `strict_path_content`: chấm theo `(path, md5, size)`. Metric này phạt lỗi rename/path.
- `content_only`: chấm theo `(md5, size)`. Metric này đo khả năng recover content, bỏ qua khác biệt path.
- `mutation_content`: chấm các version do WRITE/TRUNCATE tạo ra.
- `observed_content`: chấm các baseline version do READ hợp lệ tạo ra.
- `index_*`: metric debug theo `(path, version_number)`, không nên dùng làm kết luận chính.
- `event_confusion`: chỉ có ý nghĩa với smbmount vì pcapFS không xuất semantic SMB event timeline.

## 4. Missing / Extra / Wrong Hash

### smbmount missing versions

{json.dumps(ours_metrics.get("missing_versions", []), indent=2, ensure_ascii=False)}

### smbmount extra versions

{json.dumps(ours_metrics.get("extra_versions", []), indent=2, ensure_ascii=False)}

### smbmount index wrong hash versions

{json.dumps(ours_metrics.get("index_wrong_hash", []), indent=2, ensure_ascii=False)}

### pcapFS missing versions

{json.dumps(pcapfs_metrics.get("missing_versions", []), indent=2, ensure_ascii=False)}

### pcapFS extra versions

{json.dumps(pcapfs_metrics.get("extra_versions", []), indent=2, ensure_ascii=False)}

### pcapFS index wrong hash versions

{json.dumps(pcapfs_metrics.get("index_wrong_hash", []), indent=2, ensure_ascii=False)}

## 5. Event Confusion 

### smbmount

{json.dumps(ours_confusion or {}, indent=2, ensure_ascii=False)}

### pcapFS

{json.dumps(pcapfs_confusion or {}, indent=2, ensure_ascii=False)}
"""

    out_path.write_text(content, encoding="utf-8")