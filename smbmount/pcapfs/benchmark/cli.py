import json
from pathlib import Path

import click

from smbmount.pcapfs.benchmark.normalize_ours import normalize_ours
from smbmount.pcapfs.benchmark.normalize_pcapfs import normalize_pcapfs
from smbmount.pcapfs.benchmark.metrics import score_versions, event_confusion
from smbmount.pcapfs.benchmark.report import (
    write_json,
    write_confusion_csv,
    write_markdown_report,
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def norm_path(path):
    if not path:
        return "unknown"
    return str(path).replace("/", "\\").strip("\\")


def infer_scenario_dir(ground_truth):
    """
    Lấy folder scenario từ ground truth.
    Ví dụ:
      bench_multi_version_001\\docs\\report_final.txt
    -> bench_multi_version_001
    """
    for file_item in ground_truth.get("files", []):
        path = norm_path(file_item.get("path"))
        parts = [p for p in path.split("\\") if p]

        if parts:
            return parts[0]

    return None


@click.command()
@click.option("--ground-truth", required=True, type=click.Path(exists=True))
@click.option("--ours-json", required=True, type=click.Path(exists=True))
@click.option("--pcapfs-root", required=True, type=click.Path(exists=True))
@click.option(
    "--scenario-dir",
    default=None,
    help="Scenario root directory to strip from pcapFS paths. If omitted, inferred from ground truth.",
)
@click.option("--out", required=True, type=click.Path())
def main(ground_truth, ours_json, pcapfs_root, scenario_dir, out):
    """
    Benchmark smbmount parse-pcap với pcapFS dựa trên ground truth.
    """
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)

    gt = load_json(ground_truth)

    scenario_dir = scenario_dir or gt.get("scenario_dir") or infer_scenario_dir(gt)

    ours_norm = normalize_ours(ours_json)
    pcapfs_norm = normalize_pcapfs(
        pcapfs_root,
        scenario_dir=scenario_dir,
    )

    write_json(ours_norm, out_dir / "ours_normalized.json")
    write_json(pcapfs_norm, out_dir / "pcapfs_normalized.json")

    ours_metrics = score_versions(gt, ours_norm)
    pcapfs_metrics = score_versions(gt, pcapfs_norm)
    
    pcapfs_metrics["mutation_content"] = {
        "applicable": False,
        "note": "pcapFS does not expose semantic operation labels, so mutation_content is not applicable.",
    }

    write_json(ours_metrics, out_dir / "ours_metrics.json")
    write_json(pcapfs_metrics, out_dir / "pcapfs_metrics.json")

    # Event confusion chỉ có ý nghĩa với smbmount.
    ours_confusion = event_confusion(gt, ours_norm)

    pcapfs_confusion = {
        "note": "pcapFS exposes reconstructed filesystem content, not semantic SMB event timeline. Event confusion is not applicable.",
        "labels": [],
        "matrix": [],
    }

    write_json(ours_confusion, out_dir / "ours_event_confusion.json")
    write_json(pcapfs_confusion, out_dir / "pcapfs_event_confusion.json")

    write_confusion_csv(
        ours_confusion,
        out_dir / "ours_event_confusion.csv",
    )

    comparison = {
        "scenario_dir": scenario_dir,
        "ours": ours_metrics,
        "pcapfs": pcapfs_metrics,
        "delta": {
            "strict_path_version_f1": (
                ours_metrics.get("version_f1", 0)
                - pcapfs_metrics.get("version_f1", 0)
            ),
            "content_only_f1": (
                ours_metrics.get("content_only", {}).get("f1", 0)
                - pcapfs_metrics.get("content_only", {}).get("f1", 0)
            ),
            "mutation_content_f1": "not_applicable_for_pcapfs",
        },
    }

    write_json(comparison, out_dir / "comparison_metrics.json")

    write_markdown_report(
        out_dir / "comparison_report.md",
        ours_metrics=ours_metrics,
        pcapfs_metrics=pcapfs_metrics,
        ours_confusion=ours_confusion,
        pcapfs_confusion=pcapfs_confusion,
    )

    click.echo(f"Benchmark complete: {out_dir}")
    click.echo(f"Scenario dir: {scenario_dir}")


if __name__ == "__main__":
    main()
