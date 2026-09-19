#!/usr/bin/env python3
"""Profile pcapFS cold indexing, warm mount, export, hash and scoring."""

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from smbmount.pcapfs.benchmark.metrics import score_versions
from smbmount.pcapfs.benchmark.normalize_pcapfs import (
    is_noise_file,
    norm_path,
    parse_versioned_name,
    strip_to_scenario,
)


def elapsed(callable_):
    started = time.perf_counter()
    value = callable_()
    return value, time.perf_counter() - started


def wait_for_mount(mountpoint, process, timeout=120.0):
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if os.path.ismount(mountpoint):
            return
        if process.poll() is not None:
            raise RuntimeError(f"pcapFS exited before mount readiness: {process.returncode}")
        time.sleep(0.01)
    raise TimeoutError(f"mount not ready after {timeout}s")


def export_inventory(mountpoint, scenario_dir):
    inventory = []
    mountpoint = Path(mountpoint)
    for root, _, files in os.walk(mountpoint):
        for filename in files:
            absolute = Path(root) / filename
            relative = absolute.relative_to(mountpoint)
            base_path, version = parse_versioned_name(str(relative))
            if is_noise_file(base_path):
                continue
            scenario_path = strip_to_scenario(base_path, scenario_dir=scenario_dir)
            if scenario_path is None:
                continue
            try:
                size = absolute.stat().st_size
            except OSError:
                continue
            inventory.append({
                "absolute": absolute,
                "source_path": norm_path(str(relative)),
                "path": scenario_path,
                "version": version,
                "size": size,
            })
    return inventory


def hash_inventory(inventory):
    for item in inventory:
        digest = hashlib.md5()
        with item["absolute"].open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        item["md5"] = digest.hexdigest()
    return inventory


def normalize_inventory(inventory):
    grouped = defaultdict(list)
    for item in inventory:
        grouped[item["path"]].append(item)
    files = []
    for path, versions in grouped.items():
        explicit = [item for item in versions if item["version"] is not None]
        selected = sorted(explicit, key=lambda item: item["version"]) if explicit else versions
        normalized_versions = []
        for index, item in enumerate(selected):
            metadata = {"source_path": item["source_path"]}
            if item["version"] is not None:
                metadata["pcapfs_version"] = item["version"]
            normalized_versions.append({
                "version": index,
                "op": None,
                "version_kind": "content",
                "size": item["size"],
                "md5": item["md5"],
                "metadata": metadata,
            })
        files.append({
            "path": norm_path(path),
            "is_dir": False,
            "deleted": False,
            "object_type": "file",
            "versions": normalized_versions,
            "events": [],
        })
    files.sort(key=lambda item: item["path"])
    return {"tool": "pcapFS", "files": files, "events": []}


def summarize(runs):
    keys = [key for key, value in runs[0].items() if isinstance(value, (int, float))]
    result = {}
    for key in keys:
        values = [float(run[key]) for run in runs]
        result[key] = {
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcapfs", required=True)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--scenario-dir", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()

    pcapfs = str(Path(args.pcapfs).resolve())
    pcap = str(Path(args.pcap).resolve())
    work = Path(args.work_dir)
    work.mkdir(parents=True, exist_ok=True)
    with open(args.ground_truth, "r", encoding="utf-8") as handle:
        ground_truth = json.load(handle)

    runs = []
    for run_id in range(1, args.repeats + 1):
        index = work / f"run_{run_id}.index"
        mountpoint = work / f"mount_{run_id}"
        log = work / f"run_{run_id}.log"
        index.unlink(missing_ok=True)
        shutil.rmtree(mountpoint, ignore_errors=True)
        mountpoint.mkdir()

        command = [
            pcapfs, "-r", "-n", "-i", str(index),
            "--timestamp-mode", "network", pcap,
        ]
        _, cold_index_seconds = elapsed(
            lambda: subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        )

        log_handle = log.open("wb")
        process = subprocess.Popen(
            [
                pcapfs, "-f", "-i", str(index),
                "--timestamp-mode", "network", pcap, str(mountpoint),
            ],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        mount_started = time.perf_counter()
        try:
            wait_for_mount(mountpoint, process)
            mount_seconds = time.perf_counter() - mount_started
            inventory, export_seconds = elapsed(
                lambda: export_inventory(mountpoint, args.scenario_dir)
            )
            inventory, hash_seconds = elapsed(lambda: hash_inventory(inventory))
            normalized, normalization_seconds = elapsed(
                lambda: normalize_inventory(inventory)
            )
            metrics, scoring_seconds = elapsed(
                lambda: score_versions(ground_truth, normalized)
            )
        finally:
            subprocess.run(
                ["fusermount3", "-u", str(mountpoint)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            log_handle.close()

        run = {
            "run": run_id,
            "cold_parse_reconstruct_index_seconds": cold_index_seconds,
            "warm_index_mount_seconds": mount_seconds,
            "export_inventory_seconds": export_seconds,
            "hash_seconds": hash_seconds,
            "normalization_seconds": normalization_seconds,
            "scoring_seconds": scoring_seconds,
            "exported_files": len(inventory),
            "quality": {
                "strict_path_content": metrics.get("strict_path_content"),
                "version_f1": metrics.get("version_f1"),
            },
        }
        runs.append(run)
        print(
            f"run={run_id} cold_index={cold_index_seconds:.6f}s "
            f"mount={mount_seconds:.6f}s export={export_seconds:.6f}s "
            f"hash={hash_seconds:.6f}s score={scoring_seconds:.6f}s"
        )

    output = {
        "tool": "pcapFS",
        "pcapfs_version": subprocess.check_output([pcapfs, "--version"], text=True).strip(),
        "pcap": pcap,
        "ground_truth": str(Path(args.ground_truth).resolve()),
        "repeats": args.repeats,
        "stage_definitions": {
            "cold_parse_reconstruct_index": "pcapFS --rewrite --no-mount with a fresh index path",
            "warm_index_mount": "start with existing index until kernel reports mountpoint ready",
            "export_inventory": "walk/stat scenario files without reading content",
            "hash": "read and MD5 every exported regular-file version",
            "normalization": "construct common benchmark schema from inventory and precomputed hashes",
            "scoring": "score_versions on the precomputed normalized object",
        },
        "runs": runs,
        "summary": summarize(runs),
    }
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, ensure_ascii=False)
    print(f"wrote {output_path}")


if __name__ == "__main__":
    main()
