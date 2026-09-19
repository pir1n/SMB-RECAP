#!/usr/bin/env python3
"""Measure SMBmount parse-pcap stages without mixing scoring into parsing.

When ``--mount-work-dir`` is supplied, mount startup is measured separately
from reconstructed state until the kernel reports the mountpoint ready.  It is
left null on platforms or runs where that option is not used.
"""

import argparse
import gc
import json
import multiprocessing
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from smbmount.pcapfs.benchmark.metrics import score_versions
from smbmount.pcapfs.benchmark.normalize_ours import normalize_ours
from smbmount.pcapfs.output.fs_export import export_files
from smbmount.shared.parser.pcap_reader import (
    enrich_with_file_metadata_mapping,
    enrich_with_query_info_timestamps,
    enrich_with_request_mapping,
    write_json,
)
from smbmount.shared.parser.streaming_pcap_reader import read_pcap_reconstruction_streaming
from smbmount.pcapfs.reconstruct.content import process_packets
from smbmount.pcapfs.reconstruct.hierarchy import build_tree
from smbmount.pcapfs.reconstruct.versioning import FileVersion


def timed(callable_):
    started = time.perf_counter()
    value = callable_()
    return value, time.perf_counter() - started


def run_fuse_mount(file_table, mountpoint):
    from smbmount.pcapfs.output.fuse_mount import mount_reconstructed_fs

    mount_reconstructed_fs(
        file_table,
        mountpoint=mountpoint,
        include_deleted=True,
        foreground=True,
        debug=False,
        allow_other=False,
    )


def measure_mount(file_table, mountpoint, timeout=30.0):
    mountpoint = Path(mountpoint)
    mountpoint.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["fusermount3", "-u", str(mountpoint)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    context = multiprocessing.get_context("fork")
    process = context.Process(target=run_fuse_mount, args=(file_table, str(mountpoint)))
    started = time.perf_counter()
    process.start()
    deadline = started + timeout
    try:
        while time.perf_counter() < deadline:
            if os.path.ismount(mountpoint):
                return time.perf_counter() - started
            if not process.is_alive():
                raise RuntimeError(f"SMBmount FUSE process exited with code {process.exitcode}")
            time.sleep(0.01)
        raise TimeoutError(f"SMBmount FUSE mount not ready after {timeout}s")
    finally:
        subprocess.run(
            ["fusermount3", "-u", str(mountpoint)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        process.terminate()
        process.join(timeout=5)
        if process.is_alive():
            process.kill()
            process.join(timeout=5)


def profile_once(pcap, ground_truth, output_json, timestamp_mode, mountpoint=None):
    packets, parse_seconds = timed(lambda: read_pcap_reconstruction_streaming(pcap))

    def enrich():
        value = enrich_with_request_mapping(packets)
        value = enrich_with_file_metadata_mapping(value)
        return enrich_with_query_info_timestamps(value)

    packets, enrich_seconds = timed(enrich)
    file_table, reconstruct_seconds = timed(
        lambda: process_packets(packets, timestamp_mode=timestamp_mode)
    )
    tree, tree_seconds = timed(lambda: build_tree(file_table))
    if mountpoint:
        mount_seconds = measure_mount(file_table, mountpoint)
        mount_status = "measured_from_reconstructed_state_to_kernel_mount_ready"
    else:
        mount_seconds = None
        mount_status = "not_measured"

    hash_seconds = 0.0
    hash_calls = 0
    original_get_hash = FileVersion.get_hash

    def measured_get_hash(self):
        nonlocal hash_seconds, hash_calls
        started = time.perf_counter()
        try:
            return original_get_hash(self)
        finally:
            hash_seconds += time.perf_counter() - started
            hash_calls += 1

    FileVersion.get_hash = measured_get_hash
    try:
        result, export_including_hash_seconds = timed(
            lambda: export_files(file_table, tree)
        )
    finally:
        FileVersion.get_hash = original_get_hash

    _, serialization_seconds = timed(lambda: write_json(result, output_json))

    normalized, normalization_seconds = timed(lambda: normalize_ours(output_json))
    with open(ground_truth, "r", encoding="utf-8") as handle:
        gt = json.load(handle)
    metrics, scoring_seconds = timed(lambda: score_versions(gt, normalized))

    export_excluding_hash_seconds = max(
        0.0, export_including_hash_seconds - hash_seconds
    )
    measured_total = sum((
        parse_seconds,
        enrich_seconds,
        reconstruct_seconds,
        tree_seconds,
        export_including_hash_seconds,
        serialization_seconds,
        normalization_seconds,
        scoring_seconds,
    ))

    return {
        "parse_seconds": parse_seconds,
        "enrich_seconds": enrich_seconds,
        "reconstruct_seconds": reconstruct_seconds,
        "tree_seconds": tree_seconds,
        "mount_seconds": mount_seconds,
        "mount_status": mount_status,
        "export_including_hash_seconds": export_including_hash_seconds,
        "hash_seconds": hash_seconds,
        "hash_calls": hash_calls,
        "export_excluding_hash_seconds": export_excluding_hash_seconds,
        "serialization_seconds": serialization_seconds,
        "normalization_seconds": normalization_seconds,
        "scoring_seconds": scoring_seconds,
        "pipeline_excluding_mount_seconds": measured_total,
        "quality": {
            "strict_path_content": metrics.get("strict_path_content"),
            "version_f1": metrics.get("version_f1"),
        },
    }


def summarize(runs):
    numeric_keys = [
        key for key, value in runs[0].items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    output = {}
    for key in numeric_keys:
        values = [float(run[key]) for run in runs]
        output[key] = {
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--timestamp-mode", default="network")
    parser.add_argument("--mount-work-dir")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    runs = []
    for index in range(1, args.repeats + 1):
        output_json = out_dir / f"parse_output_run_{index}.json"
        run = profile_once(
            args.pcap,
            args.ground_truth,
            output_json,
            args.timestamp_mode,
            (
                Path(args.mount_work_dir) / f"mount_{index}"
                if args.mount_work_dir
                else None
            ),
        )
        run["run"] = index
        runs.append(run)
        print(
            f"run={index} parse={run['parse_seconds']:.6f}s "
            f"reconstruct={run['reconstruct_seconds']:.6f}s "
            f"export_no_hash={run['export_excluding_hash_seconds']:.6f}s "
            f"hash={run['hash_seconds']:.6f}s "
            f"score={run['scoring_seconds']:.6f}s"
        )
        gc.collect()

    report = {
        "tool": "smbmount",
        "pcap": str(Path(args.pcap).resolve()),
        "ground_truth": str(Path(args.ground_truth).resolve()),
        "repeats": args.repeats,
        "stage_definitions": {
            "parse": "stream PCAP and decode SMB records only",
            "enrich": "request/response, file metadata and timestamp correlation",
            "reconstruct": "build in-memory file/version state",
            "mount": (
                "optional: reconstructed state until kernel reports mountpoint ready; "
                "measured only when --mount-work-dir is supplied"
            ),
            "export": "build export model; reported both including and excluding measured get_hash time",
            "hash": "cumulative exclusive wall time inside FileVersion.get_hash during export",
            "serialization": "write exported JSON",
            "normalization": "convert export to common benchmark schema",
            "scoring": "score normalized output against ground truth",
        },
        "runs": runs,
        "summary": summarize(runs),
        "comparison_policy": (
            "Do not calculate a cross-tool speedup unless both tools expose "
            "the same stage boundary on the same host, PCAP, cache policy, and repeats."
        ),
    }
    with (out_dir / "stage_timings.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    print(f"wrote {out_dir / 'stage_timings.json'}")


if __name__ == "__main__":
    main()
