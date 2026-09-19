import argparse
import hashlib
import json
import os
import shutil
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from smbmount.pcapfs.benchmark.metrics import score_versions
from smbmount.pcapfs.benchmark.normalize_pcapfs import (
    is_noise_file,
    norm_path,
    parse_versioned_name,
    strip_to_scenario,
)

COMPARABLE_METRICS = (
    "start_to_mount_ready_seconds",
    "export_seconds",
    "hash_seconds",
    "scoring_seconds",
    "post_mount_seconds",
    "end_to_end_seconds",
)


PHASE_DESCRIPTIONS = {
    "parse": (
        "reader(read_pcap_reconstruction_streaming or read_pcap_basic) + "
        "enrich_with_request_mapping + enrich_with_file_metadata_mapping + "
        "enrich_with_query_info_timestamps"
    ),
    "reconstruct": "process_packets(...) only; ends when FileTable is complete",
    "mount_prepare": "build_fuse_entries(...) only; excludes foreground FUSE runtime",
}


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(data, output_path):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def ensure_clean_dir(path):
    path = Path(path)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def terminate_process(proc, timeout=5.0):
    if proc.poll() is not None:
        return

    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=timeout)


def unmount(mountpoint):
    for command in (
        ["fusermount3", "-u", str(mountpoint)],
        ["fusermount", "-u", str(mountpoint)],
        ["umount", "-l", str(mountpoint)],
    ):
        try:
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except FileNotFoundError:
            continue


def wait_for_mount_ready(mountpoint, proc=None, timeout=300.0, poll_interval=0.1):
    timeout = float(timeout)
    deadline = None if timeout <= 0 else time.perf_counter() + timeout
    mountpoint = Path(mountpoint)

    while deadline is None or time.perf_counter() < deadline:
        if os.path.ismount(mountpoint):
            return True

        if proc is not None and proc.poll() is not None:
            return False

        time.sleep(poll_interval)

    return False


def parse_and_reconstruct_for_mount(input_pcap, timestamp_mode="hybrid", reader="streaming"):
    """
    Benchmark-specific SMBmount path.

    It mirrors parse_pcap_to_json up to FileTable creation, but deliberately
    excludes JSON export, hash generation, snapshot export, and FUSE execution.
    """
    from smbmount.pcapfs.parser.pcap_reader import (
        enrich_with_file_metadata_mapping,
        enrich_with_query_info_timestamps,
        enrich_with_request_mapping,
        read_pcap_basic,
    )
    from smbmount.pcapfs.parser.streaming_pcap_reader import read_pcap_reconstruction_streaming
    from smbmount.pcapfs.reconstruct.content import process_packets

    timings = {}

    t0 = time.perf_counter()
    if reader == "streaming":
        packets = read_pcap_reconstruction_streaming(input_pcap)
    elif reader == "legacy":
        packets = read_pcap_basic(input_pcap)
    else:
        raise ValueError(f"Unsupported PCAP reader: {reader}")

    packets = enrich_with_request_mapping(packets)
    packets = enrich_with_file_metadata_mapping(packets)
    packets = enrich_with_query_info_timestamps(packets)
    timings["parse_seconds"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    file_table = process_packets(packets, timestamp_mode=timestamp_mode)
    timings["reconstruct_seconds"] = time.perf_counter() - t0
    timings["internal_total_seconds"] = (
        timings["parse_seconds"] + timings["reconstruct_seconds"]
    )
    timings["phase_descriptions"] = PHASE_DESCRIPTIONS

    return file_table, timings


def run_smbmount_fuse_foreground(
    input_pcap,
    mountpoint,
    timestamp_mode="hybrid",
    reader="streaming",
    snapshot_at=None,
    snapshot_time_source="network",
    include_deleted=False,
    complete_only=False,
    allow_other=False,
    debug=False,
    profile_json=None,
):
    from smbmount.pcapfs.output.fuse_mount import SMBMountFuseFS, build_fuse_entries
    import mfusepy as fuse

    file_table, timings = parse_and_reconstruct_for_mount(
        input_pcap,
        timestamp_mode=timestamp_mode,
        reader=reader,
    )

    t0 = time.perf_counter()
    entries = build_fuse_entries(
        file_table,
        snapshot_at=snapshot_at,
        snapshot_time_source=snapshot_time_source,
        include_deleted=include_deleted,
        complete_only=complete_only,
    )
    timings["mount_prepare_seconds"] = time.perf_counter() - t0
    timings["internal_total_seconds"] += timings["mount_prepare_seconds"]

    if profile_json:
        write_json(timings, profile_json)

    options = {
        "foreground": True,
        "nothreads": True,
        "ro": True,
        "debug": debug,
    }
    if allow_other:
        options["allow_other"] = True

    os.makedirs(mountpoint, exist_ok=True)
    return fuse.FUSE(SMBMountFuseFS(entries), mountpoint, **options)


def export_mounted_filesystem(source_root, export_root):
    source_root = Path(source_root)
    export_root = ensure_clean_dir(export_root)

    for root, dirs, files in os.walk(source_root, followlinks=False):
        root_path = Path(root)
        rel_root = root_path.relative_to(source_root)
        target_root = export_root / rel_root
        target_root.mkdir(parents=True, exist_ok=True)

        for dirname in list(dirs):
            source_dir = root_path / dirname
            if source_dir.is_symlink():
                dirs.remove(dirname)
                continue
            (target_root / dirname).mkdir(exist_ok=True)

        for filename in files:
            source_file = root_path / filename
            if source_file.is_symlink() or not source_file.is_file():
                continue
            shutil.copyfile(source_file, target_root / filename)

    return export_root


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_exported_files(export_root):
    export_root = Path(export_root)
    files = []

    for root, _dirs, filenames in os.walk(export_root):
        for filename in filenames:
            path = Path(root) / filename
            if not path.is_file() or path.is_symlink():
                continue
            rel_path = norm_path(path.relative_to(export_root))
            files.append({
                "path": rel_path,
                "size": path.stat().st_size,
                "md5": md5_file(path),
            })

    files.sort(key=lambda item: item["path"])
    return {"algorithm": "md5", "files": files}


def normalized_from_hash_manifest(manifest, tool, scenario_dir=None):
    grouped = {}

    for item in manifest.get("files", []):
        base_path, version = parse_versioned_name(item["path"])

        if is_noise_file(base_path):
            continue

        base_path = strip_to_scenario(base_path, scenario_dir=scenario_dir)
        if base_path is None:
            continue

        grouped.setdefault(base_path, []).append({
            "version": version,
            "size": item["size"],
            "md5": item["md5"],
            "source_path": item["path"],
        })

    normalized_files = []
    for path, versions in grouped.items():
        explicit = [v for v in versions if v["version"] is not None]
        plain = [v for v in versions if v["version"] is None]
        selected = sorted(explicit, key=lambda v: v["version"]) if explicit else plain

        normalized_files.append({
            "path": norm_path(path),
            "is_dir": False,
            "deleted": False,
            "object_type": "file",
            "versions": [
                {
                    "version": idx,
                    "op": None,
                    "version_kind": "content",
                    "size": version["size"],
                    "md5": version["md5"],
                    "metadata": {"source_path": version["source_path"]},
                }
                for idx, version in enumerate(selected)
            ],
            "events": [],
        })

    normalized_files.sort(key=lambda item: item["path"])
    return {"tool": tool, "files": normalized_files, "events": []}


def build_timeout_runtime(tool, timeout_seconds):
    return {
        "tool": tool,
        "status": "timeout",
        "mount_ready": False,
        "timeout_seconds": timeout_seconds,
        "external": None,
        "internal": None,
        "correctness": None,
    }


def build_failed_runtime(tool, message):
    return {
        "tool": tool,
        "status": "failed",
        "error": message,
        "external": None,
        "internal": None,
        "correctness": None,
    }


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def default_tool_command(tool, input_pcap, mountpoint, profile_json, timestamp_mode, reader):
    if tool == "smbmount":
        return [
            sys.executable,
            "-m",
            "smbmount",
            "mount-pcap",
            str(input_pcap),
            str(mountpoint),
            "--timestamp-mode",
            timestamp_mode,
            "--reader",
            reader,
            "--profile-json",
            str(profile_json),
            "--fuse-complete-only",
        ]

    if tool == "pcapfs":
        return [
            "pcapfs",
            "--timestamp-mode",
            timestamp_mode,
            "--show-metadata",
            "-f",
            str(input_pcap),
            str(mountpoint),
        ]

    raise ValueError(f"Unsupported tool: {tool}")


def format_command_template(template, input_pcap, mountpoint):
    return shlex.split(
        template.format(
            pcap=str(input_pcap),
            input_pcap=str(input_pcap),
            mountpoint=str(mountpoint),
            mount=str(mountpoint),
        )
    )


def run_mounted_tool_runtime(
    tool,
    input_pcap,
    ground_truth,
    mountpoint,
    out_dir,
    timeout=300.0,
    timestamp_mode="network",
    reader="streaming",
    scenario_dir=None,
    command_template=None,
):
    tool = tool.lower()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    mountpoint = Path(mountpoint)
    mountpoint.mkdir(parents=True, exist_ok=True)

    profile_json = out_dir / "internal_profile.json"
    log_path = out_dir / f"{tool}.log"
    export_dir = out_dir / "exported"

    command = (
        format_command_template(command_template, input_pcap, mountpoint)
        if command_template
        else default_tool_command(
            tool, input_pcap, mountpoint, profile_json, timestamp_mode, reader
        )
    )

    proc = None
    started_at = now_iso()
    start = time.perf_counter()

    try:
        with open(log_path, "wb") as log:
            proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)

        if not wait_for_mount_ready(mountpoint, proc=proc, timeout=timeout):
            runtime = build_timeout_runtime(tool, timeout)
            if proc and proc.poll() is not None:
                runtime = build_failed_runtime(
                    tool,
                    f"process exited before mount-ready; see {log_path}",
                )
            runtime["started_at"] = started_at
            runtime["finished_at"] = now_iso()
            runtime["command"] = command
            write_json(runtime, out_dir / "runtime.json")
            return runtime

        start_to_mount_ready = time.perf_counter() - start

        t0 = time.perf_counter()
        export_mounted_filesystem(mountpoint, export_dir)
        export_seconds = time.perf_counter() - t0

        t0 = time.perf_counter()
        hash_manifest = hash_exported_files(export_dir)
        hash_seconds = time.perf_counter() - t0
        write_json(hash_manifest, out_dir / "hash_manifest.json")

        prediction = normalized_from_hash_manifest(
            hash_manifest,
            tool=tool,
            scenario_dir=scenario_dir,
        )
        write_json(prediction, out_dir / "normalized.json")

        gt = load_json(ground_truth)
        t0 = time.perf_counter()
        metrics = score_versions(gt, prediction)
        scoring_seconds = time.perf_counter() - t0
        write_json(metrics, out_dir / "metrics.json")

        post_mount = export_seconds + hash_seconds + scoring_seconds
        external = {
            "start_to_mount_ready_seconds": start_to_mount_ready,
            "export_seconds": export_seconds,
            "hash_seconds": hash_seconds,
            "scoring_seconds": scoring_seconds,
            "post_mount_seconds": post_mount,
            "end_to_end_seconds": start_to_mount_ready + post_mount,
        }

        internal = None
        if tool == "smbmount" and profile_json.exists():
            internal = load_json(profile_json)

        runtime = {
            "tool": tool,
            "status": "success",
            "started_at": started_at,
            "finished_at": now_iso(),
            "mount_ready": True,
            "command": command,
            "external": external,
            "internal": internal,
            "correctness": {
                "strict_path_content_f1": metrics.get(
                    "strict_path_content", {}
                ).get("f1")
            },
        }
        write_json(runtime, out_dir / "runtime.json")
        return runtime
    except Exception as exc:
        runtime = build_failed_runtime(tool, str(exc))
        runtime["started_at"] = started_at
        runtime["finished_at"] = now_iso()
        runtime["command"] = command
        write_json(runtime, out_dir / "runtime.json")
        return runtime
    finally:
        if proc is not None:
            terminate_process(proc)
        unmount(mountpoint)


def comparable_speedup(smbmount_runtime, pcapfs_runtime):
    result = {}
    if (
        smbmount_runtime.get("status") != "success"
        or pcapfs_runtime.get("status") != "success"
    ):
        return result

    smb_external = smbmount_runtime.get("external") or {}
    pcap_external = pcapfs_runtime.get("external") or {}

    for key in COMPARABLE_METRICS:
        smb_time = smb_external.get(key)
        pcap_time = pcap_external.get(key)
        if smb_time and pcap_time:
            result[key] = pcap_time / smb_time

    return result


def compare_runtime_files(smbmount_runtime_path, pcapfs_runtime_path, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    smbmount_runtime = load_json(smbmount_runtime_path)
    pcapfs_runtime = load_json(pcapfs_runtime_path)
    speedups = comparable_speedup(smbmount_runtime, pcapfs_runtime)

    comparison = {
        "smbmount": smbmount_runtime,
        "pcapfs": pcapfs_runtime,
        "speedup_formula": "pcapfs_time / smbmount_time",
        "speedups": speedups,
        "note": (
            "Speedups are computed only for comparable external milestones. "
            "Internal SMBmount phases are not compared with pcapFS black-box time."
        ),
    }
    write_json(comparison, out_dir / "runtime_comparison.json")
    write_runtime_markdown(comparison, out_dir / "runtime_comparison.md")
    return comparison


def seconds(value):
    if value is None:
        return "n/a"
    return f"{float(value):.6f}s"


def speedup_text(value):
    if value is None:
        return "n/a"
    return f"{float(value):.2f}x"


def write_runtime_markdown(comparison, path):
    smb_external = (comparison.get("smbmount", {}).get("external") or {})
    pcap_external = (comparison.get("pcapfs", {}).get("external") or {})
    speedups = comparison.get("speedups") or {}

    labels = {
        "start_to_mount_ready_seconds": "Start -> mount ready",
        "export_seconds": "Export",
        "hash_seconds": "Hash",
        "scoring_seconds": "Scoring",
        "post_mount_seconds": "Post-mount",
        "end_to_end_seconds": "End-to-end",
    }

    lines = [
        "# Runtime comparison",
        "",
        "| Phase | SMBmount | pcapFS | Speedup |",
        "|---|---:|---:|---:|",
    ]

    for key in COMPARABLE_METRICS:
        lines.append(
            f"| {labels[key]} | {seconds(smb_external.get(key))} | "
            f"{seconds(pcap_external.get(key))} | {speedup_text(speedups.get(key))} |"
        )

    internal = comparison.get("smbmount", {}).get("internal")
    if internal:
        lines.extend([
            "",
            "## SMBmount internal profiling",
            "",
            "| SMBmount internal phase | Time |",
            "|---|---:|",
            f"| Parse | {seconds(internal.get('parse_seconds'))} |",
            f"| Reconstruct | {seconds(internal.get('reconstruct_seconds'))} |",
            f"| Mount preparation | {seconds(internal.get('mount_prepare_seconds'))} |",
            f"| Internal total | {seconds(internal.get('internal_total_seconds'))} |",
        ])

    lines.extend([
        "",
        "Speedup formula: `pcapfs_time / smbmount_time`.",
        "No pcapFS internal parse/reconstruct time is inferred.",
    ])

    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Comparable parse-pcap runtime benchmark.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_run_args(p):
        p.add_argument("--pcap", required=True)
        p.add_argument("--ground-truth", required=True)
        p.add_argument("--mountpoint", required=True)
        p.add_argument("--out", required=True)
        p.add_argument(
            "--timeout",
            type=float,
            default=300.0,
            help="Mount-ready timeout in seconds. Use 0 to wait indefinitely.",
        )
        p.add_argument("--timestamp-mode", default="network")
        p.add_argument("--reader", default="streaming", choices=["streaming", "legacy"])
        p.add_argument("--scenario-dir", default=None)
        p.add_argument("--command-template", default=None)

    p_smb = sub.add_parser("run-smbmount")
    add_run_args(p_smb)

    p_pcapfs = sub.add_parser("run-pcapfs")
    add_run_args(p_pcapfs)

    p_compare = sub.add_parser("compare")
    p_compare.add_argument("--smbmount-runtime", required=True)
    p_compare.add_argument("--pcapfs-runtime", required=True)
    p_compare.add_argument("--out", required=True)

    args = parser.parse_args(argv)

    if args.command in ("run-smbmount", "run-pcapfs"):
        tool = "smbmount" if args.command == "run-smbmount" else "pcapfs"
        runtime = run_mounted_tool_runtime(
            tool=tool,
            input_pcap=args.pcap,
            ground_truth=args.ground_truth,
            mountpoint=args.mountpoint,
            out_dir=args.out,
            timeout=args.timeout,
            timestamp_mode=args.timestamp_mode,
            reader=args.reader,
            scenario_dir=args.scenario_dir,
            command_template=args.command_template,
        )
        print(json.dumps(runtime, indent=2, ensure_ascii=False))
        return 0 if runtime.get("status") == "success" else 1

    compare_runtime_files(
        args.smbmount_runtime,
        args.pcapfs_runtime,
        args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
