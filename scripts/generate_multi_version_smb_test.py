#!/home/k9t/dacn/SMBmount/.venv/bin python
import argparse
import hashlib
import json
import os
import time
from pathlib import Path


SCENARIO_ID = "multi_file_versioning_001"
SCENARIO_DIR = "bench_multi_version_001"


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def rel_path(*parts: str) -> str:
    return "\\".join([SCENARIO_DIR, *parts])


def fsync_write(path: Path, data: bytes, mode: str = "wb", offset=None):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, mode) as f:
        if offset is not None:
            f.seek(offset)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def fsync_truncate(path: Path, size: int):
    with open(path, "r+b") as f:
        f.truncate(size)
        f.flush()
        os.fsync(f.fileno())


def sleep_step(delay: float):
    if delay > 0:
        time.sleep(delay)


def version(version_id: int, op: str, data: bytes):
    return {
        "version": version_id,
        "op": op,
        "size": len(data),
        "md5": md5_bytes(data),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mount-root",
        required=True,
        help="SMB share mountpoint, ví dụ /mnt/smbbench",
    )
    parser.add_argument(
        "--ground-truth",
        required=True,
        help="Output ground truth JSON, ví dụ data/gt/multi_version_gt.json",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.25,
        help="Delay giữa các thao tác để PCAP dễ tách event hơn",
    )
    args = parser.parse_args()

    mount_root = Path(args.mount_root)
    scenario_root = mount_root / SCENARIO_DIR

    if scenario_root.exists():
        raise SystemExit(
            f"Scenario directory already exists: {scenario_root}\n"
            "Hãy xóa nó TRƯỚC KHI start tcpdump để tránh capture noise."
        )

    events = []

    def add_event(op, path, **kwargs):
        item = {
            "op": op,
            "path": path,
        }
        item.update(kwargs)
        events.append(item)

    # =========================
    # 1. mkdir directories
    # =========================
    for dirname in ["docs", "bin", "tmp", "folder", "emptydir"]:
        p = scenario_root / dirname
        p.mkdir(parents=True, exist_ok=False)
        add_event("mkdir", rel_path(dirname))
        sleep_step(args.delay)

    # =========================
    # 2. report.txt: write -> append -> overwrite -> rename
    # =========================
    report_path = scenario_root / "docs" / "report.txt"

    report_v0 = b"alpha\n"
    fsync_write(report_path, report_v0, "wb")
    add_event("append", rel_path("docs", "report.txt"))
    sleep_step(args.delay)

    report_append = b"beta\n"
    report_v1 = report_v0 + report_append
    fsync_write(report_path, report_append, "ab")
    add_event("append", rel_path("docs", "report.txt"))
    sleep_step(args.delay)

    # overwrite "alpha" -> "ALPHA"
    overwrite_data = b"ALPHA"
    report_v2 = overwrite_data + report_v1[len(overwrite_data):]
    fsync_write(report_path, overwrite_data, "r+b", offset=0)
    add_event("overwrite", rel_path("docs", "report.txt"))
    sleep_step(args.delay)

    report_final_path = scenario_root / "docs" / "report_final.txt"
    os.rename(report_path, report_final_path)
    add_event(
        "rename",
        rel_path("docs", "report_final.txt"),
        old_path=rel_path("docs", "report.txt"),
        new_path=rel_path("docs", "report_final.txt"),
    )
    sleep_step(args.delay)

    # =========================
    # 3. notes.txt: write -> truncate
    # =========================
    notes_path = scenario_root / "docs" / "notes.txt"

    notes_v0 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
    fsync_write(notes_path, notes_v0, "wb")
    add_event("append", rel_path("docs", "notes.txt"))
    sleep_step(args.delay)

    notes_v1 = notes_v0[:10]
    fsync_truncate(notes_path, 10)
    add_event("truncate", rel_path("docs", "notes.txt"))
    sleep_step(args.delay)

    # =========================
    # 4. large.bin: large write -> overwrite at high offset
    # =========================
    large_path = scenario_root / "bin" / "large.bin"

    large_v0 = (b"BLOCK_A_" * 200000)[:1_500_000]
    fsync_write(large_path, large_v0, "wb")
    add_event("append", rel_path("bin", "large.bin"))
    sleep_step(args.delay)

    patch_offset = 1_048_576
    patch_data = b"PATCHED_AT_1MIB"
    large_v1 = bytearray(large_v0)
    large_v1[patch_offset:patch_offset + len(patch_data)] = patch_data
    large_v1 = bytes(large_v1)

    fsync_write(large_path, patch_data, "r+b", offset=patch_offset)
    add_event("overwrite", rel_path("bin", "large.bin"))
    sleep_step(args.delay)

    # =========================
    # 5. nested file
    # =========================
    nested_path = scenario_root / "folder" / "nested.txt"

    nested_v0 = b"NESTED_FILE_CONTENT\n"
    fsync_write(nested_path, nested_v0, "wb")
    add_event("append", rel_path("folder", "nested.txt"))
    sleep_step(args.delay)

    # =========================
    # 6. delete file
    # =========================
    delete_path = scenario_root / "tmp" / "delete_me.tmp"

    delete_v0 = b"DELETE_ME_CONTENT\n"
    fsync_write(delete_path, delete_v0, "wb")
    add_event("append", rel_path("tmp", "delete_me.tmp"))
    sleep_step(args.delay)

    os.remove(delete_path)
    add_event("delete", rel_path("tmp", "delete_me.tmp"))
    sleep_step(args.delay)

    # =========================
    # 7. rmdir emptydir
    # =========================
    emptydir_path = scenario_root / "emptydir"
    os.rmdir(emptydir_path)
    add_event("rmdir", rel_path("emptydir"))
    sleep_step(args.delay)

    ground_truth = {
        "scenario_id": SCENARIO_ID,
        "scenario_dir": SCENARIO_DIR,
        "files": [
            {
                "path": rel_path("docs", "report_final.txt"),
                "is_dir": False,
                "deleted": False,
                "path_history": [
                    rel_path("docs", "report.txt"),
                    rel_path("docs", "report_final.txt"),
                ],
                "versions": [
                    version(0, "write", report_v0),
                    version(1, "append", report_v1),
                    version(2, "overwrite", report_v2),
                ],
            },
            {
                "path": rel_path("docs", "notes.txt"),
                "is_dir": False,
                "deleted": False,
                "versions": [
                    version(0, "write", notes_v0),
                    version(1, "truncate", notes_v1),
                ],
            },
            {
                "path": rel_path("bin", "large.bin"),
                "is_dir": False,
                "deleted": False,
                "versions": [
                    version(0, "write", large_v0),
                    version(1, "overwrite", large_v1),
                ],
            },
            {
                "path": rel_path("folder", "nested.txt"),
                "is_dir": False,
                "deleted": False,
                "versions": [
                    version(0, "write", nested_v0),
                ],
            },
            {
                "path": rel_path("tmp", "delete_me.tmp"),
                "is_dir": False,
                "deleted": True,
                "versions": [
                    version(0, "write", delete_v0),
                ],
            },
            {
                "path": rel_path("emptydir"),
                "is_dir": True,
                "deleted": True,
                "versions": [],
            },
        ],
        "events": events,
    }

    gt_path = Path(args.ground_truth)
    gt_path.parent.mkdir(parents=True, exist_ok=True)

    with gt_path.open("w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)

    print(f"[OK] Scenario generated at: {scenario_root}")
    print(f"[OK] Ground truth written to: {gt_path}")


if __name__ == "__main__":
    main()
