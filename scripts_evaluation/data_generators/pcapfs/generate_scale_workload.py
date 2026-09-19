#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import random
import time
from pathlib import Path


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def deterministic_bytes(label: str, size: int) -> bytes:
    """
    Sinh bytes deterministic theo label để ground truth ổn định giữa các lần chạy.
    """
    out = bytearray()
    counter = 0

    while len(out) < size:
        block = hashlib.sha256(f"{label}:{counter}".encode()).digest()
        out.extend(block)
        counter += 1

    return bytes(out[:size])


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


def smb_rel_path(scenario_dir: str, *parts: str) -> str:
    return "\\".join([scenario_dir, *parts])


def posix_path(root: Path, *parts: str) -> Path:
    return root.joinpath(*parts)


def main():
    parser = argparse.ArgumentParser(
        description="Generate SMB scale workload and ground truth JSON."
    )

    parser.add_argument(
        "--mount-root",
        required=True,
        help="SMB share mountpoint, ví dụ /mnt/smbbench",
    )

    parser.add_argument(
        "--ground-truth",
        required=True,
        help="Output ground truth JSON.",
    )

    parser.add_argument(
        "--scenario-id",
        default="scale_100_mixed",
    )

    parser.add_argument(
        "--scenario-dir",
        default="bench_scale_100_mixed",
    )

    parser.add_argument(
        "--files",
        type=int,
        default=100,
        help="Số file cần tạo, ví dụ 20, 100, 200.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.03,
        help="Delay giữa các thao tác. Scale benchmark nên nhỏ hơn multi nhỏ.",
    )

    parser.add_argument(
        "--dir-count",
        type=int,
        default=10,
        help="Số directory cấp 1.",
    )

    parser.add_argument(
        "--min-size",
        type=int,
        default=256,
    )

    parser.add_argument(
        "--max-size",
        type=int,
        default=4096,
    )

    parser.add_argument(
        "--large-every",
        type=int,
        default=25,
        help="Cứ N file thì tạo một file lớn. 0 để tắt.",
    )

    parser.add_argument(
        "--large-size",
        type=int,
        default=512 * 1024,
        help="Kích thước file lớn.",
    )

    parser.add_argument(
        "--append-every",
        type=int,
        default=1,
        help="Cứ N file thì append. Default 1 nghĩa là file nào cũng append.",
    )

    parser.add_argument(
        "--overwrite-every",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--truncate-every",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--rename-every",
        type=int,
        default=7,
    )

    parser.add_argument(
        "--delete-every",
        type=int,
        default=11,
    )

    args = parser.parse_args()

    rng = random.Random(args.seed)

    mount_root = Path(args.mount_root)
    scenario_root = mount_root / args.scenario_dir

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
    # 1. mkdir scenario dirs
    # =========================
    scenario_root.mkdir(parents=True, exist_ok=False)
    add_event("mkdir", args.scenario_dir)
    sleep_step(args.delay)

    created_dirs = set()

    def ensure_smb_dir(*parts: str):
        cur = []

        for part in parts:
            cur.append(part)
            key = tuple(cur)

            if key in created_dirs:
                continue

            p = posix_path(scenario_root, *cur)
            p.mkdir(parents=True, exist_ok=True)

            add_event(
                "mkdir",
                smb_rel_path(args.scenario_dir, *cur),
            )

            created_dirs.add(key)
            sleep_step(args.delay)

    for i in range(args.dir_count):
        ensure_smb_dir(f"dir_{i:02d}")

    # Một vài empty dir để test rmdir.
    empty_dirs = []

    for i in range(3):
        dirname = f"empty_{i:02d}"
        ensure_smb_dir(dirname)
        empty_dirs.append(dirname)

    # =========================
    # 2. generate files
    # =========================
    gt_files = []

    for i in range(args.files):
        dir_name = f"dir_{i % args.dir_count:02d}"
        sub_name = f"sub_{(i // args.dir_count) % 4:02d}"

        ensure_smb_dir(dir_name, sub_name)

        original_name = f"file_{i:04d}.bin"
        final_name = original_name

        rel_parts = [dir_name, sub_name, original_name]
        current_path = posix_path(scenario_root, *rel_parts)
        current_rel = smb_rel_path(args.scenario_dir, *rel_parts)

        versions = []
        path_history = [current_rel]
        deleted = False

        # Size deterministic nhưng có random phân bố.
        if args.large_every > 0 and i % args.large_every == 0:
            initial_size = args.large_size
        else:
            initial_size = rng.randint(args.min_size, args.max_size)

        data = bytearray(
            deterministic_bytes(
                f"{args.scenario_id}:file:{i}:v0",
                initial_size,
            )
        )

        # Initial write.
        fsync_write(current_path, bytes(data), "wb")
        add_event("append", current_rel)
        versions.append(version(len(versions), "write", bytes(data)))
        sleep_step(args.delay)

        # Append.
        if args.append_every > 0 and i % args.append_every == 0:
            append_size = max(16, min(512, max(16, initial_size // 8)))
            append_data = deterministic_bytes(
                f"{args.scenario_id}:file:{i}:append",
                append_size,
            )

            fsync_write(current_path, append_data, "ab")
            data.extend(append_data)

            add_event("append", current_rel)
            versions.append(version(len(versions), "append", bytes(data)))
            sleep_step(args.delay)

        # Overwrite.
        if args.overwrite_every > 0 and i % args.overwrite_every == 0:
            patch_size = max(8, min(128, len(data) // 10))

            # Đổi offset để test cả overwrite đầu file và giữa file.
            if i % 2 == 0:
                patch_offset = 0
            else:
                patch_offset = max(0, len(data) // 3)

            patch_data = deterministic_bytes(
                f"{args.scenario_id}:file:{i}:overwrite",
                patch_size,
            )

            fsync_write(
                current_path,
                patch_data,
                "r+b",
                offset=patch_offset,
            )

            data[patch_offset:patch_offset + patch_size] = patch_data

            add_event(
                "overwrite",
                current_rel,
                offset=patch_offset,
                length=patch_size,
            )

            versions.append(version(len(versions), "overwrite", bytes(data)))
            sleep_step(args.delay)

        # Truncate.
        if args.truncate_every > 0 and i % args.truncate_every == 0:
            if len(data) > 64:
                new_size = max(32, len(data) // 2)

                fsync_truncate(current_path, new_size)
                data = data[:new_size]

                add_event(
                    "truncate",
                    current_rel,
                    size=new_size,
                )

                versions.append(version(len(versions), "truncate", bytes(data)))
                sleep_step(args.delay)

        # Rename.
        if args.rename_every > 0 and i % args.rename_every == 0:
            final_name = f"file_{i:04d}_final.bin"
            new_rel_parts = [dir_name, sub_name, final_name]
            new_path = posix_path(scenario_root, *new_rel_parts)
            new_rel = smb_rel_path(args.scenario_dir, *new_rel_parts)

            os.rename(current_path, new_path)

            add_event(
                "rename",
                new_rel,
                old_path=current_rel,
                new_path=new_rel,
            )

            current_path = new_path
            current_rel = new_rel
            path_history.append(new_rel)

            sleep_step(args.delay)

        # Delete.
        if args.delete_every > 0 and i % args.delete_every == 0:
            os.remove(current_path)
            deleted = True

            add_event("delete", current_rel)
            sleep_step(args.delay)

        gt_files.append({
            "path": current_rel,
            "is_dir": False,
            "deleted": deleted,
            "path_history": path_history,
            "versions": versions,
        })

    # =========================
    # 3. rmdir empty dirs
    # =========================
    for dirname in empty_dirs:
        p = scenario_root / dirname

        try:
            os.rmdir(p)
            add_event(
                "rmdir",
                smb_rel_path(args.scenario_dir, dirname),
            )

            gt_files.append({
                "path": smb_rel_path(args.scenario_dir, dirname),
                "is_dir": True,
                "deleted": True,
                "versions": [],
            })

            sleep_step(args.delay)
        except OSError:
            # Nếu vì lý do nào đó không rỗng thì bỏ qua.
            pass

    ground_truth = {
        "scenario_id": args.scenario_id,
        "scenario_dir": args.scenario_dir,
        "parameters": {
            "files": args.files,
            "seed": args.seed,
            "dir_count": args.dir_count,
            "min_size": args.min_size,
            "max_size": args.max_size,
            "large_every": args.large_every,
            "large_size": args.large_size,
            "append_every": args.append_every,
            "overwrite_every": args.overwrite_every,
            "truncate_every": args.truncate_every,
            "rename_every": args.rename_every,
            "delete_every": args.delete_every,
        },
        "files": gt_files,
        "events": events,
    }

    gt_path = Path(args.ground_truth)
    gt_path.parent.mkdir(parents=True, exist_ok=True)

    with gt_path.open("w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)

    expected_versions = sum(
        len(item.get("versions", []))
        for item in gt_files
        if not item.get("is_dir")
    )

    print(f"[OK] Scenario generated at: {scenario_root}")
    print(f"[OK] Ground truth written to: {gt_path}")
    print(f"[OK] Files: {args.files}")
    print(f"[OK] Expected content versions: {expected_versions}")
    print(f"[OK] Events: {len(events)}")


if __name__ == "__main__":
    main()