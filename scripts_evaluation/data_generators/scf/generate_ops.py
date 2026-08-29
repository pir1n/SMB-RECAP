#!/usr/bin/env python3
import argparse
import hashlib
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from smbmount.shared.evaluation import ensure_dir, posix_join, write_json, write_jsonl


EVENT_CYCLE = [
    "create_directory",
    "create_file",
    "write_file",
    "read_file",
    "overwrite_file",
    "rename_file",
    "directory_listing",
    "delete_file",
    "delete_directory",
]

SMALL_FILE_SIZE = 4
EXT_CYCLE = [""]


def content_for(run_id, op_id, size):
    if size <= 0:
        return ""
    seed = f"{run_id}:{op_id}:".encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()
    text = (digest + "\n") * ((size // (len(digest) + 1)) + 1)
    return text[: min(size, 4096)]


def content_hash_for(run_id, op_id, size):
    digest = hashlib.sha256(f"{run_id}:{op_id}:".encode("utf-8")).hexdigest() + "\n"
    remaining = size
    hasher = hashlib.sha256()
    while remaining > 0:
        chunk = digest[: min(len(digest), remaining)]
        hasher.update(chunk.encode("utf-8"))
        remaining -= len(chunk)
    return hasher.hexdigest()


def case_paths(case_id, style):
    base = f"c{case_id:06d}"
    directory = posix_join(base)

    stem_variants = [f"f{case_id:06d}"]
    stem = stem_variants[0]
    ext = EXT_CYCLE[case_id % len(EXT_CYCLE)]

    source = posix_join(directory, stem + ext)
    target = posix_join(directory, f"g{case_id:06d}{ext}")
    return directory, source, target


def build_operation(run_id, client, op_id, event, rng):
    case_id = ((op_id - 1) // len(EVENT_CYCLE)) + 1
    directory, source, target = case_paths(case_id, op_id % 3)
    file_size = 0
    if event in {"write_file", "overwrite_file"}:
        file_size = SMALL_FILE_SIZE
    content = content_for(run_id, op_id, file_size)

    path_by_event = {
        "create_directory": directory,
        "create_file": source,
        "write_file": source,
        "read_file": source,
        "overwrite_file": source,
        "rename_file": source,
        "directory_listing": directory,
        "delete_file": target,
        "delete_directory": directory,
    }

    return {
        "run_id": run_id,
        "op_id": op_id,
        "client": client,
        "event": event,
        "path": path_by_event[event],
        "target_path": target if event == "rename_file" else None,
        "status": "success",
        "start_time": None,
        "end_time": None,
        "command": None,
        "file_size": file_size,
        "content_hash": content_hash_for(run_id, op_id, file_size),
        "content_sample": content,
        "operation_variant": variant_for(event, op_id),
    }


def variant_for(event, op_id):
    if event == "write_file":
        return "append"
    if event == "overwrite_file":
        return "overwrite"
    if event == "rename_file":
        return "same_directory"
    if event == "directory_listing":
        return "wildcard_listing"
    return "default"


def generate(client, run_id, count, seed):
    rng = random.Random(f"{seed}:{client}:{run_id}:{count}")
    rows = []
    for op_id in range(1, count + 1):
        event = EVENT_CYCLE[(op_id - 1) % len(EVENT_CYCLE)]
        rows.append(build_operation(run_id, client, op_id, event, rng))
    return rows


def default_run_id(client, profile):
    return f"{client}_{profile}_001"


def main():
    parser = argparse.ArgumentParser(description="Generate SMB SCF evaluation operation plans.")
    parser.add_argument("--client", choices=["cmd", "powershell", "smbclient", "all"], default="all")
    parser.add_argument("--count", type=int, required=True, help="Number of operations per client.")
    parser.add_argument("--profile", default="pilot", help="Run profile name, e.g. pilot or scale.")
    parser.add_argument("--run-id", help="Run id. Only valid when --client is not all.")
    parser.add_argument("--seed", type=int, default=20260624)
    parser.add_argument("--out-dir", default="data/eval/generated")
    args = parser.parse_args()

    if args.count <= 0:
        raise SystemExit("--count must be positive")
    if args.client == "all" and args.run_id:
        raise SystemExit("--run-id can only be used with one client")

    clients = ["cmd", "powershell", "smbclient"] if args.client == "all" else [args.client]
    out_dir = Path(args.out_dir)
    plan_dir = out_dir / "plans"
    expected_dir = out_dir / "ground_truth_expected"
    manifest_dir = out_dir / "manifests"
    for directory in [plan_dir, expected_dir, manifest_dir]:
        ensure_dir(directory)

    created = []
    for client in clients:
        run_id = args.run_id or default_run_id(client, args.profile)
        rows = generate(client, run_id, args.count, args.seed)

        plan_path = plan_dir / f"{run_id}.jsonl"
        expected_path = expected_dir / f"{run_id}.expected.jsonl"
        manifest_path = manifest_dir / f"{run_id}.json"

        write_jsonl(plan_path, rows)
        write_jsonl(expected_path, rows)
        write_json(manifest_path, {
            "run_id": run_id,
            "client": client,
            "operation_count": args.count,
            "profile": args.profile,
            "seed": args.seed,
            "plan": str(plan_path.as_posix()),
            "expected_ground_truth": str(expected_path.as_posix()),
            "actual_ground_truth": str((out_dir / "ground_truth" / f"{run_id}.jsonl").as_posix()),
            "pcap": str((Path("data/eval/pcaps") / f"{run_id}.pcapng").as_posix()),
        })
        created.append(str(plan_path))

    print("Generated operation plans:")
    for path in created:
        print(f"  {path}")


if __name__ == "__main__":
    main()
