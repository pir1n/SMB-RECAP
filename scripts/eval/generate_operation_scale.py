#!/usr/bin/env python3
import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from common import ensure_dir, posix_join, write_json, write_jsonl
from generate_ops import content_for, content_hash_for


OPERATIONS = [
    "Create Directory",
    "Create File",
    "Upload file",
    "Download file",
    "View File",
    "List Directory",
    "Rename Directory",
    "Move Directory",
    "rename File",
    "Move file",
    "Append to File",
    "Remove Directory",
    "Remove File",
]

CLIENTS = {"cmd", "powershell", "smbclient"}
NONZERO_SIZES = [128, 4096, 65536, 1048576]


def slug(value):
    output = []
    for ch in value.lower():
        if ch.isalnum():
            output.append(ch)
        else:
            output.append("_")
    text = "".join(output).strip("_")
    while "__" in text:
        text = text.replace("__", "_")
    return text


def default_run_id(client, profile):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{client}_{profile}_{stamp}"


def file_size_for(run_id, op_id, operation):
    if operation not in {"Upload file", "Append to File"}:
        return 0
    digest = hashlib.sha256(f"{run_id}:{op_id}:{operation}".encode("utf-8")).digest()
    return NONZERO_SIZES[digest[0] % len(NONZERO_SIZES)]


class OperationBuilder:
    def __init__(self, client, run_id):
        self.client = client
        self.run_id = run_id
        self.root = run_id
        self.setup_id = 900000000
        self.setup_keys = set()

    def setup_op(self, event, path, *, target_path=None, variant="setup", file_size=128):
        self.setup_id += 1
        content = content_for(self.run_id, self.setup_id, file_size)
        return {
            "run_id": self.run_id,
            "op_id": self.setup_id,
            "client": self.client,
            "event": event,
            "operation": "setup",
            "operation_name": "setup",
            "path": path,
            "target_path": target_path,
            "status": "success",
            "start_time": None,
            "end_time": None,
            "command": None,
            "file_size": file_size if event in {"write_file", "upload_file", "append_file", "overwrite_file"} else 0,
            "content_hash": content_hash_for(self.run_id, self.setup_id, file_size) if event in {"write_file", "upload_file", "append_file", "overwrite_file"} else content_hash_for(self.run_id, self.setup_id, 0),
            "content_sample": content if event in {"write_file", "upload_file", "append_file", "overwrite_file"} else "",
            "operation_variant": variant,
            "log_ground_truth": True,
        }

    def measured_op(self, op_id, operation, event, path, *, target_path=None, variant="default", file_size=0, **extra):
        content = content_for(self.run_id, op_id, file_size)
        row = {
            "run_id": self.run_id,
            "op_id": op_id,
            "client": self.client,
            "event": event,
            "operation": operation,
            "operation_name": operation,
            "requested_operation": operation,
            "path": path,
            "target_path": target_path,
            "status": "success",
            "start_time": None,
            "end_time": None,
            "command": None,
            "file_size": file_size,
            "content_hash": content_hash_for(self.run_id, op_id, file_size),
            "content_sample": content,
            "operation_variant": variant,
            "log_ground_truth": True,
        }
        row.update(extra)
        return row

    def ensure_root(self):
        return self.ensure_directory(self.root)

    def ensure_directory(self, path):
        if path in self.setup_keys:
            return []
        self.setup_keys.add(path)
        return [self.setup_op("create_directory", path)]

    def ensure_file(self, path, file_size=128):
        if path in self.setup_keys:
            return []
        self.setup_keys.add(path)
        return [self.setup_op("upload_file", path, file_size=file_size)]

    def stage_local_source_from_server(self, path):
        setup = self.ensure_file(path)
        download_setup = self.setup_op("download_file", path, variant="setup_local_source")
        setup.append(download_setup)
        return setup, download_setup["op_id"]

    def build(self, op_id, operation, index):
        prefix = posix_join(self.root, f"{slug(operation)}_{index:06d}")
        setup = self.ensure_root()

        if operation == "Create Directory":
            path = prefix
            return setup, self.measured_op(op_id, operation, "create_directory", path)

        if operation == "Create File":
            path = f"{prefix}.dat"
            return setup, self.measured_op(op_id, operation, "create_file", path)

        if operation == "Upload file":
            path = f"{prefix}.dat"
            seed_path = f"{prefix}_server_seed.dat"
            size = file_size_for(self.run_id, op_id, operation)
            staged_setup, local_source_op_id = self.stage_local_source_from_server(seed_path)
            setup += staged_setup
            return setup, self.measured_op(
                op_id,
                operation,
                "upload_file",
                path,
                variant="upload",
                file_size=size,
                local_source_op_id=local_source_op_id,
            )

        if operation == "Download file":
            path = f"{prefix}.dat"
            setup += self.ensure_file(path)
            return setup, self.measured_op(op_id, operation, "download_file", path, variant="download")

        if operation == "View File":
            path = f"{prefix}.dat"
            setup += self.ensure_file(path)
            return setup, self.measured_op(op_id, operation, "read_file", path, variant="view")

        if operation == "List Directory":
            path = prefix
            setup += self.ensure_directory(path)
            setup += self.ensure_file(posix_join(path, "entry.txt"))
            return setup, self.measured_op(op_id, operation, "directory_listing", path)

        if operation == "Rename Directory":
            path = f"{prefix}_src"
            target = f"{prefix}_renamed"
            setup += self.ensure_directory(path)
            return setup, self.measured_op(op_id, operation, "rename_file", path, target_path=target, variant="rename_directory")

        if operation == "Move Directory":
            path = f"{prefix}_src"
            target_parent = posix_join(self.root, "moved_directories")
            target = posix_join(target_parent, f"{slug(operation)}_{index:06d}")
            setup += self.ensure_directory(path)
            setup += self.ensure_directory(target_parent)
            return setup, self.measured_op(op_id, operation, "rename_file", path, target_path=target, variant="move")

        if operation == "rename File":
            path = f"{prefix}_src.dat"
            target = f"{prefix}_renamed.dat"
            setup += self.ensure_file(path)
            return setup, self.measured_op(op_id, operation, "rename_file", path, target_path=target, variant="rename_file")

        if operation == "Move file":
            path = f"{prefix}_src.dat"
            target_parent = posix_join(self.root, "moved_files")
            target = posix_join(target_parent, f"{slug(operation)}_{index:06d}.dat")
            setup += self.ensure_file(path)
            setup += self.ensure_directory(target_parent)
            return setup, self.measured_op(op_id, operation, "rename_file", path, target_path=target, variant="move")

        if operation == "Append to File":
            path = f"{prefix}.dat"
            setup += self.ensure_file(path)
            size = file_size_for(self.run_id, op_id, operation)
            return setup, self.measured_op(op_id, operation, "append_file", path, variant="append", file_size=size)

        if operation == "Remove Directory":
            path = prefix
            setup += self.ensure_directory(path)
            return setup, self.measured_op(op_id, operation, "delete_directory", path)

        if operation == "Remove File":
            path = f"{prefix}.dat"
            setup += self.ensure_file(path)
            return setup, self.measured_op(op_id, operation, "delete_file", path)

        raise ValueError(f"unsupported operation: {operation}")


def generate(client, run_id, count_per_operation):
    builder = OperationBuilder(client, run_id)
    plan_rows = []
    expected_rows = []
    op_id = 0

    for index in range(1, count_per_operation + 1):
        for operation in OPERATIONS:
            op_id += 1
            setup_rows, measured = builder.build(op_id, operation, index)
            plan_rows.extend(setup_rows)
            plan_rows.append(measured)
            expected_rows.extend(setup_rows)
            expected_rows.append(measured)

    return plan_rows, expected_rows


def render_workload(client, plan_path, out_dir, args):
    if client == "cmd":
        from render_cmd import render

        from common import read_jsonl

        plan = read_jsonl(plan_path)
        run_id = plan[0]["run_id"] if plan else Path(plan_path).stem
        out_file = Path(out_dir) / "workloads" / "cmd" / f"{run_id}.cmd"
        render(plan, out_file, args.drive, stop_on_error=not args.continue_on_error)
        return [out_file]

    if client == "powershell":
        from render_powershell import render

        from common import read_jsonl

        plan = read_jsonl(plan_path)
        run_id = plan[0]["run_id"] if plan else Path(plan_path).stem
        out_file = Path(out_dir) / "workloads" / "powershell" / f"{run_id}.ps1"
        render(plan, out_file, args.drive, stop_on_error=not args.continue_on_error)
        return [out_file]

    if client == "smbclient":
        from render_smbclient import render

        from common import read_jsonl

        plan = read_jsonl(plan_path)
        run_id = plan[0]["run_id"] if plan else Path(plan_path).stem
        workload_dir = Path(out_dir) / "workloads" / "smbclient"
        script_path = workload_dir / f"{run_id}.sh"
        commands_path = workload_dir / f"{run_id}.smbclient"
        render(
            plan=plan,
            out_script=script_path,
            out_commands=commands_path,
            server=args.server,
            share=args.share,
            auth_file=args.auth_file,
            local_dir=args.local_dir,
            stop_on_error=not args.continue_on_error,
        )
        return [script_path, commands_path]

    raise ValueError(f"unsupported client: {client}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate scale plans with an equal number of each requested SMB operation."
    )
    parser.add_argument("--client", choices=sorted(CLIENTS), required=True)
    parser.add_argument("--count-per-operation", type=int, help="Number of measured rows for each operation.")
    parser.add_argument("--profile", default="operation_scale")
    parser.add_argument("--run-id")
    parser.add_argument("--out-dir", default="data/eval/generated")
    parser.add_argument("--render", action="store_true", help="Also render the workload script for the selected client.")
    parser.add_argument("--drive", default="Z", help="Mapped drive for cmd/powershell render.")
    parser.add_argument("--server", default="SERVER", help="smbclient server name or IP.")
    parser.add_argument("--share", default="SMB_EVAL", help="smbclient share name.")
    parser.add_argument("--auth-file", default="", help="smbclient auth file path.")
    parser.add_argument("--local-dir", default="/tmp/smbmount_scf_eval", help="Local data dir for smbclient render.")
    parser.add_argument("--continue-on-error", action="store_true")
    args = parser.parse_args()

    if args.count_per_operation is None:
        raw = input("count-per-operation: ").strip()
        args.count_per_operation = int(raw)

    if args.count_per_operation <= 0:
        raise SystemExit("--count-per-operation must be positive")

    run_id = args.run_id or default_run_id(args.client, args.profile)
    out_dir = Path(args.out_dir)
    plan_dir = out_dir / "plans"
    expected_dir = out_dir / "ground_truth_expected"
    manifest_dir = out_dir / "manifests"
    for directory in [plan_dir, expected_dir, manifest_dir]:
        ensure_dir(directory)

    plan_rows, expected_rows = generate(args.client, run_id, args.count_per_operation)

    plan_path = plan_dir / f"{run_id}.jsonl"
    expected_path = expected_dir / f"{run_id}.expected.jsonl"
    manifest_path = manifest_dir / f"{run_id}.json"

    write_jsonl(plan_path, plan_rows)
    write_jsonl(expected_path, expected_rows)

    rendered = []
    if args.render:
        rendered = [str(path.as_posix()) for path in render_workload(args.client, plan_path, out_dir, args)]

    write_json(
        manifest_path,
        {
            "run_id": run_id,
            "client": args.client,
            "profile": args.profile,
            "count_per_operation": args.count_per_operation,
            "measured_operation_count": len(OPERATIONS) * args.count_per_operation,
            "ground_truth_operation_count": len(expected_rows),
            "operation_count": len(expected_rows),
            "plan_operation_count": len(plan_rows),
            "operations": OPERATIONS,
            "plan": str(plan_path.as_posix()),
            "expected_ground_truth": str(expected_path.as_posix()),
            "actual_ground_truth": str((out_dir / "ground_truth" / f"{run_id}.jsonl").as_posix()),
            "pcap": str((Path("data/eval/pcaps") / f"{run_id}.pcapng").as_posix()),
            "rendered_workloads": rendered,
        },
    )

    print(f"run_id: {run_id}")
    print(f"measured operations: {len(OPERATIONS) * args.count_per_operation}")
    print(f"ground truth operations including setup: {len(expected_rows)}")
    print(f"plan rows including setup: {len(plan_rows)}")
    print(f"plan: {plan_path}")
    print(f"expected ground truth: {expected_path}")
    print(f"manifest: {manifest_path}")
    for path in rendered:
        print(f"workload: {path}")


if __name__ == "__main__":
    main()
