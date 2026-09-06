#!/usr/bin/env python3
"""Convert manually recorded File Explorer actions to SCF scoring JSONL.

The mapping is behavior-based and contains no capture-specific names or paths.
"""

import argparse
import json
import re
from pathlib import Path


EVENT_MAP = {
    "navigate_to_share": "directory_listing",
    "navigate_folder": "directory_listing",
    "refresh_folder": "directory_listing",
    "create_folder_on_share": "create_directory",
    "create_file_on_share": "create_file",
    "copy_file_to_share": "upload_file",
    "copy_file_from_share": "download_file",
    # An intra-share copy has the same destination-side SMB create/write
    # behavior as an upload; SCF cannot observe the local UI clipboard intent.
    "copy_file_within_share": "upload_file",
    "open_file_from_share": "read_file",
    "view_file_properties": "read_file",
    "edit_file_content": "write_file",
    "rename_file_on_share": "rename_file",
    "move_file_within_share": "rename_file",
    "move_files_within_share": "rename_file",
    "delete_file_on_share": "delete_file",
}


def share_relative(value):
    if not value:
        return None
    text = str(value).replace("/", "\\")
    if re.match(r"^[A-Za-z]:\\", text):
        return None
    if text.startswith("\\\\"):
        parts = [part for part in text.split("\\") if part]
        return "\\".join(parts[2:]) if len(parts) > 2 else ""
    return text.strip("\\")


def convert(row, run_id):
    op_type = row.get("op_type")
    event = EVENT_MAP.get(op_type)
    if event is None or row.get("result") != "success":
        return None
    source = share_relative(row.get("source"))
    destination = share_relative(row.get("destination"))
    if event in {"create_file", "create_directory", "upload_file"}:
        path, target_path = destination, None
    elif event == "rename_file":
        path, target_path = source, destination
    elif event == "directory_listing":
        path, target_path = destination, None
    else:
        path, target_path = source if source is not None else destination, None
    return {
        "run_id": run_id,
        "op_id": row.get("op_id"),
        "client": "file_explorer",
        "event": event,
        "path": path,
        "target_path": target_path,
        "start_time": row.get("start_time"),
        "end_time": row.get("end_time"),
        "source_op_type": op_type,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_jsonl")
    parser.add_argument("output_jsonl")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    output = []
    with open(args.input_jsonl, encoding="utf-8-sig") as stream:
        for line in stream:
            if line.strip():
                item = convert(json.loads(line), args.run_id)
                if item:
                    output.append(item)
    target = Path(args.output_jsonl)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as stream:
        for item in output:
            stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"Wrote {len(output)} actions to {target}")


if __name__ == "__main__":
    main()
