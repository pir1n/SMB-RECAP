#!/usr/bin/env python3
"""Normalize untouched FKIE File Explorer text output for timeline scoring."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path


LINE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(\S+)\s+\[[^]]+]\s+(.*)$")


def clean_path(value):
    text = str(value or "").strip().replace("\\", "/")
    if text.startswith("//") and not re.match(r"^//[^/]+/SMB_LAB(?:/|$)", text, flags=re.I):
        return None
    text = re.sub(r"^//[^/]+/SMB_LAB/?", "", text, flags=re.I)
    return text.strip("/").replace("/", "\\")


def parse_message(message):
    if message.startswith("Creation of directory:"):
        return "temporary_create_directory", clean_path(message.split("->", 1)[0].split(":", 1)[1]), None
    prefixes = (
        ("Creation of file ", "create_file"),
        ("Copied file to server ", "upload_file"),
        ("Copied file from server ", "download_file"),
        ("Appending to file ", "write_file"),
        ("Deletion of file ", "delete_file"),
    )
    for prefix, event in prefixes:
        if message.startswith(prefix):
            return event, clean_path(message[len(prefix):]), None
    moved = re.match(r"Moved file (.+?) to (.+)$", message)
    if moved:
        source = clean_path(moved.group(1))
        target = clean_path(moved.group(2))
        if "\\" not in target:
            parent = source.rsplit("\\", 1)[0] if "\\" in source else ""
            target = f"{parent}\\{target}" if parent else target
        source_name = source.rsplit("\\", 1)[-1].casefold()
        if source_name == "new folder":
            return "create_directory", target, None
        if source_name == "new text document.txt":
            return "create_file", target, None
        return "rename_file", source, target
    return None, None, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_txt")
    parser.add_argument("output_json")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    rows = []
    for line in Path(args.input_txt).read_text(encoding="utf-8-sig").splitlines():
        match = LINE.match(line.strip())
        if not match:
            continue
        event, path, target = parse_message(match.group(3))
        if not event or event == "temporary_create_directory" or path is None:
            continue
        timestamp = datetime.fromisoformat(match.group(1)).timestamp()
        rows.append({
            "run_id": args.run_id,
            "timestamp": timestamp,
            "src_ip": match.group(2),
            "rule_id": f"fkie_explorer_{event}",
            "action": event,
            "path": path,
            "target_path": target,
            "success": True,
            "raw": line,
        })

    # Suppress the temporary-name create when its later rename-derived event
    # already represents the final newly-created file.
    suppressed = set()
    for idx, row in enumerate(rows):
        if row["action"] != "create_file" or row["path"].rsplit("\\", 1)[-1].casefold() != "new text document.txt":
            continue
        if any(
            other["action"] == "create_file"
            and 0 <= other["timestamp"] - row["timestamp"] <= 15
            for other in rows[idx + 1:]
        ):
            suppressed.add(idx)

    # Explorer's intra-share copy appears in FKIE as download(source),
    # upload(temporary destination), then rename(destination). Collapse it to
    # the same destination-side user behavior used by the ground truth map.
    for idx, row in enumerate(rows):
        if row["action"] != "rename_file":
            continue
        candidates = [
            (row["timestamp"] - other["timestamp"], other_idx)
            for other_idx, other in enumerate(rows[:idx])
            if other["action"] == "upload_file"
            and other["path"].casefold() == row["path"].casefold()
            and 0 <= row["timestamp"] - other["timestamp"] <= 20
        ]
        if not candidates:
            continue
        _, upload_idx = min(candidates)
        row["action"] = "upload_file"
        row["rule_id"] = "fkie_explorer_copy_within_share"
        row["path"] = row["target_path"]
        row["target_path"] = None
        suppressed.add(upload_idx)
        preceding_downloads = [
            (rows[upload_idx]["timestamp"] - other["timestamp"], other_idx)
            for other_idx, other in enumerate(rows[:upload_idx])
            if other["action"] == "download_file"
            and 0 <= rows[upload_idx]["timestamp"] - other["timestamp"] <= 2
        ]
        if preceding_downloads:
            suppressed.add(min(preceding_downloads)[1])

    rows = [row for idx, row in enumerate(rows) if idx not in suppressed]
    Path(args.output_json).write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(rows)} FKIE events to {args.output_json}")


if __name__ == "__main__":
    main()
