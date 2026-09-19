#!/usr/bin/env python3
"""Compare untouched FKIE text output with untouched SMBmount timeline JSON."""

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path


FKIE_LINE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<ip>\S+)\s+\[(?P<app>[^]]+)]\s+(?P<message>.*)$"
)


def clean_path(value):
    if value is None:
        return None
    return str(value).strip().replace("\\", "/").strip("/").casefold()


def classify_fkie(message):
    prefixes = {
        "Creation of directory ": "create_directory",
        "Creation of file ": "create_file",
        "View file ": "read_file",
        "Read file ": "read_file",
        "Listing contents of directory ": "directory_listing",
        "Deletion of directory ": "delete_directory",
        "Deletion of file ": "delete_file",
        "Copied file to server ": "upload_file",
        "Copied file from server ": "download_file",
        "Appended to file ": "append_file",
    }
    for prefix, action in prefixes.items():
        if message.startswith(prefix):
            return action, message[len(prefix):], None

    moved = re.match(r"^(?:Moved|Renamed) (?:file|directory) (.+?) to (.+)$", message)
    if moved:
        source, target = moved.groups()
        if "/" not in target and "\\" not in target:
            parent = source.replace("\\", "/").rsplit("/", 1)[0]
            target = f"{parent}/{target}" if parent else target
        return "rename_file", source, target
    return "unclassified", None, None


def classify_smbmount(value):
    key = re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")
    if "directory" in key and ("list" in key or "query" in key):
        return "directory_listing"
    if "upload" in key:
        return "upload_file"
    if "download" in key:
        return "download_file"
    if "append" in key:
        return "append_file"
    if "overwrite" in key:
        return "overwrite_file"
    if "rename" in key or "move" in key:
        return "rename_file"
    if "delete" in key or "deletion" in key or "remove" in key:
        return "delete_directory" if "director" in key else "delete_file"
    if "creat" in key:
        return "create_directory" if "director" in key else "create_file"
    if "read" in key or "view" in key:
        return "read_file"
    if "write" in key:
        return "write_file"
    return key or "unclassified"


def load_fkie(path):
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8-sig").splitlines(), 1):
        match = FKIE_LINE.match(line.strip())
        if not match:
            continue
        action, source, target = classify_fkie(match["message"])
        rows.append({
            "line": number,
            "timestamp_text": match["time"],
            "timestamp": datetime.fromisoformat(match["time"]).timestamp(),
            "action": action,
            "path": clean_path(source),
            "target_path": clean_path(target),
            "raw": line,
        })
    return rows


def load_smbmount(path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return [{
        "index": index,
        "timestamp": float(row["timestamp"]),
        "action": classify_smbmount(row.get("action") or row.get("rule_id")),
        "path": clean_path(row.get("path")),
        "target_path": clean_path(row.get("target_path")),
        "raw": row,
    } for index, row in enumerate(data) if row.get("success") is not False]


def same_detection(left, right, tolerance):
    if left["action"] != right["action"] or left["path"] != right["path"]:
        return False
    if left["action"] == "rename_file" and left["target_path"] != right["target_path"]:
        return False
    return abs(left["timestamp"] - right["timestamp"]) <= tolerance


def compare(fkie, smbmount, tolerance):
    used = set()
    common = []
    only_fkie = []
    for left in fkie:
        candidates = [
            (abs(left["timestamp"] - right["timestamp"]), index)
            for index, right in enumerate(smbmount)
            if index not in used and same_detection(left, right, tolerance)
        ]
        if not candidates:
            only_fkie.append(left)
            continue
        _, index = min(candidates)
        used.add(index)
        common.append((left, smbmount[index]))
    only_smbmount = [row for index, row in enumerate(smbmount) if index not in used]
    return common, only_fkie, only_smbmount


def counts(rows):
    return dict(sorted(Counter(row["action"] for row in rows).items()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fkie", required=True, help="Raw -o text produced by SCF/python/main.py")
    parser.add_argument("--smbmount", required=True, help="Raw timeline JSON produced by SMBmount")
    parser.add_argument("--output", required=True)
    parser.add_argument("--time-tolerance", type=float, default=5.0)
    args = parser.parse_args()

    fkie = load_fkie(args.fkie)
    smbmount = load_smbmount(args.smbmount)
    common, only_fkie, only_smbmount = compare(fkie, smbmount, args.time_tolerance)
    result = {
        "inputs": vars(args),
        "summary": {
            "fkie_total": len(fkie),
            "smbmount_total": len(smbmount),
            "exact_semantic_matches": len(common),
            "only_fkie": len(only_fkie),
            "only_smbmount": len(only_smbmount),
            "outputs_identical": not only_fkie and not only_smbmount,
        },
        "counts": {
            "fkie": counts(fkie),
            "smbmount": counts(smbmount),
            "only_fkie": counts(only_fkie),
            "only_smbmount": counts(only_smbmount),
        },
        "only_fkie": only_fkie,
        "only_smbmount": only_smbmount,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], ensure_ascii=False))


if __name__ == "__main__":
    main()
