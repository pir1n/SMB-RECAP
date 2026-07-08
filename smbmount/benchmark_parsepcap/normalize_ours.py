import json
from pathlib import Path


def norm_path(path):
    if not path:
        return "unknown"
    return str(path).replace("/", "\\").strip("\\")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def merge_renamed_files(normalized):
    files = normalized.get("files", [])
    by_path = {f["path"]: f for f in files}

    rename_pairs = []

    for f in files:
        for e in f.get("events", []):
            if e.get("op") == "rename" and e.get("old_path") and e.get("new_path"):
                rename_pairs.append((e["old_path"], e["new_path"]))

    for old_path, new_path in rename_pairs:
        old_item = by_path.get(old_path)
        new_item = by_path.get(new_path)

        if not old_item:
            continue

        # Nếu chưa có object path mới thì tạo object mới.
        if not new_item:
            new_item = {
                "path": new_path,
                "is_dir": old_item.get("is_dir", False),
                "deleted": old_item.get("deleted", False),
                "object_type": old_item.get("object_type"),
                "reconstruction_state": old_item.get("reconstruction_state"),
                "semantic_summary": old_item.get("semantic_summary"),
                "versions": [],
                "events": [],
                "path_history": [],
            }
            files.append(new_item)
            by_path[new_path] = new_item

        # Move versions từ old path sang new path.
        if old_item.get("versions"):
            if not new_item.get("versions"):
                new_item["versions"] = old_item["versions"]
            else:
                new_item["versions"].extend(old_item["versions"])

            old_item["versions"] = []

        # Reindex version number.
        for idx, v in enumerate(new_item.get("versions", [])):
            v["version"] = idx

        # Gộp event và path history.
        new_item.setdefault("events", [])
        new_item.setdefault("path_history", [])

        for event in old_item.get("events", []):
            if event not in new_item["events"]:
                new_item["events"].append(event)

        if old_path not in new_item["path_history"]:
            new_item["path_history"].append(old_path)

        if new_path not in new_item["path_history"]:
            new_item["path_history"].append(new_path)

    normalized["files"] = [
        f for f in files
        if (
            f.get("versions")
            or f.get("is_dir")
            or f.get("deleted")
            or f.get("reconstruction_state") in ("hollow", "partial")
            or f.get("events")
        )
    ]

    # Rebuild top-level events.
    normalized["events"] = [
        event
        for file_item in normalized["files"]
        for event in file_item.get("events", [])
    ]

    return normalized

def normalize_ours(input_json_path):
    """
    Convert output của smbmount parse-pcap về common benchmark schema.
    """
    data = load_json(input_json_path)

    normalized_files = []

    for item in data.get("files", []):
        path = norm_path(item.get("path"))

        # versions = []
        # for v in item.get("versions", []):
        #     metadata = v.get("metadata") or {}

        #     versions.append({
        #         "version": int(v.get("version", 0)),
        #         "op": v.get("op"),
        #         "md5": v.get("md5") or v.get("hash"),
        #         "size": metadata.get("size"),
        #         "metadata": metadata,
        #     })

        versions = []

        for v in item.get("versions", []):
            metadata = v.get("metadata") or {}
            op = v.get("op")

            reconstruction_state = v.get("reconstruction_state")

            # Partial/hollow evidence vẫn tồn tại trong JSON gốc,
            # nhưng không được chấm như full content version.
            if reconstruction_state in ("partial", "hollow"):
                continue

            # Tương thích với output cũ chỉ có observed_complete.
            if op in ("read", "observed_read"):
                if v.get("observed_complete") is False:
                    continue

            version_kind = v.get("version_kind")

            if version_kind is None:
                if op in ("read", "observed_read"):
                    version_kind = "observed"
                elif op in ("write", "truncate", "append", "overwrite"):
                    version_kind = "mutation"
                else:
                    version_kind = "content"

            versions.append({
                "version": len(versions),
                "op": op,
                "version_kind": version_kind,
                "reconstruction_state": reconstruction_state,
                "md5": v.get("md5") or v.get("hash"),
                "size": metadata.get("size"),
                "metadata": metadata,
            })

        events = []
        for e in item.get("events", []):
            events.append({
                "op": e.get("op"),
                "path": norm_path(e.get("path") or path),
                "old_path": norm_path(e.get("old_path")) if e.get("old_path") else None,
                "new_path": norm_path(e.get("new_path")) if e.get("new_path") else None,
                "timestamp": e.get("timestamp"),
                "frame_number": e.get("frame_number"),
                "smb_command": e.get("smb_command"),
            })

        normalized_files.append({
            "path": path,
            "is_dir": bool(item.get("is_dir", False)),
            "deleted": bool(item.get("deleted", False)),
            "object_type": item.get("object_type"),
            "reconstruction_state": item.get("reconstruction_state"),
            "semantic_summary": item.get("semantic_summary"),
            "versions": versions,
            "events": events,
        })

    result = {
        "tool": "smbmount",
        "files": normalized_files,
        "events": [
            event
            for file_item in normalized_files
            for event in file_item.get("events", [])
        ],
    }

    return merge_renamed_files(result)


def write_normalized_ours(input_json_path, output_json_path):
    result = normalize_ours(input_json_path)

    output_path = Path(output_json_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return result