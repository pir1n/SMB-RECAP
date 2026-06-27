from collections import defaultdict

KNOWN_NAMED_PIPES = {
    "srvsvc",
    "samr",
    "lsarpc",
    "winreg",
    "wkssvc",
    "netlogon",
    "spoolss",
    "browser",
}

def normalize_scalar(value):
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    try:
        return float(value)
    except Exception:
        return str(value)


def sortable_timestamp(value):
    value = normalize_scalar(value)

    if value is None:
        return float("inf")

    try:
        return float(value)
    except Exception:
        return float("inf")

def infer_object_type(path, is_dir=False):
    if is_dir:
        return "directory"

    if path:
        normalized = path.replace("/", "\\").split("\\")[-1].lower()
        if normalized in KNOWN_NAMED_PIPES:
            return "pipe"

    return "file"

def dedupe_path_history(history):
    """
    Làm sạch path_history:
    - Convert timestamp về scalar
    - Bỏ record rỗng
    - Sort theo timestamp
    - Bỏ duplicate liên tiếp
    - Nếu path bị flip do handle phụ/context_seen, nén lại để giữ luồng đổi tên chính.
    """
    cleaned = []

    for item in history:
        if not item:
            continue

        path = item.get("path")
        if not path:
            continue

        cleaned.append({
            "timestamp": normalize_scalar(item.get("timestamp")),
            "path": path,
        })

    cleaned.sort(key=lambda x: (
        sortable_timestamp(x.get("timestamp")),
        x.get("path") or "",
    ))

    # Bỏ trùng liên tiếp
    compact = []
    last_path = None

    for item in cleaned:
        path = item.get("path")
        if path == last_path:
            continue

        compact.append(item)
        last_path = path

    if len(compact) <= 2:
        return compact

    # Nén oscillation kiểu:
    # old -> new -> old -> new
    result = []

    for item in compact:
        path = item["path"]

        # Nếu path này đã xuất hiện trước đó, giữ occurrence mới nhất
        # bằng cách xóa occurrence cũ. Điều này giúp loại các flip do handle phụ.
        result = [x for x in result if x["path"] != path]
        result.append(item)

    result.sort(key=lambda x: (
        sortable_timestamp(x.get("timestamp")),
        x.get("path") or "",
    ))

    # Bỏ trùng liên tiếp lần cuối
    final = []
    last_path = None

    for item in result:
        if item["path"] == last_path:
            continue
        final.append(item)
        last_path = item["path"]

    return final

def build_semantic_summary(events, versions):
    semantic_ops = []
    smb_commands = []

    for event in events:
        op = event.get("semantic_op") or event.get("op")
        if op and op not in semantic_ops:
            semantic_ops.append(op)

        cmd = event.get("smb_command") or event.get("source_command")
        if cmd and cmd not in smb_commands:
            smb_commands.append(cmd)

    return {
        "semantic_ops": semantic_ops,
        "smb_commands": smb_commands,
        "event_count": len(events),
        "version_count": len(versions),
        "has_content": len(versions) > 0,
    }

def version_export_time(version, metadata):
    metadata = metadata or {}

    return (
        metadata.get("network_timestamp")
        or getattr(version, "modified", None)
        or metadata.get("modified")
        or metadata.get("changed")
    )


def version_export_sort_key(item):
    version, fid, metadata = item

    return (
        sortable_timestamp(version_export_time(version, metadata)),
        file_id_to_str(fid) or "",
        int(getattr(version, "version_id", 0) or 0),
    )

def file_id_to_str(fid):
    if fid is None:
        return None

    if isinstance(fid, bytes):
        return fid.hex()

    if isinstance(fid, bytearray):
        return bytes(fid).hex()

    if isinstance(fid, memoryview):
        return fid.tobytes().hex()

    return str(fid)


def merge_bool(file_objs, attr):
    return any(bool(getattr(f, attr, False)) for f in file_objs)


def choose_representative(file_objs):
    """
    Ưu tiên object có version thật.
    Nếu không có version, lấy object cuối cùng.
    """
    with_versions = [
        f for f in file_objs
        if f.versions and f.versions.versions
    ]

    if with_versions:
        return with_versions[-1]

    return file_objs[-1]

def path_history_from_events(path_history, events, final_path):
    """
    Ưu tiên rename event để tạo path history semantic.
    Nếu có rename old_path -> new_path thì history nên là:
      old_path -> new_path
    """
    rename_events = [
        e for e in events
        if e.get("op") == "rename" and e.get("old_path") and e.get("new_path")
    ]

    if not rename_events:
        return dedupe_path_history(path_history)

    rename_events.sort(key=lambda e: (
        sortable_timestamp(e.get("timestamp")),
        sortable_timestamp(e.get("frame_number")),
    ))

    result = []

    first = rename_events[0]
    result.append({
        "timestamp": normalize_scalar(first.get("timestamp")),
        "path": first.get("old_path"),
    })

    for e in rename_events:
        result.append({
            "timestamp": normalize_scalar(e.get("timestamp")),
            "path": e.get("new_path"),
        })

    return dedupe_path_history(result)

def export_files(file_table, tree):
    path_groups = defaultdict(list)

    for f in file_table.files.values():
        path = f.path or "unknown"
        path_groups[path].append(f)

    files = []

    for path, file_objs in path_groups.items():
        all_versions = []
        all_events = []
        all_path_history = []

        representative = choose_representative(file_objs)

        for f in file_objs:
            all_events.extend([
                event.to_dict()
                for event in getattr(f, "events", [])
            ])

            all_path_history.extend(
                getattr(f, "path_history", [])
            )

            deduped = f.versions.deduplicated_versions(
                file_id=f.file_id,
                path=f.path,
            )

            for v in deduped:
                if v.last_op is None:
                    continue

                meta = v.snapshot_metadata or {
                    "created": f.metadata.created,
                    "modified": f.metadata.modified,
                    "accessed": f.metadata.accessed,
                    "size": v.size,
                }

                all_versions.append((v, f.file_id, meta))

        all_versions.sort(key=version_export_sort_key)
        # Dedup lần 2 sau khi gộp nhiều FileObject cùng path.
        final_versions = []

        for v, fid, meta in all_versions:
            if final_versions and v.same_content_as(final_versions[-1][0]):
                if v.modified is not None:
                    final_versions[-1][2]["modified"] = v.modified
                continue

            final_versions.append((v, fid, meta))

        versions = []
        
        event_dicts = sorted(
            all_events,
            key=lambda e: (
                sortable_timestamp(e.get("timestamp")),
                sortable_timestamp(e.get("frame_number")),
            )
        )

        for i, (v, fid, meta) in enumerate(final_versions):
            versions.append({
                "version": i,
                "file_id": file_id_to_str(fid),
                "op": v.last_op,
                "metadata": meta,
                "hash": v.get_hash(),
            })

        sources = sorted(set(
            getattr(f, "source", "observed")
            for f in file_objs
        ))

        files.append({
            "path": path,
            "object_type": infer_object_type(path, merge_bool(file_objs, "is_dir")),

            "source": representative.source,
            "sources": sources,
            "is_dir": merge_bool(file_objs, "is_dir"),
            "deleted": merge_bool(file_objs, "deleted"),
            "delete_time": representative.delete_time,

            "semantic_summary": build_semantic_summary(event_dicts, versions),
            "path_history": path_history_from_events(
                all_path_history,
                event_dicts,
                path,
            ),
            "events": event_dicts,

            "versions": versions,
        })

    return {
        "files": files,
        "tree": tree,
    }

