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
    - Convert timestamp EDecimal -> float
    - Bỏ record lỗi/rỗng
    - Sort theo timestamp
    - Chỉ giữ khi path thay đổi, tránh lặp hàng chục dòng cùng path
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

    result = []
    last_path = None

    for item in cleaned:
        path = item.get("path")

        if path == last_path:
            continue

        result.append(item)
        last_path = path

    return result

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
            "path_history": dedupe_path_history(all_path_history),
            "events": event_dicts,

            "versions": versions,
        })

    return {
        "files": files,
        "tree": tree,
    }
