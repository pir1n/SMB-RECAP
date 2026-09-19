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

def content_event_time_for_version(file_obj, version, time_source="network"):
    """
    Lấy thời điểm semantic event tạo ra content version.
    Với WRITE version, ưu tiên event append/overwrite/write.
    Với READ version, ưu tiên event read.
    """
    target_ops = []

    if version.last_op == "write":
        target_ops = ["append", "overwrite", "write"]
    elif version.last_op == "read":
        target_ops = ["read"]
    else:
        target_ops = [version.last_op]

    candidates = []

    for event in getattr(file_obj, "events", []):
        event_dict = event.to_dict()
        op = event_dict.get("semantic_op") or event_dict.get("op")

        if op not in target_ops:
            continue

        ts = event_time(event_dict, time_source=time_source)
        if ts is None:
            continue

        candidates.append(ts)

    if not candidates:
        return None

    # Version hiện tại thường được tạo bởi event cuối cùng cùng loại trước commit.
    return max(candidates)

def normalize_scalar(value):
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    try:
        return float(value)
    except Exception:
        return str(value)


def normalize_time(value):
    value = normalize_scalar(value)

    if value is None:
        return None

    try:
        return float(value)
    except Exception:
        return None


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


def infer_object_type(path, is_dir=False):
    if is_dir:
        return "directory"

    if path:
        normalized = path.replace("/", "\\").split("\\")[-1].lower()
        if normalized in KNOWN_NAMED_PIPES:
            return "pipe"

    return "file"


def event_time(event_dict, time_source="network"):
    """
    time_source:
    - network: dùng network_timestamp nếu có
    - fs: dùng fs_timestamp nếu có
    Fallback cuối cùng là timestamp.
    """
    if time_source == "network":
        return (
            normalize_time(event_dict.get("network_timestamp"))
            or normalize_time(event_dict.get("timestamp"))
        )

    if time_source == "fs":
        return (
            normalize_time(event_dict.get("fs_timestamp"))
            or normalize_time(event_dict.get("timestamp"))
        )

    return normalize_time(event_dict.get("timestamp"))


def version_time(version, metadata, time_source="network", file_obj=None):
    """
    Chọn timestamp để xác định version đã tồn tại tại snapshot_at chưa.
    Với network snapshot, ưu tiên thời điểm event tạo content,
    không ưu tiên CLOSE timestamp.
    """
    if time_source == "network":
        if file_obj is not None:
            content_ts = content_event_time_for_version(
                file_obj,
                version,
                time_source=time_source,
            )
            if content_ts is not None:
                return content_ts

        return (
            normalize_time(metadata.get("network_timestamp"))
            or normalize_time(version.modified)
            or normalize_time(metadata.get("modified"))
        )

    if time_source == "fs":
        return (
            normalize_time(metadata.get("modified"))
            or normalize_time(metadata.get("changed"))
            or normalize_time(metadata.get("accessed"))
            or normalize_time(metadata.get("created"))
            or normalize_time(version.modified)
        )

    return normalize_time(version.modified)


def path_at_time(file_obj, snapshot_at):
    """
    Dựa vào path_history để lấy path tại thời điểm snapshot.
    Nếu chưa có history trước snapshot_at thì fallback về path hiện tại.
    """
    history = getattr(file_obj, "path_history", []) or []

    candidates = []

    for item in history:
        ts = normalize_time(item.get("timestamp"))
        path = item.get("path")

        if ts is None or path is None:
            continue

        if ts <= snapshot_at:
            candidates.append((ts, path))

    if candidates:
        candidates.sort(key=lambda x: x[0])
        return candidates[-1][1]

    return file_obj.path or "unknown"


def metadata_for_version(file_obj, version):
    return version.snapshot_metadata or {
        "created": file_obj.metadata.created,
        "modified": file_obj.metadata.modified,
        "accessed": file_obj.metadata.accessed,
        "changed": getattr(file_obj.metadata, "changed", None),
        "size": version.size,
    }


def events_until(file_obj, snapshot_at, time_source="network"):
    result = []

    for event in getattr(file_obj, "events", []):
        event_dict = event.to_dict()
        ts = event_time(event_dict, time_source=time_source)

        if ts is None:
            continue

        if ts <= snapshot_at:
            result.append(event_dict)

    result.sort(key=lambda e: (
        event_time(e, time_source=time_source) is None,
        event_time(e, time_source=time_source) or float("inf"),
        e.get("frame_number") if e.get("frame_number") is not None else float("inf"),
    ))

    return result


def deleted_by_time(events):
    for event in events:
        op = event.get("semantic_op") or event.get("op")
        if op in ("delete", "rmdir"):
            return True
    return False


def semantic_ops(events):
    ops = []

    for event in events:
        op = event.get("semantic_op") or event.get("op")
        if op and op not in ops:
            ops.append(op)

    return ops


def build_snapshot_tree(snapshot_files):
    tree = {}

    for item in snapshot_files:
        if item.get("state") == "deleted":
            continue

        path = item.get("path")
        if not path or path == "unknown":
            continue

        parts = [
            p for p in path.replace("/", "\\").split("\\")
            if p
        ]

        cursor = tree

        for part in parts:
            cursor = cursor.setdefault(part, {})

    return tree


def choose_latest_version_before(file_obj, snapshot_at, time_source="network"):
    candidates = []

    deduped = file_obj.versions.deduplicated_versions(
        file_id=file_obj.file_id,
        path=file_obj.path,
    )

    for version in deduped:
        if version.last_op is None:
            continue

        metadata = metadata_for_version(file_obj, version)
        ts = version_time(
            version,
            metadata,
            time_source=time_source,
            file_obj=file_obj,
        )

        if ts is None:
            continue

        if ts <= snapshot_at:
            candidates.append((ts, version, metadata))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0])
    return candidates[-1]


def first_seen_time(file_obj, time_source="network"):
    times = []

    for event in getattr(file_obj, "events", []):
        event_dict = event.to_dict()
        ts = event_time(event_dict, time_source=time_source)
        if ts is not None:
            times.append(ts)

    for item in getattr(file_obj, "path_history", []) or []:
        ts = normalize_time(item.get("timestamp"))
        if ts is not None:
            times.append(ts)

    if not times:
        return None

    return min(times)


def build_snapshot(file_table, snapshot_at, time_source="network", include_deleted=True):
    snapshot_at = float(snapshot_at)

    grouped = defaultdict(list)

    # Gom theo path tại snapshot_at, không phải path cuối cùng.
    for file_obj in file_table.files.values():
        path = path_at_time(file_obj, snapshot_at)
        grouped[path].append(file_obj)

    snapshot_files = []

    for path, file_objs in grouped.items():
        version_candidates = []
        all_events_until = []

        for file_obj in file_objs:
            all_events_until.extend(
                events_until(
                    file_obj,
                    snapshot_at,
                    time_source=time_source,
                )
            )

            selected = choose_latest_version_before(
                file_obj,
                snapshot_at,
                time_source=time_source,
            )

            if selected is not None:
                ts, version, metadata = selected
                version_candidates.append((ts, file_obj, version, metadata))

        all_events_until.sort(key=lambda e: (
            event_time(e, time_source=time_source) is None,
            event_time(e, time_source=time_source) or float("inf"),
            e.get("frame_number") if e.get("frame_number") is not None else float("inf"),
        ))

        is_deleted = deleted_by_time(all_events_until)

        if is_deleted and not include_deleted:
            continue

        # Nếu chưa có version, vẫn có thể là context-only hoặc directory.
        if not version_candidates:
            seen_times = [
                first_seen_time(file_obj, time_source=time_source)
                for file_obj in file_objs
            ]
            seen_times = [ts for ts in seen_times if ts is not None]

            if not seen_times:
                continue

            if min(seen_times) > snapshot_at:
                continue

            representative = file_objs[-1]

            snapshot_files.append({
                "path": path,
                "object_type": infer_object_type(
                    path,
                    any(getattr(f, "is_dir", False) for f in file_objs),
                ),
                "state": "deleted" if is_deleted else "present",
                "source": getattr(representative, "source", "observed"),
                "sources": sorted(set(getattr(f, "source", "observed") for f in file_objs)),
                "is_dir": any(getattr(f, "is_dir", False) for f in file_objs),
                "deleted": is_deleted,
                "selected_version": None,
                "file_id": file_id_to_str(representative.file_id),
                "metadata": None,
                "hash": None,
                "semantic_ops_until_snapshot": semantic_ops(all_events_until),
                "event_count_until_snapshot": len(all_events_until),
            })
            continue

        version_candidates.sort(key=lambda x: x[0])
        selected_ts, selected_file_obj, selected_version, selected_metadata = version_candidates[-1]

        snapshot_files.append({
            "path": path,
            "object_type": infer_object_type(
                path,
                any(getattr(f, "is_dir", False) for f in file_objs),
            ),
            "state": "deleted" if is_deleted else "present",
            "source": getattr(selected_file_obj, "source", "observed"),
            "sources": sorted(set(getattr(f, "source", "observed") for f in file_objs)),
            "is_dir": any(getattr(f, "is_dir", False) for f in file_objs),
            "deleted": is_deleted,

            "selected_version": selected_version.version_id,
            "selected_version_time": selected_ts,
            "file_id": file_id_to_str(selected_file_obj.file_id),
            "metadata": selected_metadata,
            "hash": selected_version.get_hash(),

            "semantic_ops_until_snapshot": semantic_ops(all_events_until),
            "event_count_until_snapshot": len(all_events_until),
        })

    snapshot_files.sort(key=lambda item: item.get("path") or "")

    return {
        "snapshot_at": snapshot_at,
        "snapshot_time_source": time_source,
        "include_deleted": include_deleted,
        "files": snapshot_files,
        "tree": build_snapshot_tree(snapshot_files),
    }
