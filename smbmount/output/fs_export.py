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

def version_kind_for_op(op):
    if op in ("read", "observed_read"):
        return "observed"

    if op in ("write", "truncate", "append", "overwrite"):
        return "mutation"

    return "content"


def version_expected_size(version, metadata):
    metadata = metadata or {}

    candidates = [
        getattr(version, "expected_size", None),
        metadata.get("size"),
        getattr(version, "size", None),
    ]

    for value in candidates:
        if value is None:
            continue

        try:
            return int(value)
        except Exception:
            continue

    return 0


def version_coverage_bytes(version, expected_size):
    if hasattr(version, "coverage_bytes"):
        return int(version.coverage_bytes(expected_size))

    ranges = []

    data_chunks = getattr(version, "data_chunks", []) or []

    for offset, data in data_chunks:
        start = int(offset)
        end = start + len(data or b"")

        if end > start:
            ranges.append((start, end))

    if not ranges:
        data_map = getattr(version, "data_map", {}) or {}

        for offset, data in data_map.items():
            start = int(offset)
            end = start + len(data or b"")

            if end > start:
                ranges.append((start, end))

    if not ranges:
        return 0

    ranges.sort()

    merged = []
    cur_start, cur_end = ranges[0]

    for start, end in ranges[1:]:
        if start <= cur_end:
            cur_end = max(cur_end, end)
        else:
            merged.append((cur_start, cur_end))
            cur_start, cur_end = start, end

    merged.append((cur_start, cur_end))

    if expected_size is not None:
        expected_size = int(expected_size)
        total = 0

        for start, end in merged:
            if start >= expected_size:
                continue

            total += max(0, min(end, expected_size) - start)

        return total

    return sum(end - start for start, end in merged)


def version_reconstruction_state(version, metadata):
    """
    State cấp version:
    - complete: đủ coverage theo expected size
    - partial: có dữ liệu nhưng thiếu coverage
    - hollow: không có content bytes
    """
    op = getattr(version, "last_op", None)

    expected_size = version_expected_size(version, metadata)
    coverage = version_coverage_bytes(version, expected_size)

    if coverage <= 0:
        return "hollow"

    if op == "read":
        observed_state = getattr(version, "observed_state", None)

        if observed_state in ("complete", "partial"):
            return observed_state

        if bool(getattr(version, "is_observed_complete", False)):
            return "complete"

        return "partial"

    # Zero-byte file nếu có version và không có content bytes thì vẫn có thể xem là complete.
    # Nhưng vì coverage <= 0 đã return hollow ở trên, zero-byte version thực tế sẽ hiếm.
    if expected_size == 0:
        return "complete"

    if coverage >= expected_size:
        return "complete"

    return "partial"


def file_reconstruction_state(is_dir, versions):
    """
    State cấp file để report robustness:
    - directory: thư mục
    - hollow: thấy file/path nhưng không có content version
    - partial: có ít nhất một version partial/hollow
    - complete: tất cả version đều complete
    """
    if is_dir:
        return "directory"

    if not versions:
        return "hollow"

    states = {
        item.get("reconstruction_state")
        for item in versions
    }

    if "partial" in states or "hollow" in states:
        return "partial"

    return "complete"

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
            expected_size = version_expected_size(v, meta)
            coverage_bytes = version_coverage_bytes(v, expected_size)

            if expected_size > 0:
                coverage_ratio = coverage_bytes / expected_size
            else:
                coverage_ratio = 1.0

            reconstruction_state = version_reconstruction_state(v, meta)

            version_item = {
                "version": i,
                "file_id": file_id_to_str(fid),
                "op": v.last_op,
                "version_kind": version_kind_for_op(v.last_op),
                "reconstruction_state": reconstruction_state,
                "expected_size": expected_size,
                "coverage_bytes": coverage_bytes,
                "coverage_ratio": coverage_ratio,
                "metadata": meta,
                "hash": v.get_hash(),
            }

            if v.last_op == "read":
                version_item["observed_state"] = getattr(
                    v,
                    "observed_state",
                    reconstruction_state,
                )
                version_item["observed_complete"] = bool(
                    getattr(v, "is_observed_complete", False)
                )
                version_item["observed_coverage_bytes"] = int(
                    getattr(v, "observed_coverage_bytes", coverage_bytes) or 0
                )
                version_item["observed_coverage_ratio"] = float(
                    getattr(v, "observed_coverage_ratio", coverage_ratio) or 0.0
                )

            versions.append(version_item)

        sources = sorted(set(
            getattr(f, "source", "observed")
            for f in file_objs
        ))

        is_dir = merge_bool(file_objs, "is_dir")

        files.append({
            "path": path,
            "object_type": infer_object_type(path, is_dir),

            "reconstruction_state": file_reconstruction_state(
                is_dir,
                versions,
            ),

            "source": representative.source,
            "sources": sources,
            "is_dir": is_dir,
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

