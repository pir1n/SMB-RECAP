import errno
import os
import stat
import time
from dataclasses import dataclass
from collections import defaultdict

import mfusepy as fuse

from smbmount.output.snapshot_export import (
    normalize_time,
    path_at_time,
    events_until,
    deleted_by_time,
    choose_latest_version_before,
    metadata_for_version,
    infer_object_type,
)


@dataclass
class FuseEntry:
    path: str
    is_dir: bool
    data: bytes = b""
    metadata: dict = None
    source: str = "observed"
    object_type: str = "file"


def to_ns(value):
    ts = normalize_time(value)

    if ts is None:
        return int(time.time() * 1_000_000_000)

    return int(ts * 1_000_000_000)


def smb_path_to_fuse_path(path):
    if not path:
        return "/unknown"

    path = str(path).replace("\\", "/").strip("/")

    if not path:
        return "/"

    return "/" + path


def parent_paths(path):
    parts = path.strip("/").split("/")

    parents = []

    for i in range(1, len(parts)):
        parents.append("/" + "/".join(parts[:i]))

    return parents


def ensure_parent_dirs(entries, fuse_path):
    for parent in parent_paths(fuse_path):
        if parent not in entries:
            entries[parent] = FuseEntry(
                path=parent,
                is_dir=True,
                data=b"",
                metadata={},
                source="synthetic_parent",
                object_type="directory",
            )


def promote_parent_paths_to_dirs(entries):
    """
    Any path that has children must behave as a directory in FUSE.

    SMB traces can expose directory-like paths without enough CREATE metadata for
    reconstruction to mark them as directories. If such a path is mounted as a
    zero-byte file, users cannot descend into it and its children appear missing.
    """
    parent_set = set()

    for fuse_path in list(entries):
        if fuse_path == "/":
            continue

        for parent in parent_paths(fuse_path):
            parent_set.add(parent)

    for parent in sorted(parent_set, key=lambda p: p.count("/")):
        entry = entries.get(parent)

        if entry is None:
            entries[parent] = FuseEntry(
                path=parent,
                is_dir=True,
                data=b"",
                metadata={},
                source="synthetic_parent",
                object_type="directory",
            )
            continue

        if not entry.is_dir:
            entry.is_dir = True
            entry.data = b""
            entry.object_type = "directory"

    return entries


def version_sort_time(version, metadata):
    return (
        normalize_time((metadata or {}).get("network_timestamp"))
        or normalize_time((metadata or {}).get("modified"))
        or normalize_time(getattr(version, "modified", None))
        or 0.0
    )


def final_versions_for_file_objs(file_objs):
    """
    Match fs_export.py version grouping so FUSE @N files line up with JSON output.
    """
    all_versions = []

    for file_obj in file_objs:
        deduped = file_obj.versions.deduplicated_versions(
            file_id=file_obj.file_id,
            path=file_obj.path,
        )

        for version in deduped:
            if version.last_op is None:
                continue

            metadata = metadata_for_version(file_obj, version)
            all_versions.append((version, file_obj, metadata))

    final_versions = []

    for version, file_obj, metadata in all_versions:
        if final_versions and version.same_content_as(final_versions[-1][0]):
            if version.modified is not None:
                final_versions[-1][2]["modified"] = version.modified
            continue

        final_versions.append((version, file_obj, metadata))

    return final_versions


def versioned_fuse_path(fuse_path, index):
    return f"{fuse_path}@{index}"


def make_file_entry(fuse_path, file_obj, version, metadata, object_type):
    return FuseEntry(
        path=fuse_path,
        is_dir=False,
        data=version.get_data(),
        metadata=metadata or {},
        source=getattr(file_obj, "source", "observed"),
        object_type=object_type,
    )


def collect_latest_entries(file_table, include_deleted=False):
    entries = {
        "/": FuseEntry(
            path="/",
            is_dir=True,
            data=b"",
            metadata={},
            source="root",
            object_type="directory",
        )
    }

    grouped = defaultdict(list)

    for file_obj in file_table.files.values():
        if getattr(file_obj, "deleted", False) and not include_deleted:
            continue

        path = file_obj.path or "unknown"
        grouped[path].append(file_obj)

    for path, file_objs in grouped.items():
        representative = file_objs[-1]

        fuse_path = smb_path_to_fuse_path(path)

        if fuse_path == "/unknown" and not any(getattr(f, "events", None) for f in file_objs):
            continue

        ensure_parent_dirs(entries, fuse_path)

        is_dir = any(bool(getattr(f, "is_dir", False)) for f in file_objs)
        object_type = infer_object_type(path, is_dir=is_dir)

        if is_dir:
            entries[fuse_path] = FuseEntry(
                path=fuse_path,
                is_dir=True,
                data=b"",
                metadata={},
                source=getattr(representative, "source", "observed"),
                object_type="directory",
            )
            continue

        final_versions = final_versions_for_file_objs(file_objs)

        if not final_versions:
            entries[fuse_path] = FuseEntry(
                path=fuse_path,
                is_dir=False,
                data=b"",
                metadata={},
                source=getattr(representative, "source", "observed"),
                object_type=object_type,
            )
            continue

        if len(final_versions) == 1:
            version, file_obj, metadata = final_versions[0]
            entries[fuse_path] = make_file_entry(
                fuse_path,
                file_obj,
                version,
                metadata,
                object_type,
            )
            continue

        for index, (version, file_obj, metadata) in enumerate(final_versions):
            version_path = versioned_fuse_path(fuse_path, index)
            ensure_parent_dirs(entries, version_path)
            entries[version_path] = make_file_entry(
                version_path,
                file_obj,
                version,
                metadata,
                object_type,
            )

    return promote_parent_paths_to_dirs(entries)


def collect_snapshot_entries(
    file_table,
    snapshot_at,
    time_source="network",
    include_deleted=False,
):
    snapshot_at = float(snapshot_at)

    entries = {
        "/": FuseEntry(
            path="/",
            is_dir=True,
            data=b"",
            metadata={},
            source="root",
            object_type="directory",
        )
    }

    grouped = defaultdict(list)

    for file_obj in file_table.files.values():
        path = path_at_time(file_obj, snapshot_at)
        grouped[path].append(file_obj)

    for path, file_objs in grouped.items():
        all_events = []

        for file_obj in file_objs:
            all_events.extend(
                events_until(
                    file_obj,
                    snapshot_at,
                    time_source=time_source,
                )
            )

        is_deleted = deleted_by_time(all_events)

        if is_deleted and not include_deleted:
            continue

        fuse_path = smb_path_to_fuse_path(path)

        if fuse_path == "/unknown":
            continue

        ensure_parent_dirs(entries, fuse_path)

        is_dir = any(getattr(f, "is_dir", False) for f in file_objs)
        object_type = infer_object_type(path, is_dir=is_dir)

        if is_dir:
            entries[fuse_path] = FuseEntry(
                path=fuse_path,
                is_dir=True,
                data=b"",
                metadata={},
                source="observed",
                object_type="directory",
            )
            continue

        version_candidates = []

        for file_obj in file_objs:
            selected = choose_latest_version_before(
                file_obj,
                snapshot_at,
                time_source=time_source,
            )

            if selected is None:
                continue

            selected_ts, version, metadata = selected
            version_candidates.append((
                selected_ts,
                file_obj,
                version,
                metadata,
            ))

        if version_candidates:
            version_candidates.sort(key=lambda x: x[0])
            selected_ts, file_obj, version, metadata = version_candidates[-1]

            entries[fuse_path] = FuseEntry(
                path=fuse_path,
                is_dir=False,
                data=version.get_data(),
                metadata=metadata or {},
                source=getattr(file_obj, "source", "observed"),
                object_type=object_type,
            )
        else:
            # context-only file: hiện trong directory listing nhưng không có content
            seen = False

            for file_obj in file_objs:
                for event_dict in events_until(
                    file_obj,
                    snapshot_at,
                    time_source=time_source,
                ):
                    if (event_dict.get("semantic_op") or event_dict.get("op")) == "context_seen":
                        seen = True
                        break

            if seen:
                entries[fuse_path] = FuseEntry(
                    path=fuse_path,
                    is_dir=False,
                    data=b"",
                    metadata={},
                    source="context_only",
                    object_type=object_type,
                )

    return promote_parent_paths_to_dirs(entries)


class SMBMountFuseFS(fuse.Operations):
    """
    Read-only FUSE filesystem từ reconstructed SMB state.
    """

    use_ns = True

    def __init__(self, entries):
        self.entries = entries
        self.children = defaultdict(set)
        self.uid = os.getuid() if hasattr(os, "getuid") else 0
        self.gid = os.getgid() if hasattr(os, "getgid") else 0

        for path in entries:
            if path == "/":
                continue

            parent = os.path.dirname(path.rstrip("/")) or "/"
            name = os.path.basename(path.rstrip("/"))
            self.children[parent].add(name)

    def _entry(self, path):
        if path not in self.entries:
            raise fuse.FuseOSError(errno.ENOENT)

        return self.entries[path]

    def getattr(self, path, fh=None):
        entry = self._entry(path)
        metadata = entry.metadata or {}

        if entry.is_dir:
            mode = stat.S_IFDIR | 0o555
            size = 0
            nlink = 2
        else:
            mode = stat.S_IFREG | 0o444
            size = len(entry.data)
            nlink = 1

        mtime = (
            metadata.get("modified")
            or metadata.get("changed")
            or metadata.get("accessed")
            or metadata.get("created")
            or metadata.get("network_timestamp")
        )

        ts_ns = to_ns(mtime)

        return {
            "st_mode": mode,
            "st_nlink": nlink,
            "st_size": size,
            "st_ctime": ts_ns,
            "st_mtime": ts_ns,
            "st_atime": ts_ns,
            "st_uid": self.uid,
            "st_gid": self.gid,
        }

    def readdir(self, path, fh):
        self._entry(path)

        yield "."
        yield ".."

        for name in sorted(self.children.get(path, [])):
            yield name

    def open(self, path, flags):
        entry = self._entry(path)

        if entry.is_dir:
            raise fuse.FuseOSError(errno.EISDIR)

        access_mode = flags & os.O_ACCMODE

        if access_mode in (os.O_WRONLY, os.O_RDWR):
            raise fuse.FuseOSError(errno.EROFS)

        return 0

    def read(self, path, size, offset, fh):
        entry = self._entry(path)

        if entry.is_dir:
            raise fuse.FuseOSError(errno.EISDIR)

        return entry.data[offset: offset + size]

    def statfs(self, path):
        return {
            "f_bsize": 4096,
            "f_frsize": 4096,
            "f_blocks": 1024,
            "f_bfree": 1024,
            "f_bavail": 1024,
            "f_files": len(self.entries),
            "f_ffree": 0,
            "f_namemax": 255,
        }

    # Read-only guard
    def write(self, path, data, offset, fh):
        raise fuse.FuseOSError(errno.EROFS)

    def create(self, path, mode, fi=None):
        raise fuse.FuseOSError(errno.EROFS)

    def mkdir(self, path, mode):
        raise fuse.FuseOSError(errno.EROFS)

    def unlink(self, path):
        raise fuse.FuseOSError(errno.EROFS)

    def rmdir(self, path):
        raise fuse.FuseOSError(errno.EROFS)

    def rename(self, old, new):
        raise fuse.FuseOSError(errno.EROFS)

    def truncate(self, path, length, fh=None):
        raise fuse.FuseOSError(errno.EROFS)


def build_fuse_entries(
    file_table,
    snapshot_at=None,
    snapshot_time_source="network",
    include_deleted=False,
):
    if snapshot_at is not None:
        return collect_snapshot_entries(
            file_table,
            snapshot_at=snapshot_at,
            time_source=snapshot_time_source,
            include_deleted=include_deleted,
        )

    return collect_latest_entries(
        file_table,
        include_deleted=include_deleted,
    )


def mount_reconstructed_fs(
    file_table,
    mountpoint,
    snapshot_at=None,
    snapshot_time_source="network",
    include_deleted=False,
    foreground=True,
    debug=False,
    allow_other=False,
):
    entries = build_fuse_entries(
        file_table,
        snapshot_at=snapshot_at,
        snapshot_time_source=snapshot_time_source,
        include_deleted=include_deleted,
    )

    fs = SMBMountFuseFS(entries)

    fuse_options = {
        "foreground": foreground,
        "nothreads": True,
        "ro": True,
        "debug": debug,
    }

    if allow_other:
        fuse_options["allow_other"] = True

    return fuse.FUSE(
        fs,
        mountpoint,
        **fuse_options,
    )
