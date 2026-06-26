from typing import Dict
from smbmount.reconstruct.metadata import FileMetadata
from smbmount.reconstruct.versioning import VersionManager
from smbmount.reconstruct.events import FileEvent


class FileObject:
    def __init__(self, file_id: str):
        self.file_id = file_id
        self.path = None
        self.metadata = FileMetadata()
        self.versions = VersionManager()
        
        self.is_dir = False
        self.deleted = False
        self.delete_time = None
        self.source = "observed"   # observed | context_only
        self.path_history = []
        self.events = []

    def update_metadata(self, pkt):
        self.metadata.update_from_packet(pkt)

    def mark_metadata_update(self, pkt=None):
        self.add_event(
            "metadata_update",
            pkt,
            evidence={
                "file_info_class": (pkt or {}).get("smb2_file_info_class"),
                "file_info_class_raw": (pkt or {}).get("smb2_file_info_class_raw"),
                "create_time": (pkt or {}).get("smb2_create_time"),
                "last_access_time": (pkt or {}).get("smb2_last_access_time"),
                "last_write_time": (pkt or {}).get("smb2_last_write_time"),
                "change_time": (pkt or {}).get("smb2_change_time"),
            },
        )

    def open(self, timestamp=None):
        self.versions.open_session(timestamp, file_id=self.file_id)

    def write(self, offset, length, timestamp=None, data=None, pkt=None):
        self.add_write(
            offset,
            length,
            data=data,
            timestamp=timestamp,
            pkt=pkt,
        )

    def commit(self, timestamp=None):
        self.versions.commit(timestamp)

    def update_version_metadata(self, timestamp=None):
        self.versions.update_metadata(
            timestamp,
            file_id=self.file_id,
        )
    
    def add_read(self, offset, length, data=None, timestamp=None, pkt=None):
        self.versions.add_read(
            offset,
            length,
            data=data,
            timestamp=timestamp,
            file_id=self.file_id,
        )

        self.add_event(
            "read",
            pkt,
            size_after=self.versions.current_size(),
            evidence={
                "offset": offset,
                "length": length,
            },
        )
    
    def add_write(self, offset, length, data=None, timestamp=None, pkt=None):
        self.semantic_write(
            offset,
            length,
            data=data,
            timestamp=timestamp,
            pkt=pkt,
        )

    def set_path(self, path, timestamp=None):
        if not path:
            return

        if self.path != path:
            self.path_history.append({
                "timestamp": timestamp,
                "path": path,
            })

        self.path = path

    def file_id_str(self):
        if isinstance(self.file_id, bytes):
            return self.file_id.hex()
        if isinstance(self.file_id, bytearray):
            return bytes(self.file_id).hex()
        if isinstance(self.file_id, memoryview):
            return self.file_id.tobytes().hex()
        return str(self.file_id)
    
    def add_event(self, op, pkt=None, **kwargs):
        pkt = pkt or {}

        event = FileEvent(
            op=op,
            timestamp=pkt.get("timestamp"),
            timestamp_source=pkt.get("timestamp_source"),
            network_timestamp=pkt.get("network_timestamp"),
            fs_timestamp=pkt.get("fs_timestamp"),
            timestamp_mode=pkt.get("timestamp_mode"),

            frame_number=pkt.get("frame_number"),
            path=kwargs.get("path", self.path),
            old_path=kwargs.get("old_path"),
            new_path=kwargs.get("new_path"),
            file_id=self.file_id_str(),
            is_dir=kwargs.get("is_dir", self.is_dir),
            size_before=kwargs.get("size_before"),
            size_after=kwargs.get("size_after"),
            source_command=pkt.get("smb2_command_name"),
            evidence=kwargs.get("evidence", {}),
        )

        self.events.append(event)
        return event

    def mark_directory(self, is_dir=True):
        self.is_dir = bool(is_dir)

    def mark_context_only(self):
        self.source = "context_only"

    def mark_delete(self, pkt=None):
        self.deleted = True
        self.delete_time = (pkt or {}).get("timestamp")
        self.add_event(
            "rmdir" if self.is_dir else "delete",
            pkt,
            is_dir=self.is_dir,
            evidence={
                "file_info_class": (pkt or {}).get("smb2_file_info_class"),
                "delete_pending": (pkt or {}).get("smb2_delete_pending"),
                "disposition_flags": (pkt or {}).get("smb2_disposition_flags"),
            },
        )

    def rename(self, new_path, pkt=None):
        if not new_path:
            return

        old_path = self.path
        self.set_path(new_path, timestamp=(pkt or {}).get("timestamp"))

        self.add_event(
            "rename",
            pkt,
            old_path=old_path,
            new_path=new_path,
            evidence={
                "file_info_class": (pkt or {}).get("smb2_file_info_class"),
            },
        )
        
    def truncate(self, new_size, pkt=None):
        if new_size is None:
            return

        new_size = int(new_size)
        old_size = self.versions.current_size()

        self.versions.truncate(
            new_size,
            timestamp=(pkt or {}).get("timestamp"),
            file_id=self.file_id,
        )

        self.metadata.size = new_size

        self.add_event(
            "truncate",
            pkt,
            size_before=old_size,
            size_after=new_size,
            evidence={
                "file_info_class": (pkt or {}).get("smb2_file_info_class"),
                "file_info_class_raw": (pkt or {}).get("smb2_file_info_class_raw"),
            },
        )

    def semantic_write(self, offset, length, data=None, timestamp=None, pkt=None):
        if offset is None or length is None:
            return

        offset = int(offset)
        length = int(length)

        old_size = self.versions.current_size()

        if offset == old_size:
            op = "append"
        elif offset < old_size:
            op = "overwrite"
        else:
            op = "write"

        self.versions.add_write(
            offset,
            length,
            data=data,
            timestamp=timestamp,
            file_id=self.file_id,
        )

        new_size = self.versions.current_size()

        old_meta_size = self.metadata.size or 0
        self.metadata.size = max(old_meta_size, new_size)

        self.add_event(
            op,
            pkt,
            size_before=old_size,
            size_after=new_size,
            evidence={
                "offset": offset,
                "length": length,
            },
        )
        

class FileTable:
    def __init__(self):
        self.files: Dict[str, FileObject] = {}
        self.path_index: Dict[str, FileObject] = {}

    def get_or_create(self, file_id: str) -> FileObject:
        key = self.normalize_file_id(file_id)

        if key not in self.files:
            self.files[key] = FileObject(file_id)

        return self.files[key]

    def bind_path(self, file_obj: FileObject, path: str, timestamp=None):
        if not path:
            return

        # Xóa mọi path cũ đang trỏ tới cùng object,
        # vì path_index chỉ nên biểu diễn current path.
        stale_paths = [
            old_path
            for old_path, obj in self.path_index.items()
            if obj is file_obj and old_path != path
        ]

        for old_path in stale_paths:
            del self.path_index[old_path]

        file_obj.set_path(path, timestamp=timestamp)
        self.path_index[path] = file_obj
    
    def get_or_create_path_context(self, path: str, is_dir=False, timestamp=None, pkt=None) -> FileObject:
        if path in self.path_index:
            return self.path_index[path]

        synthetic_id = f"path:{path}"
        obj = self.get_or_create(synthetic_id)
        obj.mark_context_only()
        obj.mark_directory(is_dir)

        self.bind_path(obj, path, timestamp=timestamp)

        event_pkt = dict(pkt or {})
        event_pkt.setdefault("timestamp", timestamp)
        event_pkt.setdefault("smb2_command_name", "QUERY_DIRECTORY/QUERY_INFO")

        obj.add_event(
            "context_seen",
            event_pkt,
            evidence={
                "synthetic_id": synthetic_id,
            },
        )

        return obj
    
    def normalize_file_id(self, file_id):
        if file_id is None:
            return None
        if isinstance(file_id, bytes):
            return file_id.hex()
        if isinstance(file_id, bytearray):
            return bytes(file_id).hex()
        if isinstance(file_id, memoryview):
            return file_id.tobytes().hex()
        return str(file_id)
