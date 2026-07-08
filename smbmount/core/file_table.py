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

    def write(
        self,
        offset,
        length,
        timestamp=None,
        data=None,
        pkt=None,
        replace_content=False,
        final_size=None,
    ):
        self.add_write(
            offset,
            length,
            data=data,
            timestamp=timestamp,
            pkt=pkt,
            replace_content=replace_content,
            final_size=final_size,
        )

    def commit(self, timestamp=None):
        self.versions.commit(timestamp)

    def update_version_metadata(self, timestamp=None):
        self.versions.update_metadata(
            timestamp,
            file_id=self.file_id,
        )
    
    def add_read(
        self,
        offset,
        length,
        data=None,
        timestamp=None,
        pkt=None,
        expected_size=None,
        allow_after_prior_content=False,
    ):
        data_len = None
        data_md5 = None

        if data is not None:
            try:
                import hashlib

                if isinstance(data, bytes):
                    raw = data
                elif isinstance(data, bytearray):
                    raw = bytes(data)
                elif isinstance(data, memoryview):
                    raw = data.tobytes()
                elif isinstance(data, str):
                    try:
                        raw = bytes.fromhex(data)
                    except ValueError:
                        raw = data.encode(errors="ignore")
                else:
                    raw = bytes(data)

                data_len = len(raw)
                data_md5 = hashlib.md5(raw).hexdigest()
            except Exception:
                pass

        observed = self.versions.add_read(
            offset,
            length,
            data=data,
            timestamp=timestamp,
            file_id=self.file_id,
            expected_size=expected_size,
            allow_after_prior_content=allow_after_prior_content,
        )

        self.add_event(
            "read",
            pkt,
            size_after=self.versions.current_size(),
            evidence={
                "offset": offset,
                "length": length,
                "data_len": data_len,
                "data_md5": data_md5,
                "observed": observed,
                "expected_size": expected_size,
                "allow_after_prior_content": allow_after_prior_content,
            },
        )

        return observed
    
    def add_write(
        self,
        offset,
        length,
        data=None,
        timestamp=None,
        pkt=None,
        replace_content=False,
        final_size=None,
    ):
        self.semantic_write(
            offset,
            length,
            data=data,
            timestamp=timestamp,
            pkt=pkt,
            replace_content=replace_content,
            final_size=final_size,
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

    def semantic_write(
        self,
        offset,
        length,
        data=None,
        timestamp=None,
        pkt=None,
        replace_content=False,
        final_size=None,
    ):
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
            replace_content=replace_content,
            final_size=final_size,
        )

        new_size = self.versions.current_size()

        old_meta_size = self.metadata.size or 0

        if replace_content:
            self.metadata.size = new_size
        else:
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
        self.path_objects: Dict[str, set] = {}

    def get_or_create(self, file_id: str) -> FileObject:
        key = self.normalize_file_id(file_id)

        if key not in self.files:
            self.files[key] = FileObject(file_id)

        return self.files[key]
    
    def version_time_key(self, version):
        """
        Chọn thứ tự thời gian cho content version.

        Ưu tiên network_timestamp trong snapshot_metadata vì:
        - hybrid/fs timestamp có thể trùng nhau giữa nhiều operation gần nhau.
        - scale benchmark cần phân biệt append/overwrite/truncate sát nhau.
        """
        if version is None:
            return float("-inf")

        meta = getattr(version, "snapshot_metadata", None) or {}

        candidates = [
            meta.get("network_timestamp"),
            meta.get("modified"),
            meta.get("changed"),
            getattr(version, "modified", None),
        ]

        for value in candidates:
            if value is None:
                continue

            try:
                return float(value)
            except Exception:
                continue

        return float("-inf")

    def latest_content_for_path(self, path: str, exclude=None):
        """
        Lấy content version mới nhất theo path.

        Không được chọn theo thứ tự dict object, vì SMB có thể dùng nhiều handle/FileId
        cho cùng một file. Phải chọn version có timestamp mới nhất.
        """
        best_version = None
        best_key = (float("-inf"), -1)

        for obj in self.objects_for_path(path):
            if obj is exclude:
                continue

            candidate = obj.versions.latest_content_version()

            if candidate is None:
                continue

            key = (
                self.version_time_key(candidate),
                int(getattr(candidate, "version_id", -1) or -1),
            )

            if key > best_key:
                best_key = key
                best_version = candidate

        return best_version

    def bind_path(self, file_obj: FileObject, path: str, timestamp=None):
        if not path:
            return

        if file_obj.path == path:
            self.path_index[path] = file_obj
            self.path_objects.setdefault(path, set()).add(
                self.normalize_file_id(file_obj.file_id)
            )
            return

        file_obj.versions.set_base_version(
            self.latest_content_for_path(path, exclude=file_obj)
        )

        # Xóa mọi path cũ đang trỏ tới cùng object,
        # vì path_index chỉ nên biểu diễn current path.
        stale_paths = [
            old_path
            for old_path, obj in self.path_index.items()
            if obj is file_obj and old_path != path
        ]

        for old_path in stale_paths:
            del self.path_index[old_path]
            keys = self.path_objects.get(old_path)
            if keys is not None:
                keys.discard(self.normalize_file_id(file_obj.file_id))
                if not keys:
                    del self.path_objects[old_path]

        file_obj.set_path(path, timestamp=timestamp)
        self.path_index[path] = file_obj
        self.path_objects.setdefault(path, set()).add(
            self.normalize_file_id(file_obj.file_id)
        )
    
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

    def objects_for_path(self, path: str):
        if not path:
            return []

        keys = self.path_objects.get(path)
        if not keys:
            return []

        return [
            self.files[key]
            for key in list(keys)
            if key in self.files and self.files[key].path == path
        ]


    def best_content_object_for_path(self, path: str, exclude=None):
        """
        Chọn object đại diện cho file content tại path cũ.

        Ưu tiên object có content version mới nhất, không chỉ object có nhiều version nhất.
        """
        best_obj = None
        best_key = (0, float("-inf"), -1)

        for obj in self.objects_for_path(path):
            if obj is exclude:
                continue

            versions = getattr(obj.versions, "versions", []) or []

            content_versions = [
                v for v in versions
                if getattr(v, "last_op", None) in ("write", "truncate", "read")
            ]

            if not content_versions:
                continue

            latest = max(
                content_versions,
                key=lambda v: (
                    self.version_time_key(v),
                    int(getattr(v, "version_id", -1) or -1),
                ),
            )

            key = (
                len(content_versions),
                self.version_time_key(latest),
                int(getattr(latest, "version_id", -1) or -1),
            )

            if key > best_key:
                best_key = key
                best_obj = obj

        if best_obj is not None:
            return best_obj

        return self.path_index.get(path)


    def rename_path(self, handle_obj, old_path: str, new_path: str, pkt=None, timestamp=None):
        """
        Apply rename ở mức path, không chỉ ở handle hiện tại.

        Lý do:
        SMB rename có thể dùng handle khác với handle đã WRITE.
        Nếu chỉ rename handle hiện tại thì content versions vẫn nằm ở old_path.
        """
        if not old_path or not new_path:
            return handle_obj

        # Object có content thật ở old_path.
        target_obj = self.best_content_object_for_path(
            old_path,
            exclude=None,
        )

        if target_obj is None:
            target_obj = handle_obj

        # Gắn rename event vào object có content.
        target_obj.add_event(
            "rename",
            pkt,
            old_path=old_path,
            new_path=new_path,
            evidence={
                "file_info_class": (pkt or {}).get("smb2_file_info_class"),
            },
        )

        # Tất cả object đang ở old_path phải chuyển sang new_path
        # để export không còn tạo file report.txt riêng.
        old_path_objects = self.objects_for_path(old_path)

        for obj in old_path_objects:
            obj.set_path(new_path, timestamp=timestamp)

        # Handle rename hiện tại cũng chuyển sang new_path để events được group chung.
        if handle_obj is not None:
            handle_obj.set_path(new_path, timestamp=timestamp)

        # Update path_index.
        if old_path in self.path_index:
            del self.path_index[old_path]

        self.path_index[new_path] = target_obj

        old_keys = self.path_objects.pop(old_path, set())

        for obj in old_path_objects:
            old_keys.add(self.normalize_file_id(obj.file_id))

        if handle_obj is not None:
            old_keys.add(self.normalize_file_id(handle_obj.file_id))

        if old_keys:
            self.path_objects.setdefault(new_path, set()).update(old_keys)

        return target_obj
