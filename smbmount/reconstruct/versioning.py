from copy import deepcopy
import hashlib

class FileVersion:
    def __init__(self, version_id: int, previous=None, inherit_chunks=True, file_id=None):
        self.version_id = version_id
        self.size = previous.size if previous is not None else 0
        self.modified = None
        self.chunks = deepcopy(previous.chunks) if (previous is not None and inherit_chunks) else []
        self.last_op = None
        self.file_id = file_id
        self.snapshot_metadata = None
        self._hasher = hashlib.md5()
        self._data_hash = None
        self.data_chunks = deepcopy(getattr(previous, "data_chunks", [])) if (previous is not None and inherit_chunks) else []
        self.data_map = deepcopy(previous.data_map) if (previous is not None and inherit_chunks) else {}

        if previous is not None and inherit_chunks and not self.data_chunks and self.data_map:
            self.data_chunks = [
                (int(offset), data)
                for offset, data in sorted(self.data_map.items())
            ]

    def add_chunk(self, offset, length, data=None, op=None):
        if offset is None or length is None:
            self.last_op = op
            return

        offset = int(offset)
        length = int(length)

        chunk = (offset, length)
        self.chunks.append(chunk)

        # Cập nhật logical size trước
        self.size = max(int(self.size or 0), offset + length)

        if data is not None:
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

            raw = raw[:length]

            # Lưu delta theo thứ tự phát sinh. Ghép full content chỉ khi get_data/hash cần.
            # Tránh rebuild toàn bộ file trên mỗi READ/WRITE chunk.
            self.data_chunks.append((offset, raw))
            self.data_map[offset] = raw
            self._data_hash = None

        self.last_op = op

    def get_data(self):
        """
        Ghép lại nội dung file từ data_map theo offset.

        data_map:
            offset -> bytes

        Lưu ý:
        - Không return None, luôn return bytes.
        - Dùng self.size làm logical file size.
        - Nếu file sparse hoặc thiếu chunk ở giữa, vùng trống sẽ là b'\\x00'.
        """
        if not self.data_chunks and not self.data_map:
            return b"\x00" * int(self.size or 0)

        chunks = self.data_chunks or [
            (int(offset), data)
            for offset, data in sorted(self.data_map.items())
        ]

        actual_size = max(int(offset) + len(data) for offset, data in chunks)

        logical_size = max(int(self.size or 0), actual_size)

        result = bytearray(logical_size)

        for offset, data in chunks:
            offset = int(offset)

            if offset >= logical_size:
                continue

            end = min(offset + len(data), logical_size)
            result[offset:end] = data[: end - offset]

        return bytes(result)


    def get_hash(self):
        """
        Hash nội dung reconstructed hiện tại.
        Không dùng incremental hasher vì overwrite/truncate làm hash cũ sai.
        """
        if self._data_hash is None:
            data = self.get_data()
            self._data_hash = hashlib.md5(data).hexdigest()

        return self._data_hash
    
    def truncate(self, new_size):
        """
        Cắt logical content của version hiện tại về new_size.

        Ví dụ:
        data = b"Hello World"
        truncate(5) -> b"Hello"
        """
        if new_size is None:
            return

        new_size = int(new_size)

        # Cập nhật logical size
        self.size = new_size

        # Cắt chunks vượt quá new_size
        new_chunks = []
        for offset, length in self.chunks:
            offset = int(offset)
            length = int(length)

            if offset >= new_size:
                continue

            new_length = min(length, new_size - offset)
            if new_length > 0:
                new_chunks.append((offset, new_length))

        self.chunks = new_chunks

        # Cắt data_chunks vượt quá new_size, giữ thứ tự apply delta.
        new_data_chunks = []
        for offset, data in self.data_chunks:
            offset = int(offset)

            if offset >= new_size:
                continue

            keep_len = new_size - offset
            new_data = data[:keep_len]

            if new_data:
                new_data_chunks.append((offset, new_data))

        self.data_chunks = new_data_chunks

        new_data_map = {}
        for offset, data in new_data_chunks:
            new_data_map[offset] = data

        self.data_map = new_data_map

        self.last_op = "truncate"
        self._data_hash = None
    
    def same_content_as(self, other):
        # Nếu cả hai đều có data → so hash
        self_hash = self.get_hash()
        other_hash = other.get_hash()
        empty_hash = hashlib.md5().hexdigest()
        
        # print(f"  self_hash={self_hash} other_hash={other_hash} empty={empty_hash}")
        # print(f"  self_empty={self_hash == empty_hash} other_empty={other_hash == empty_hash}")
        
        if self_hash != empty_hash and other_hash != empty_hash:
            return self_hash == other_hash
        # Fallback: so size nếu không có data
        return self.size == other.size and self.size == 0
            
class VersionManager:
    def __init__(self):
        self.versions = []
        self.current = None
        
    def start_new_version(self, timestamp=None, inherit=True, inherit_chunks=True, file_id=None):
        version_id = len(self.versions) + 1

        previous = None
        if inherit:
            previous = self.current or (self.versions[-1] if self.versions else None)

        v = FileVersion(
            version_id,
            previous,
            inherit_chunks=inherit_chunks,
            file_id=file_id,
        )

        v.modified = timestamp
        self.versions.append(v)
        self.current = v

        return v

    def current_size(self):
        if self.current is not None:
            return self.current.size

        if self.versions:
            return self.versions[-1].size

        return 0
    
    def open_session(self, timestamp=None, file_id=None):
        if self.current is None:
            self.start_new_version(timestamp, inherit=bool(self.versions), file_id=file_id)
        elif timestamp is not None:
            self.current.modified = timestamp

    def commit(self, timestamp=None):
        if self.current is not None and timestamp is not None:
            self.current.modified = timestamp
        self.current = None

    def update_metadata(self, timestamp=None, file_id=None):
        if timestamp is None:
            return

        if self.current is None:
            self.start_new_version(
                timestamp,
                inherit=bool(self.versions),
                file_id=file_id,
            )
            return

        if self.current.modified is not None and self.current.modified != timestamp:
            self.commit(self.current.modified)
            self.start_new_version(
                timestamp,
                inherit=True,
                file_id=file_id,
            )
            return

        self.current.modified = timestamp
    
    def add_chunk(self, offset, length, timestamp=None, data=None, op=None, file_id=None):
        if self.current is None:
            self.start_new_version(
                timestamp,
                inherit=bool(self.versions),
                file_id=file_id,
            )

        elif timestamp is not None and self.current.modified is None:
            self.current.modified = timestamp

        self.current.add_chunk(
            offset,
            length,
            data=data,
            op=op,
        )
        
    def add_read(self, offset, length, data=None, timestamp=None, file_id=None):
        if self.current is None:
            self.start_new_version(
                timestamp,
                inherit=bool(self.versions),
                file_id=file_id,
            )

        elif self.current.last_op == "write":
            # READ sau WRITE không làm thay đổi server state,
            # nhưng ta tách version để phân biệt evidence read/write.
            # inherit=True để không mất dữ liệu vừa write.
            self.commit(self.current.modified)
            self.start_new_version(
                timestamp,
                inherit=True,
                file_id=file_id,
            )

        elif timestamp is not None and self.current.modified is None:
            self.current.modified = timestamp

        self.current.add_chunk(
            offset,
            length,
            data=data,
            op="read",
        )

    def add_write(self, offset, length, data=None, timestamp=None, file_id=None):
        if offset is None or length is None:
            return

        offset = int(offset)
        length = int(length)

        if self.current is None:
            self.start_new_version(
                timestamp,
                inherit=bool(self.versions),
                file_id=file_id,
            )

        elif self.current.last_op == "read":
            # WRITE sau READ nghĩa là bắt đầu một state mới của file.
            # Phải inherit=True để giữ nội dung cũ rồi apply phần write mới.
            self.commit(self.current.modified)
            self.start_new_version(
                timestamp,
                inherit=True,
                file_id=file_id,
            )

        elif self.current.last_op == "write":
            expected_offset = self.current.size

            if offset < expected_offset:
                # Ghi đè hoặc ghi overlap.
                # Đây là version mới, nhưng phải inherit=True để giữ phần không bị ghi đè.
                self.commit(self.current.modified)
                self.start_new_version(
                    timestamp,
                    inherit=True,
                    file_id=file_id,
                )

            elif timestamp is not None and self.current.modified is None:
                self.current.modified = timestamp

        elif timestamp is not None and self.current.modified is None:
            self.current.modified = timestamp

        self.current.add_chunk(
            offset,
            length,
            data=data,
            op="write",
        )
        
    def truncate(self, new_size, timestamp=None, file_id=None):
        if new_size is None:
            return

        new_size = int(new_size)

        if self.current is None:
            self.start_new_version(
                timestamp,
                inherit=bool(self.versions),
                file_id=file_id,
            )

        elif self.current.last_op in ("read", "write"):
            # Truncate là operation thay đổi state file.
            # Tạo version mới nhưng inherit content cũ rồi cắt.
            self.commit(self.current.modified)
            self.start_new_version(
                timestamp,
                inherit=True,
                file_id=file_id,
            )

        self.current.truncate(new_size)
        self.current.modified = timestamp
    
    # def deduplicated_versions(self, file_id=None, path=None):
    #     deduped = []
    #     for version in self.versions:
    #         # print(f"[DEDUP LOOP] v{version.version_id} op={version.last_op} hash={version.get_hash()}")
    #         if deduped:
    #             prev = deduped[-1]
    #             # print(f"  comparing with deduped[-1] v{deduped[-1].version_id} op={deduped[-1].last_op}")
    #             # print(f"[COMPARE] v{prev.version_id}({prev.last_op}) hash={prev.get_hash()} data={prev.get_data()}")
    #             # print(f"[COMPARE] v{version.version_id}({version.last_op}) hash={version.get_hash()} data={version.get_data()}")
    #         # print(version)
    #         if deduped and version.same_content_as(deduped[-1]):
    #             if version.modified is not None:
    #                 deduped[-1].modified = version.modified
    #             continue
    #         deduped.append(version)

    #     for index, version in enumerate(deduped):
    #         version.version_id = index

    #     return deduped
    
    def deduplicated_versions(self, file_id=None, path=None):
        deduped = []

        for version in self.versions:
            # Bỏ version rỗng không có content và không có operation
            if version.last_op is None and not version.data_map:
                continue

            if deduped and version.same_content_as(deduped[-1]):
                if version.modified is not None:
                    deduped[-1].modified = version.modified
                continue

            deduped.append(version)

        # Đánh số lại để export dễ đọc.
        # Nếu muốn giữ version_id gốc thì bỏ block này.
        for index, version in enumerate(deduped):
            version.version_id = index

        return deduped
