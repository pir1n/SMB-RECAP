import hashlib

class FileVersion:
    def __init__(self, version_id: int, previous=None, inherit_chunks=True, file_id=None):
        self.version_id = version_id
        self.size = previous.size if previous is not None else 0
        self.modified = None
        self.chunks = list(previous.chunks) if (previous is not None and inherit_chunks) else []
        self.last_op = None
        self.file_id = file_id
        self.snapshot_metadata = None
        self._hasher = hashlib.md5()
        self._data_hash = None
        self.data_chunks = list(getattr(previous, "data_chunks", [])) if (previous is not None and inherit_chunks) else []
        self.data_map = {}
        self.expected_size = None
        self.is_observed_complete = False
        self.observed_state = None
        self.observed_coverage_bytes = 0
        self.observed_coverage_ratio = 0.0

        previous_data_map = getattr(previous, "data_map", {}) if previous is not None else {}
        if previous is not None and inherit_chunks and not self.data_chunks and previous_data_map:
            self.data_chunks = [
                (int(offset), data)
                for offset, data in sorted(previous_data_map.items())
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

    def read_range(self, offset, size):
        """
        Return only the requested byte range for FUSE reads.
        Missing sparse/partial regions are exposed as zero bytes, matching get_data().
        """
        offset = int(offset or 0)
        size = int(size or 0)

        if size <= 0:
            return b""

        logical_size = int(self.size or 0)
        if offset >= logical_size:
            return b""

        end = min(offset + size, logical_size)
        result = bytearray(end - offset)

        for chunk_offset, data in self.data_chunks:
            chunk_start = int(chunk_offset)
            chunk_end = chunk_start + len(data or b"")

            if chunk_end <= offset or chunk_start >= end:
                continue

            src_start = max(offset, chunk_start)
            src_end = min(end, chunk_end)
            dst_start = src_start - offset
            data_start = src_start - chunk_start
            result[dst_start:dst_start + (src_end - src_start)] = data[
                data_start:data_start + (src_end - src_start)
            ]

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
    
    def has_full_coverage(self, expected_size):
        if expected_size is None:
            return False

        expected_size = int(expected_size)
        if expected_size <= 0:
            return False

        ranges = []

        for offset, data in self.data_chunks:
            start = int(offset)
            end = start + len(data)
            if end > start:
                ranges.append((start, end))

        if not ranges:
            return False

        ranges.sort()

        covered_until = 0

        for start, end in ranges:
            if start > covered_until:
                return False
            covered_until = max(covered_until, end)
            if covered_until >= expected_size:
                return True

        return covered_until >= expected_size
    
    def coverage_bytes(self, expected_size=None):
        """
        Tính số byte thật sự có dữ liệu trong reconstructed version.

        Dùng cho robustness:
        - coverage == expected_size  -> complete
        - 0 < coverage < expected    -> partial
        - coverage == 0              -> hollow/no content
        """
        ranges = []

        for offset, data in self.data_chunks:
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

        self.data_map = {}

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
        self.base_version = None

    def set_base_version(self, version):
        if self.current is None and not self.versions and version is not None:
            self.base_version = version

    def latest_content_version(self):
        """
        Content base cho reconstruction.

        - write/truncate: mutation state.
        - read: observed baseline/snapshot đã được phân loại là đáng tin.
        """
        if (
            self.current is not None
            and self.current.last_op in ("write", "truncate", "read")
        ):
            return self.current

        for version in reversed(self.versions):
            if version.last_op in ("write", "truncate", "read"):
                return version

        return self.base_version

    def latest_mutation_version(self):
        if (
            self.current is not None
            and self.current.last_op in ("write", "truncate")
        ):
            return self.current

        for version in reversed(self.versions):
            if version.last_op in ("write", "truncate"):
                return version

        if (
            self.base_version is not None
            and self.base_version.last_op in ("write", "truncate")
        ):
            return self.base_version

        return None
        
    def start_new_version(self, timestamp=None, inherit=True, inherit_chunks=True, file_id=None):
        version_id = len(self.versions) + 1

        previous = None
        if inherit:
            previous = self.latest_content_version()

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
        if self.current is not None and self.current.last_op is not None:
            return self.current.size

        if self.versions:
            for version in reversed(self.versions):
                if version.last_op is not None:
                    return version.size

        if self.base_version is not None:
            return self.base_version.size

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
        """
        Metadata-only SMB operations như QUERY_INFO không được tạo content version mới.
        Chúng chỉ cập nhật timestamp cho version hiện tại nếu version đó đã có nội dung.
        """
        if timestamp is None:
            return

        if self.current is None:
            return

        if self.current.last_op in ("write", "truncate", "read", "observed_read"):
            self.current.modified = timestamp

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
    
    def add_read(
        self,
        offset,
        length,
        data=None,
        timestamp=None,
        file_id=None,
        expected_size=None,
        allow_after_prior_content=False,
    ):
        if offset is None or length is None or data is None:
            return False

        offset = int(offset)
        length = int(length)

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

        if not raw:
            return False

        actual_length = min(length, len(raw))
        raw = raw[:actual_length]

        if expected_size is None or int(expected_size or 0) <= 0:
            expected_size = offset + actual_length

        expected_size = int(expected_size)

        current_read_in_progress = (
            self.current is not None
            and self.current.last_op == "read"
            and not getattr(self.current, "is_observed_complete", False)
        )

        # Nếu không phải đang nối tiếp một READ baseline còn thiếu chunk,
        # thì phải quyết định có được tạo READ version mới hay không.
        if not current_read_in_progress:
            # READ sau WRITE/TRUNCATE thường chỉ là verify/cache.
            # Không được biến nó thành observed version.
            if not allow_after_prior_content and self.latest_mutation_version() is not None:
                return False

            # Bắt đầu observed READ baseline thì phải bắt đầu từ offset 0.
            if offset != 0:
                return False

            observed = FileVersion(
                len(self.versions) + 1,
                None,
                inherit_chunks=False,
                file_id=file_id,
            )

            observed.modified = timestamp
            observed.last_op = "read"
            observed.size = expected_size
            observed.expected_size = expected_size
            observed.is_observed_complete = False

            self.versions.append(observed)
            self.current = observed

        # Đang có READ baseline in-progress thì cho phép ghép tiếp chunk offset > 0.
        self.current.expected_size = max(
            int(getattr(self.current, "expected_size", 0) or 0),
            expected_size,
        )

        self.current.add_chunk(
            offset,
            actual_length,
            data=raw,
            op="read",
        )

        self.current.size = max(
            int(self.current.size or 0),
            int(self.current.expected_size or expected_size),
        )

        if timestamp is not None:
            self.current.modified = timestamp

        self.current.file_id = file_id or self.current.file_id

        coverage_bytes = self.current.coverage_bytes(
            self.current.expected_size
        )

        self.current.observed_coverage_bytes = coverage_bytes

        if self.current.expected_size:
            self.current.observed_coverage_ratio = (
                coverage_bytes / int(self.current.expected_size)
            )
        else:
            self.current.observed_coverage_ratio = 0.0

        complete = self.current.has_full_coverage(
            self.current.expected_size
        )

        self.current.is_observed_complete = complete
        self.current.observed_state = "complete" if complete else "partial"

        return complete

    def add_write(
        self,
        offset,
        length,
        data=None,
        timestamp=None,
        file_id=None,
        replace_content=False,
        final_size=None,
    ):
        if offset is None or length is None:
            return

        offset = int(offset)
        length = int(length)

        if self.current is None:
            self.start_new_version(
                timestamp,
                inherit=(bool(self.versions) and not replace_content),
                inherit_chunks=not replace_content,
                file_id=file_id,
            )

        elif self.current.last_op is None and self.latest_mutation_version() is not self.current:
            self.current = None
            self.start_new_version(
                timestamp,
                inherit=True,
                file_id=file_id,
            )

        elif self.current.last_op == "read":
            # WRITE sau observed READ có 2 khả năng:
            # 1. patch/overwrite một phần file cũ  -> inherit=True
            # 2. replace/supersede toàn bộ content -> inherit=False
            self.commit(self.current.modified)

            self.start_new_version(
                timestamp,
                inherit=not replace_content,
                inherit_chunks=not replace_content,
                file_id=file_id,
            )

        elif self.current.last_op == "truncate":
            current_size = int(self.current.size or 0)

            if offset == 0 and length >= current_size:
                pass
            else:
                self.commit(self.current.modified)
                self.start_new_version(
                    timestamp,
                    inherit=True,
                    file_id=file_id,
                )

        elif self.current.last_op == "write":
            expected_offset = int(self.current.size or 0)

            if offset < expected_offset:
                has_prior_committed_content = any(
                    v is not self.current and v.last_op in ("write", "truncate", "read")
                    for v in self.versions
                ) or self.base_version is not None

                if has_prior_committed_content:
                    self.commit(self.current.modified)
                    self.start_new_version(
                        timestamp,
                        inherit=True,
                        file_id=file_id,
                    )

        self.current.add_chunk(
            offset,
            length,
            data=data,
            op="write",
        )

        self.current.modified = timestamp
        self.current.file_id = file_id or self.current.file_id
        
        if final_size is not None:
            final_size = int(final_size)
            self.current.size = final_size

            # Cắt data_map/data_chunks để không giữ tail cũ sau replace.
            new_data_chunks = []
            for chunk_offset, chunk_data in self.current.data_chunks:
                chunk_offset = int(chunk_offset)

                if chunk_offset >= final_size:
                    continue

                keep_len = final_size - chunk_offset
                new_chunk_data = chunk_data[:keep_len]

                if new_chunk_data:
                    new_data_chunks.append((chunk_offset, new_chunk_data))

            self.current.data_chunks = new_data_chunks
            self.current.data_map = {}
            self.current._data_hash = None
        
        
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

        elif self.current.last_op is None and self.latest_mutation_version() is not self.current:
            self.current = None
            self.start_new_version(
                timestamp,
                inherit=True,
                file_id=file_id,
            )

        elif self.current.last_op in ("write", "read"):
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
    
    
    def deduplicated_versions(self, file_id=None, path=None):
        deduped = []

        for version in self.versions:
            # Không bỏ partial READ nữa.
            # Partial READ cần được export để robustness test phân loại partial.
            if version.last_op == "read" and not version.data_chunks:
                continue

            if version.last_op is None and not version.data_chunks:
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
