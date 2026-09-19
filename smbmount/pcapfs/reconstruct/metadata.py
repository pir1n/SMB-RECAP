from typing import Dict


class FileMetadata:
    def __init__(self):
        self.created = None
        self.modified = None
        self.accessed = None
        self.changed = None
        self.size = 0

    def update_from_packet(self, pkt: Dict):
        created = pkt.get("smb2_create_time")
        modified = pkt.get("smb2_last_write_time")
        accessed = pkt.get("smb2_last_access_time")
        changed = pkt.get("smb2_change_time")

        if created is not None:
            self.created = created
        if modified is not None:
            self.modified = modified
        if accessed is not None:
            self.accessed = accessed
        if changed is not None:
            self.changed = changed

        # EndOfFile từ CREATE/CLOSE/QUERY_INFO là kích thước file đáng tin hơn READ length.
        eof = pkt.get("smb2_end_of_file")
        if eof is not None:
            try:
                self.size = max(int(self.size or 0), int(eof))
            except Exception:
                pass

        # Chỉ WRITE mới được phép tăng size theo offset + length.
        # Không dùng READ length vì READ length thường là requested length, không phải file size.
        if pkt.get("smb2_command_name") == "WRITE":
            length = pkt.get("smb2_length")
            offset = pkt.get("smb2_offset")

            if length is not None and offset is not None:
                try:
                    self.size = max(int(self.size or 0), int(offset) + int(length))
                except Exception:
                    pass