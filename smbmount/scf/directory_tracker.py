from dataclasses import dataclass, field


def _file_id(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return None if value is None else str(value)


def _server(pkt):
    return pkt.get("src_ip") if pkt.get("smb2_is_response") else pkt.get("dst_ip")


@dataclass
class DirectoryEnumeration:
    key: tuple
    path: str = None
    pages: int = 0
    total_bytes: int = 0
    returned_names: list = field(default_factory=list)
    end_of_search: bool = False
    frames: list = field(default_factory=list)


class DirectoryTracker:
    """Assemble QUERY_DIRECTORY pages without inferring entries from byte size."""

    def __init__(self):
        self._active = {}
        self._completed = []

    def _key(self, packet):
        fid = _file_id(packet.get("smb2_file_id") or packet.get("mapped_file_id"))
        if fid is None:
            return None
        return (
            _server(packet),
            packet.get("smb2_session_id"),
            packet.get("smb2_tree_id"),
            fid,
            packet.get("handle_generation", 1),
        )

    def update(self, packet):
        if packet.get("smb2_is_response") is not False:
            return None
        if packet.get("smb2_command_name") != "QUERY_DIRECTORY":
            return None
        key = self._key(packet)
        if key is None:
            packet["directory_state"] = "unresolved"
            return None
        flags = packet.get("smb2_query_directory_flags_raw") or 0
        enumeration = self._active.get(key)
        if enumeration is None or flags & 0x01:
            if enumeration is not None:
                self._completed.append(enumeration)
            enumeration = DirectoryEnumeration(
                key=key,
                path=packet.get("mapped_filename") or packet.get("smb2_filename"),
            )
            self._active[key] = enumeration
        enumeration.pages += 1
        enumeration.total_bytes += packet.get("smb2_query_total_bytes") or 0
        for name in packet.get("smb2_query_returned_names") or []:
            if name not in enumeration.returned_names:
                enumeration.returned_names.append(name)
        frame = packet.get("frame_number")
        if frame is not None:
            enumeration.frames.append(frame)
        enumeration.end_of_search = bool(packet.get("smb2_query_end_of_search"))
        packet["smb2_query_page_index"] = enumeration.pages
        packet["smb2_query_aggregate_entry_count"] = len(enumeration.returned_names)
        packet["smb2_query_aggregate_returned_names"] = list(enumeration.returned_names)
        packet["smb2_query_aggregate_total_bytes"] = enumeration.total_bytes
        packet["directory_state"] = "complete" if enumeration.end_of_search else "open"
        if enumeration.end_of_search:
            self._completed.append(enumeration)
            self._active.pop(key, None)
        return enumeration

    def track(self, packets):
        for packet in packets:
            self.update(packet)
        return packets

    def completed_enumerations(self):
        return list(self._completed)

