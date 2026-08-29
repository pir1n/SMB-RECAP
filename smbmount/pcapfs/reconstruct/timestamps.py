def normalize_timestamp(value):
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    try:
        return float(value)
    except Exception:
        return None


class TimestampResolver:
    """
    mode:
    - network: dùng timestamp packet PCAP
    - fs: dùng filesystem timestamp nếu có
    - hybrid: event dùng network, version/metadata dùng fs nếu có
    """

    VALID_MODES = {"network", "fs", "hybrid"}

    def __init__(self, mode="hybrid"):
        if mode not in self.VALID_MODES:
            raise ValueError(f"Invalid timestamp mode: {mode}")
        self.mode = mode

    def network_time(self, pkt):
        return normalize_timestamp(pkt.get("timestamp"))

    def fs_modified_time(self, pkt):
        return (
            normalize_timestamp(pkt.get("smb2_last_write_time"))
            or normalize_timestamp(pkt.get("smb2_change_time"))
            or normalize_timestamp(pkt.get("smb2_last_access_time"))
            or normalize_timestamp(pkt.get("smb2_create_time"))
        )

    def event_time(self, pkt):
        if self.mode == "network":
            return self.network_time(pkt)

        if self.mode == "fs":
            return self.fs_modified_time(pkt) or self.network_time(pkt)

        # hybrid
        return self.network_time(pkt)

    def version_time(self, pkt):
        if self.mode == "network":
            return self.network_time(pkt)

        if self.mode == "fs":
            return self.fs_modified_time(pkt) or self.network_time(pkt)

        # hybrid
        return self.fs_modified_time(pkt) or self.network_time(pkt)

    def event_source(self, pkt):
        if self.mode == "network":
            return "network"

        if self.mode == "fs":
            if self.fs_modified_time(pkt) is not None:
                return "fs"
            return "network_fallback"

        return "network"

    def version_source(self, pkt):
        if self.mode == "network":
            return "network"

        if self.fs_modified_time(pkt) is not None:
            return "fs"

        return "network_fallback"

    def snapshot_metadata(self, file_obj, pkt, size=None):
        return {
            "created": pkt.get("smb2_create_time") or file_obj.metadata.created,
            "modified": pkt.get("smb2_last_write_time") or file_obj.metadata.modified,
            "accessed": pkt.get("smb2_last_access_time") or file_obj.metadata.accessed,
            "changed": pkt.get("smb2_change_time") or getattr(file_obj.metadata, "changed", None),
            "size": size if size is not None else file_obj.metadata.size,
            "timestamp_mode": self.mode,
            "version_timestamp_source": self.version_source(pkt),
            "network_timestamp": self.network_time(pkt),
        }

    def annotate_event_packet(self, pkt):
        """
        Copy packet và override timestamp dùng cho FileEvent.
        Không sửa packet gốc.
        """
        event_pkt = dict(pkt)
        event_pkt["timestamp"] = self.event_time(pkt)
        event_pkt["timestamp_source"] = self.event_source(pkt)
        event_pkt["network_timestamp"] = self.network_time(pkt)
        event_pkt["fs_timestamp"] = self.fs_modified_time(pkt)
        event_pkt["timestamp_mode"] = self.mode
        return event_pkt
