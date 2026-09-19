from dataclasses import dataclass, field


def normalize_file_id(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return None if value is None else str(value)


def server_endpoint(packet):
    return packet.get("src_ip") if packet.get("smb2_is_response") else packet.get("dst_ip")


@dataclass
class HandleState:
    key: tuple
    base_key: tuple
    generation: int
    path: str = None
    opened_at: float = None
    closed_at: float = None
    status: str = "open"
    completion_reason: str = None
    packets: list = field(default_factory=list)
    frames: list = field(default_factory=list)
    read_count: int = 0
    write_count: int = 0
    read_bytes: int = 0
    write_bytes: int = 0
    rename_target: str = None
    delete_pending: bool = False

    def as_dict(self):
        return {
            "state_id": self.key,
            "server": self.base_key[0],
            "session_id": self.base_key[1],
            "tree_id": self.base_key[2],
            "file_id": self.base_key[3],
            "generation": self.generation,
            "path": self.path,
            "opened_at": self.opened_at,
            "closed_at": self.closed_at,
            "status": self.status,
            "completion_reason": self.completion_reason,
            "frames": list(self.frames),
            "read_count": self.read_count,
            "write_count": self.write_count,
            "read_bytes": self.read_bytes,
            "write_bytes": self.write_bytes,
            "rename_target": self.rename_target,
            "delete_pending": self.delete_pending,
            "packets": list(self.packets),
        }


class HandleTracker:
    """Track SMB FileId lifecycles independently of TCP transport channels."""

    def __init__(self):
        self._active = {}
        self._generations = {}
        self._completed = []

    def _base_key(self, packet, file_id=None):
        fid = normalize_file_id(
            file_id if file_id is not None
            else packet.get("smb2_file_id") or packet.get("mapped_file_id")
        )
        if fid is None:
            return None
        return (
            server_endpoint(packet),
            packet.get("smb2_session_id"),
            packet.get("smb2_tree_id"),
            fid,
        )

    def _annotate(self, packet, state):
        if packet is None:
            return
        packet["handle_generation"] = state.generation
        packet["operation_state_id"] = state.key
        packet["handle_state"] = state.status

    def _complete(self, state, reason, timestamp=None):
        if state.status == "complete":
            return state
        state.status = "complete"
        state.completion_reason = reason
        state.closed_at = timestamp
        self._active.pop(state.base_key, None)
        self._completed.append(state)
        for packet in state.packets:
            packet["handle_state"] = "complete"
        return state

    def open(self, create_request, create_response=None):
        file_id = None
        if create_response is not None:
            file_id = create_response.get("smb2_file_id") or create_response.get("mapped_file_id")
        file_id = file_id or create_request.get("smb2_file_id") or create_request.get("mapped_file_id")
        base_key = self._base_key(create_request, file_id)
        if base_key is None:
            create_request["handle_state"] = "unresolved"
            return None
        previous = self._active.get(base_key)
        if previous is not None:
            self._complete(previous, "file_id_reused", create_request.get("timestamp"))
        generation = self._generations.get(base_key, 0) + 1
        self._generations[base_key] = generation
        state = HandleState(
            key=base_key + (generation,),
            base_key=base_key,
            generation=generation,
            path=create_request.get("mapped_filename") or create_request.get("smb2_filename"),
            opened_at=create_request.get("timestamp"),
        )
        self._active[base_key] = state
        self._append_packet(state, create_request)
        self._annotate(create_response, state)
        return state

    def lookup(self, packet):
        base_key = self._base_key(packet)
        if base_key is None:
            return None
        return self._active.get(base_key)

    def _append_packet(self, state, packet):
        if packet is None:
            return
        if packet not in state.packets:
            state.packets.append(packet)
            frame = packet.get("frame_number")
            if frame is not None:
                state.frames.append(frame)
        self._annotate(packet, state)

    def update(self, packet):
        state = self.lookup(packet)
        if state is None:
            if packet.get("smb2_file_id") is not None or packet.get("mapped_file_id") is not None:
                packet["handle_state"] = "unresolved"
            return None
        self._append_packet(state, packet)
        command = packet.get("smb2_command_name")
        length = packet.get("smb2_length") or 0
        if command == "READ":
            state.read_count += 1
            state.read_bytes += length
        elif command == "WRITE":
            state.write_count += 1
            state.write_bytes += length
        elif command == "SET_INFO":
            if packet.get("smb2_rename_target"):
                state.rename_target = packet.get("smb2_rename_target")
            if packet.get("smb2_delete_pending"):
                state.delete_pending = True
        return state

    def close(self, close_request, close_response=None):
        state = self.update(close_request)
        if state is None:
            return None
        self._annotate(close_response, state)
        return self._complete(state, "close", (close_response or close_request).get("timestamp"))

    def retire_tree(self, session_id, tree_id):
        for state in list(self._active.values()):
            if state.base_key[1] == session_id and state.base_key[2] == tree_id:
                self._complete(state, "tree_disconnect")

    def retire_session(self, session_id):
        for state in list(self._active.values()):
            if state.base_key[1] == session_id:
                self._complete(state, "logoff")

    def finalize(self):
        for state in list(self._active.values()):
            self._complete(state, "capture_end")

    def completed_operations(self):
        return [state.as_dict() for state in self._completed]

    @staticmethod
    def _transport_key(packet):
        if packet.get("smb2_is_response"):
            endpoints = (
                packet.get("dst_ip"), packet.get("src_ip"),
                packet.get("dst_port"), packet.get("src_port"),
            )
        else:
            endpoints = (
                packet.get("src_ip"), packet.get("dst_ip"),
                packet.get("src_port"), packet.get("dst_port"),
            )
        return endpoints + (packet.get("smb2_message_id"),)

    def track(self, packets):
        responses = {
            self._transport_key(packet): packet
            for packet in packets
            if packet.get("smb2_is_response") is True
        }
        for packet in packets:
            if packet.get("smb2_is_response") is not False:
                continue
            command = packet.get("smb2_command_name")
            response = responses.get(self._transport_key(packet))
            if command == "CREATE":
                self.open(packet, response)
            elif command == "CLOSE":
                self.close(packet, response)
            elif command == "TREE_DISCONNECT":
                self.retire_tree(packet.get("smb2_session_id"), packet.get("smb2_tree_id"))
            elif command == "LOGOFF":
                self.retire_session(packet.get("smb2_session_id"))
            else:
                state = self.update(packet)
                self._annotate(response, state) if state is not None else None
        self.finalize()
        return packets

