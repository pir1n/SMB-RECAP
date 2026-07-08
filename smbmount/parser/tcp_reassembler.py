from os import PathLike

from scapy.all import PcapReader, SMB2_Header, SMB2_Read_Response, SMB2_Write_Request
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6


SMB2_MAGIC = b"\xfeSMB"
NBSS_HEADER_LEN = 4
MAX_BUFFER_BYTES = 8 * 1024 * 1024
MAX_MESSAGE_BYTES = 512 * 1024


def _packet_flow_key(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        return None

    if not packet.haslayer(TCP):
        return None

    tcp = packet[TCP]
    return (src_ip, dst_ip, tcp.sport, tcp.dport)


def _tcp_payload(packet):
    if not packet.haslayer(TCP):
        return b""
    try:
        return bytes(packet[TCP].payload)
    except Exception:
        return b""


def _nbss_length(payload, offset):
    if offset + NBSS_HEADER_LEN > len(payload) or payload[offset] != 0:
        return None
    return (
        (payload[offset + 1] << 16)
        | (payload[offset + 2] << 8)
        | payload[offset + 3]
    )


def _split_compound_smb2(body):
    pos = 0
    while pos < len(body):
        magic = body.find(SMB2_MAGIC, pos)
        if magic == -1 or magic + 64 > len(body):
            break

        next_cmd = int.from_bytes(body[magic + 20:magic + 24], "little")
        if next_cmd > 0 and magic + next_cmd <= len(body):
            yield body[magic:magic + next_cmd]
            pos = magic + next_cmd
        else:
            yield body[magic:]
            break


def iter_smb2_messages_from_tcp_payload(payload):
    """
    Yield SMB2 messages from one TCP payload.

    SMB over TCP is normally wrapped in a 4-byte NetBIOS Session Service
    header. If a packet does not contain a complete NBSS frame, the fallback
    SMB2 magic scan still handles small non-fragmented messages.
    """
    pos = 0
    while pos < len(payload):
        nbss_len = _nbss_length(payload, pos)
        if nbss_len is not None and nbss_len > 0:
            frame_end = pos + NBSS_HEADER_LEN + nbss_len
            if frame_end <= len(payload):
                body = payload[pos + NBSS_HEADER_LEN:frame_end]
                for message in _split_compound_smb2(body):
                    yield message[:MAX_MESSAGE_BYTES]
                pos = frame_end
                continue

        magic = payload.find(SMB2_MAGIC, pos)
        if magic == -1:
            break

        if magic >= NBSS_HEADER_LEN:
            nbss_start = magic - NBSS_HEADER_LEN
            nbss_len = _nbss_length(payload, nbss_start)
            frame_end = (
                nbss_start + NBSS_HEADER_LEN + nbss_len
                if nbss_len is not None
                else None
            )
            if frame_end is not None and frame_end <= len(payload):
                body = payload[magic:frame_end]
                for message in _split_compound_smb2(body):
                    yield message[:MAX_MESSAGE_BYTES]
                pos = frame_end
                continue

        for message in _split_compound_smb2(payload[magic:]):
            yield message[:MAX_MESSAGE_BYTES]
        break


class _TcpFlowState:
    def __init__(self):
        self.expected_seq = None
        self.buffer = bytearray()

    def feed(self, seq, payload):
        if not payload:
            return []

        if self.expected_seq is None or seq > self.expected_seq:
            self.buffer.clear()
            self.expected_seq = seq

        if seq < self.expected_seq:
            overlap = self.expected_seq - seq
            if overlap >= len(payload):
                return []
            payload = payload[overlap:]
            seq = self.expected_seq

        if seq != self.expected_seq:
            self.buffer.clear()
            self.expected_seq = seq

        self.buffer.extend(payload)
        self.expected_seq = seq + len(payload)

        if len(self.buffer) > MAX_BUFFER_BYTES:
            magic = self.buffer.rfind(SMB2_MAGIC)
            if magic > 0:
                del self.buffer[:magic]
            if len(self.buffer) > MAX_BUFFER_BYTES:
                del self.buffer[:-NBSS_HEADER_LEN]

        return self._pop_complete_messages()

    def _pop_complete_messages(self):
        messages = []

        while len(self.buffer) >= NBSS_HEADER_LEN:
            if self.buffer[0] != 0:
                magic = self.buffer.find(SMB2_MAGIC)
                if magic == -1:
                    keep = min(len(self.buffer), NBSS_HEADER_LEN - 1)
                    if len(self.buffer) > keep:
                        del self.buffer[:-keep]
                    break
                if magic > 0:
                    # Packet loss can leave a few stray bytes before the next
                    # SMB2 header. If magic == NBSS_HEADER_LEN, deleting
                    # magic - NBSS_HEADER_LEN would delete zero bytes and loop
                    # forever.
                    del self.buffer[:magic]
                    continue
                break

            nbss_len = _nbss_length(self.buffer, 0)
            if nbss_len is None or nbss_len <= 0:
                del self.buffer[0]
                continue

            frame_len = NBSS_HEADER_LEN + nbss_len
            if len(self.buffer) < frame_len:
                break

            body = bytes(self.buffer[NBSS_HEADER_LEN:frame_len])
            del self.buffer[:frame_len]
            messages.extend(_split_compound_smb2(body))

        return [msg[:MAX_MESSAGE_BYTES] for msg in messages]


def _iter_packets(source):
    if isinstance(source, (str, bytes, PathLike)):
        with PcapReader(source) as reader:
            for packet in reader:
                yield packet
    else:
        yield from source


def _record_reassembled_message(key, raw_smb2, tcp_responses, tcp_write_requests):
    if len(raw_smb2) < 64:
        return

    try:
        cmd = int.from_bytes(raw_smb2[12:14], "little")
        flags = int.from_bytes(raw_smb2[16:20], "little")
        mid = int.from_bytes(raw_smb2[24:32], "little")
        is_resp = bool(flags & 0x01)

        if (is_resp and cmd == 8) or (not is_resp and cmd == 9):
            hdr = SMB2_Header(raw_smb2)
            if is_resp and cmd == 8 and hdr.haslayer(SMB2_Read_Response):
                tcp_responses.setdefault(key, {})[mid] = hdr
            elif not is_resp and cmd == 9 and hdr.haslayer(SMB2_Write_Request):
                tcp_write_requests.setdefault(key, {})[mid] = hdr
    except Exception:
        return


class StreamingSmb2Reassembler:
    def __init__(self):
        self.flow_states = {}
        self.tcp_responses = {}
        self.tcp_write_requests = {}

    def feed_tcp(self, key, seq, payload):
        if key is None or not payload:
            return

        state = self.flow_states.setdefault(key, _TcpFlowState())
        for raw_smb2 in state.feed(seq, payload):
            _record_reassembled_message(
                key,
                raw_smb2,
                self.tcp_responses,
                self.tcp_write_requests,
            )

    def feed_packet(self, packet):
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        if tcp.dport != 445 and tcp.sport != 445:
            return

        payload = _tcp_payload(packet)
        if not payload:
            return

        key = _packet_flow_key(packet)
        self.feed_tcp(key, tcp.seq, payload)


def reassemble_tcp_streams(capture_raw):
    """
    Reassemble TCP streams incrementally for SMB READ responses and WRITE
    requests. This avoids materializing the whole PCAP or whole TCP streams in
    memory.
    """
    reassembler = StreamingSmb2Reassembler()
    packet_count = 0

    for packet in _iter_packets(capture_raw):
        packet_count += 1
        reassembler.feed_packet(packet)

        if packet_count % 100000 == 0:
            print(f"Reassembled stream scan: {packet_count} packets")

    return reassembler.tcp_responses, reassembler.tcp_write_requests
