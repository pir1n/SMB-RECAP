import resource
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import ipaddress

from scapy.all import SMB2_Header
from scapy.utils import RawPcapReader
from scapy.layers.smb2 import (
    SMB2_Create_Request, SMB2_Create_Response,
    SMB2_Read_Request, SMB2_Read_Response,
    SMB2_Write_Request, SMB2_Write_Response,
    SMB2_Query_Info_Request, SMB2_Query_Info_Response,
    SMB2_Set_Info_Request,
)

try:
    from scapy.layers.smb2 import SMB2_Close_Request, SMB2_Close_Response
except ImportError:
    SMB2_Close_Request = None
    SMB2_Close_Response = None

from smbmount.parser.smb2_extractors import (
    get_smb2_create_metadata,
    get_smb2_info,
    get_smb2_metadata_scf,
    get_smb2_payload,
)
from smbmount.parser.utils import safe_get


FlowKey = Tuple[str, str, int, int]


def _find_smb2_payload_layer(payload_pkt):
    payload_classes = [
        SMB2_Create_Request,
        SMB2_Create_Response,
        SMB2_Read_Request,
        SMB2_Read_Response,
        SMB2_Write_Request,
        SMB2_Write_Response,
        SMB2_Query_Info_Response,
        SMB2_Query_Info_Request,
        SMB2_Set_Info_Request,
    ]
    if SMB2_Close_Request is not None:
        payload_classes.append(SMB2_Close_Request)
    if SMB2_Close_Response is not None:
        payload_classes.append(SMB2_Close_Response)

    for layer_cls in payload_classes:
        if payload_pkt.haslayer(layer_cls):
            return payload_pkt[layer_cls]
    return None


def _rss_mb() -> float:
    rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss_kb / 1024.0


def _metadata_timestamp(meta) -> Optional[float]:
    if hasattr(meta, "sec") and hasattr(meta, "usec"):
        return float(meta.sec) + (float(meta.usec) / 1_000_000.0)

    if hasattr(meta, "tshigh") and hasattr(meta, "tslow"):
        resolution = float(getattr(meta, "tsresol", 1_000_000) or 1_000_000)
        ticks = (int(meta.tshigh) << 32) + int(meta.tslow)
        return ticks / resolution

    return None


def _parse_raw_tcp_packet(raw: bytes, linktype: Optional[int]):
    if linktype not in (None, 1):
        return None

    if len(raw) < 14:
        return None

    eth_type = int.from_bytes(raw[12:14], "big")
    offset = 14

    while eth_type in (0x8100, 0x88A8):
        if len(raw) < offset + 4:
            return None
        eth_type = int.from_bytes(raw[offset + 2:offset + 4], "big")
        offset += 4

    if eth_type == 0x0800:
        if len(raw) < offset + 20:
            return None

        ihl = (raw[offset] & 0x0F) * 4
        if ihl < 20 or len(raw) < offset + ihl:
            return None

        proto = raw[offset + 9]
        if proto != 6:
            return None

        src_ip = str(ipaddress.IPv4Address(raw[offset + 12:offset + 16]))
        dst_ip = str(ipaddress.IPv4Address(raw[offset + 16:offset + 20]))
        tcp_offset = offset + ihl

    elif eth_type == 0x86DD:
        if len(raw) < offset + 40:
            return None

        next_header = raw[offset + 6]
        if next_header != 6:
            return None

        src_ip = str(ipaddress.IPv6Address(raw[offset + 8:offset + 24]))
        dst_ip = str(ipaddress.IPv6Address(raw[offset + 24:offset + 40]))
        tcp_offset = offset + 40

    else:
        return None

    if len(raw) < tcp_offset + 20:
        return None

    src_port = int.from_bytes(raw[tcp_offset:tcp_offset + 2], "big")
    dst_port = int.from_bytes(raw[tcp_offset + 2:tcp_offset + 4], "big")
    seq = int.from_bytes(raw[tcp_offset + 4:tcp_offset + 8], "big")
    data_offset = (raw[tcp_offset + 12] >> 4) * 4

    if data_offset < 20 or len(raw) < tcp_offset + data_offset:
        return None

    payload = raw[tcp_offset + data_offset:]

    return src_ip, dst_ip, src_port, dst_port, seq, payload


def _basic_record(
    timestamp: Optional[float],
    frame_number: int,
    flow_key: FlowKey,
) -> Dict[str, Any]:
    return {
        "frame_number": frame_number,
        "timestamp": timestamp,
        "highest_layer": "SMB2",
        "src_ip": flow_key[0],
        "dst_ip": flow_key[1],
        "src_port": flow_key[2],
        "dst_port": flow_key[3],
        "tcp_stream": None,
        "has_smb2": True,
    }


def _extract_smb2_records(
    smb_payload: bytes,
    timestamp: Optional[float],
    frame_number: int,
    flow_key: FlowKey,
) -> List[Dict[str, Any]]:
    records = []
    pos = 0

    while pos < len(smb_payload):
        magic = smb_payload.find(b"\xfeSMB", pos)
        if magic < 0:
            break
        if magic + 64 > len(smb_payload):
            break

        try:
            next_cmd = int.from_bytes(smb_payload[magic + 20:magic + 24], "little")
            end = magic + next_cmd if next_cmd > 0 else len(smb_payload)
            raw_smb2 = smb_payload[magic:end]
            smb2_hdr = SMB2_Header(raw_smb2)
            cmd = safe_get(smb2_hdr, "Command")
            is_response = bool((safe_get(smb2_hdr, "Flags") or 0) & 0x01)
            payload_layer = _find_smb2_payload_layer(smb2_hdr)

            record = _basic_record(timestamp, frame_number, flow_key)
            record.update(get_smb2_info(smb2_hdr))
            record.update(
                get_smb2_payload(
                    payload_layer,
                    raw_smb2=raw_smb2,
                    cmd=cmd,
                    is_response=is_response,
                )
            )
            record.update(get_smb2_create_metadata(payload_layer))
            record.update(
                get_smb2_metadata_scf(
                    payload_layer,
                    raw_smb2=raw_smb2,
                    cmd=cmd,
                    is_response=is_response,
                )
            )
            records.append(record)

            if next_cmd > 0:
                pos = end
            else:
                break
        except Exception:
            pos = magic + 4

    return records


def _pop_nbss_messages(buffer: bytearray, max_message_size: int) -> Iterable[bytes]:
    while True:
        if len(buffer) < 4:
            return

        msg_type = buffer[0]
        msg_len = int.from_bytes(buffer[1:4], "big")

        if msg_type != 0x00 or msg_len <= 0 or msg_len > max_message_size:
            magic = buffer.find(b"\xfeSMB")
            if magic > 0:
                del buffer[:magic]
                continue
            if magic == 0:
                msg = bytes(buffer)
                del buffer[:]
                yield msg
                return
            del buffer[:1]
            continue

        frame_len = 4 + msg_len
        if len(buffer) < frame_len:
            return

        msg = bytes(buffer[4:frame_len])
        del buffer[:frame_len]
        yield msg


@dataclass
class FlowState:
    expected_seq: Optional[int] = None
    buffer: bytearray = field(default_factory=bytearray)
    pending: Dict[int, bytes] = field(default_factory=dict)
    gaps: int = 0

    def feed(self, seq: int, payload: bytes) -> bool:
        if not payload:
            return False

        if self.expected_seq is None:
            self.expected_seq = seq

        if seq < self.expected_seq:
            overlap = self.expected_seq - seq
            if overlap >= len(payload):
                return False
            payload = payload[overlap:]
            seq = self.expected_seq

        if seq == self.expected_seq:
            self.buffer.extend(payload)
            self.expected_seq += len(payload)

            while self.expected_seq in self.pending:
                next_payload = self.pending.pop(self.expected_seq)
                self.buffer.extend(next_payload)
                self.expected_seq += len(next_payload)

            return True

        # Packet loss creates a permanent TCP sequence gap. The old behavior
        # kept all later packets pending forever, which made lossy captures
        # reconstruct almost nothing. For reconstruction, abandon the broken
        # fragment and resynchronize from the next observed payload.
        self.gaps += 1
        self.buffer.clear()
        self.pending.clear()
        self.buffer.extend(payload)
        self.expected_seq = seq + len(payload)
        return True


def read_pcap_reconstruction_streaming(
    input_pcap: str,
    progress_interval_packets: int = 100_000,
    max_message_size: int = 256 * 1024 * 1024,
) -> List[Dict[str, Any]]:
    """
    Stream PCAP/PCAPNG packet-by-packet and emit lightweight SMB2 records.

    This path avoids rdpcap() and parses SMB over TCP NBSS frames from a small
    per-flow reassembly buffer. It is intended for parse-pcap reconstruction;
    SCF keeps using the legacy reader.
    """
    input_path = Path(input_pcap)
    if not input_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file PCAP: {input_pcap}")

    flows: Dict[FlowKey, FlowState] = {}
    packets: List[Dict[str, Any]] = []
    tcp_payload_packets = 0
    tcp_payload_bytes = 0

    print("Streaming PCAP file...")

    reader = RawPcapReader(str(input_path))
    try:
        for frame_number, (raw, meta) in enumerate(reader, start=1):
            parsed = _parse_raw_tcp_packet(raw, getattr(meta, "linktype", None))
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, seq, payload = parsed
            if src_port != 445 and dst_port != 445:
                continue

            if not payload:
                continue

            tcp_payload_packets += 1
            tcp_payload_bytes += len(payload)

            flow_key = (src_ip, dst_ip, src_port, dst_port)
            flow = flows.setdefault(flow_key, FlowState())
            appended = flow.feed(seq, payload)

            if appended:
                for smb_msg in _pop_nbss_messages(flow.buffer, max_message_size):
                    packets.extend(
                        _extract_smb2_records(
                            smb_msg,
                            _metadata_timestamp(meta),
                            frame_number,
                            flow_key,
                        )
                    )

            if (
                progress_interval_packets
                and tcp_payload_packets % progress_interval_packets == 0
            ):
                print(
                    "[stream] "
                    f"packets={tcp_payload_packets} "
                    f"bytes={tcp_payload_bytes} "
                    f"smb_records={len(packets)} "
                    f"active_flows={len(flows)} "
                    f"rss_mb={_rss_mb():.1f}"
                )
    finally:
        reader.close()

    print(
        "[stream] complete: "
        f"packets={tcp_payload_packets} "
        f"bytes={tcp_payload_bytes} "
        f"smb_records={len(packets)} "
        f"active_flows={len(flows)} "
        f"rss_mb={_rss_mb():.1f}"
    )

    return packets
