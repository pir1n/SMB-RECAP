import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional
from scapy.all import RawPcapReader, TCP, SMB2_Header
from smbmount.reconstruct.content import process_packets
from smbmount.output.fs_export import export_files
from smbmount.reconstruct.hierarchy import build_tree
from smbmount.output.snapshot_export import build_snapshot
from smbmount.parser.utils import *
from smbmount.parser.smb2_constants import *
from smbmount.parser.smb2_extractors import *
from smbmount.parser.tcp_reassembler import (
    StreamingSmb2Reassembler,
    iter_smb2_messages_from_tcp_payload,
    reassemble_tcp_streams,
)
from smbmount.parser.streaming_pcap_reader import read_pcap_reconstruction_streaming

def _find_smb2_payload_layer(payload_pkt):
    payload_classes = [SMB2_Create_Request, SMB2_Create_Response,
                       SMB2_Read_Request, SMB2_Read_Response,
                       SMB2_Write_Request, SMB2_Write_Response,
                       SMB2_Query_Info_Response, SMB2_Query_Info_Request,
                       SMB2_Set_Info_Request]
    if SMB2_Close_Request is not None:
        payload_classes.append(SMB2_Close_Request)
    if SMB2_Close_Response is not None:
        payload_classes.append(SMB2_Close_Response)

    for layer_cls in payload_classes:
        if payload_pkt.haslayer(layer_cls):
            return payload_pkt[layer_cls]
    return None

def _packet_tcp_payload(packet):
    if not packet.haslayer(TCP):
        return b""
    try:
        return bytes(packet[TCP].payload)
    except Exception:
        return b""


def _iter_packet_smb2_messages(packet):
    payload = _packet_tcp_payload(packet)
    if payload:
        messages = list(iter_smb2_messages_from_tcp_payload(payload))
        if messages:
            return messages

    if packet.haslayer(SMB2_Header):
        try:
            return list(iter_smb2_messages_from_tcp_payload(bytes(packet[SMB2_Header])))
        except Exception:
            return []

    return []


def _metadata_timestamp(meta):
    try:
        if hasattr(meta, "tshigh") and hasattr(meta, "tslow"):
            raw_ts = (int(meta.tshigh) << 32) + int(meta.tslow)
            return raw_ts / float(meta.tsresol)
        if hasattr(meta, "sec") and hasattr(meta, "usec"):
            return float(meta.sec) + (float(meta.usec) / 1_000_000)
    except Exception:
        return None
    return None


def _format_ipv4(raw_addr):
    return ".".join(str(part) for part in raw_addr)


def _format_ipv6(raw_addr):
    parts = [raw_addr[i:i + 2].hex() for i in range(0, 16, 2)]
    return ":".join(parts)


def _parse_raw_tcp_packet(raw_frame, timestamp):
    if len(raw_frame) < 14:
        return None

    offset = 14
    eth_type = int.from_bytes(raw_frame[12:14], "big")
    while eth_type in (0x8100, 0x88A8, 0x9100):
        if len(raw_frame) < offset + 4:
            return None
        eth_type = int.from_bytes(raw_frame[offset + 2:offset + 4], "big")
        offset += 4

    if eth_type == 0x0800:
        if len(raw_frame) < offset + 20:
            return None
        version_ihl = raw_frame[offset]
        if version_ihl >> 4 != 4:
            return None
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(raw_frame) < offset + ihl:
            return None
        if raw_frame[offset + 9] != 6:
            return None
        total_len = int.from_bytes(raw_frame[offset + 2:offset + 4], "big")
        ip_end = offset + total_len if total_len else len(raw_frame)
        src_ip = _format_ipv4(raw_frame[offset + 12:offset + 16])
        dst_ip = _format_ipv4(raw_frame[offset + 16:offset + 20])
        tcp_offset = offset + ihl

    elif eth_type == 0x86DD:
        if len(raw_frame) < offset + 40:
            return None
        if raw_frame[offset] >> 4 != 6:
            return None
        payload_len = int.from_bytes(raw_frame[offset + 4:offset + 6], "big")
        next_header = raw_frame[offset + 6]
        if next_header != 6:
            return None
        ip_end = offset + 40 + payload_len
        src_ip = _format_ipv6(raw_frame[offset + 8:offset + 24])
        dst_ip = _format_ipv6(raw_frame[offset + 24:offset + 40])
        tcp_offset = offset + 40

    else:
        return None

    if len(raw_frame) < tcp_offset + 20:
        return None

    src_port = int.from_bytes(raw_frame[tcp_offset:tcp_offset + 2], "big")
    dst_port = int.from_bytes(raw_frame[tcp_offset + 2:tcp_offset + 4], "big")
    if src_port != 445 and dst_port != 445:
        return None

    seq = int.from_bytes(raw_frame[tcp_offset + 4:tcp_offset + 8], "big")
    tcp_header_len = (raw_frame[tcp_offset + 12] >> 4) * 4
    if tcp_header_len < 20:
        return None

    payload_start = tcp_offset + tcp_header_len
    payload_end = min(ip_end, len(raw_frame))
    if payload_start > payload_end:
        return None

    payload = raw_frame[payload_start:payload_end]
    if not payload:
        return None

    basic_info = {
        "frame_number": None,
        "timestamp": timestamp,
        "highest_layer": None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_stream": None,
        "has_smb2": False,
    }
    return basic_info, (src_ip, dst_ip, src_port, dst_port), seq, payload


def _build_smb2_record(basic_info, raw_smb2, tcp_responses, tcp_write_requests):
    smb2_hdr = SMB2_Header(raw_smb2)
    mid = safe_get(smb2_hdr, "MID")
    is_response = bool((safe_get(smb2_hdr, "Flags") or 0) & 0x01)
    cmd = safe_get(smb2_hdr, "Command")
    session_key = (
        basic_info["src_ip"],
        basic_info["dst_ip"],
        basic_info["src_port"],
        basic_info["dst_port"],
    )

    payload_pkt = smb2_hdr
    if is_response and str(cmd) == "8" and mid in tcp_responses.get(session_key, {}):
        payload_pkt = tcp_responses[session_key][mid]
    elif not is_response and str(cmd) == "9":
        session_writes = tcp_write_requests.get(session_key, {})
        if mid in session_writes:
            payload_pkt = session_writes[mid]

    payload_layer = _find_smb2_payload_layer(payload_pkt)

    record = basic_info.copy()
    record.update(get_smb2_info(smb2_hdr))
    record.update(get_smb2_payload(
        payload_layer,
        raw_smb2=raw_smb2,
        cmd=cmd,
        is_response=is_response,
    ))
    record.update(get_smb2_create_metadata(payload_layer))
    record.update(get_smb2_metadata_scf(
        payload_layer,
        raw_smb2=raw_smb2,
        cmd=cmd,
        is_response=is_response,
    ))
    return record


def read_pcap_basic(input_pcap: str) -> List[Dict[str, Any]]:
    """
    Read PCAP/PCAPNG as a stream and extract SMB2 records without rdpcap().
    """
    input_path = Path(input_pcap)
    if not input_path.exists():
        raise FileNotFoundError(f"Khong tim thay file PCAP: {input_pcap}")

    packets: List[Dict[str, Any]] = []

    packet_counter = 0
    smb2_counter = 0
    records_before = len(packets)
    total_packets = 0
    stream_reassembler = StreamingSmb2Reassembler()
    tcp_responses = stream_reassembler.tcp_responses
    tcp_write_requests = stream_reassembler.tcp_write_requests

    print("Reading SMB2 packets from PCAP stream...")
    with RawPcapReader(str(input_path)) as reader:
        for idx, (raw_frame, meta) in enumerate(reader, start=1):
            total_packets = idx
            parsed = _parse_raw_tcp_packet(raw_frame, _metadata_timestamp(meta))
            if parsed is None:
                if idx % 100000 == 0:
                    print(f"Read packet scan: {idx} packets")
                continue

            basic_info, session_key, seq, payload = parsed
            stream_reassembler.feed_tcp(session_key, seq, payload)
            raw_messages = list(iter_smb2_messages_from_tcp_payload(payload))
            if not raw_messages:
                if idx % 100000 == 0:
                    print(f"Read packet scan: {idx} packets")
                continue

            packet_counter += 1
            basic_info["frame_number"] = idx
            basic_info["highest_layer"] = "SMB2"
            basic_info["has_smb2"] = True

            for raw_smb2 in raw_messages:
                try:
                    packets.append(_build_smb2_record(
                        basic_info,
                        raw_smb2,
                        tcp_responses,
                        tcp_write_requests,
                    ))
                    smb2_counter += 1
                except Exception:
                    continue

            if idx % 100000 == 0:
                print(f"Read packet scan: {idx} packets")

    seen_messages = set()
    request_frames = {}
    for record in packets:
        msg_id = safe_int(record.get("smb2_message_id"))
        cmd = safe_int(record.get("smb2_command"))
        is_response = record.get("smb2_is_response")
        session_key = (
            record.get("src_ip"), record.get("dst_ip"),
            record.get("src_port"), record.get("dst_port")
        )
        seen_messages.add((session_key, msg_id, cmd, is_response))
        if is_response is False and msg_id is not None:
            request_frames[(session_key, msg_id)] = record.get("frame_number")

    supplemental_records = []

    def add_reassembled_record(session_key, msg_id, hdr, fallback_cmd, is_response):
        cmd = safe_int(safe_get(hdr, "Command"), fallback_cmd)
        if (session_key, msg_id, cmd, is_response) in seen_messages:
            return

        reverse_key = (session_key[1], session_key[0], session_key[3], session_key[2])
        request_frame = request_frames.get((reverse_key if is_response else session_key, msg_id))
        frame_number = (request_frame + 0.1) if request_frame is not None else None

        payload_layer = _find_smb2_payload_layer(hdr)
        record = {
            "frame_number": frame_number,
            "timestamp": None,
            "highest_layer": "SMB2",
            "src_ip": session_key[0],
            "dst_ip": session_key[1],
            "src_port": session_key[2],
            "dst_port": session_key[3],
            "tcp_stream": None,
            "has_smb2": True,
        }
        record.update(get_smb2_info(hdr))
        record.update(get_smb2_payload(
            payload_layer,
            raw_smb2=bytes(hdr),
            cmd=cmd,
            is_response=is_response,
        ))
        record.update(get_smb2_create_metadata(payload_layer))
        supplemental_records.append(record)
        seen_messages.add((session_key, msg_id, cmd, is_response))

    for session_key, responses in tcp_responses.items():
        for msg_id, hdr in responses.items():
            add_reassembled_record(session_key, msg_id, hdr, 8, True)

    for session_key, requests in tcp_write_requests.items():
        for msg_id, hdr in requests.items():
            add_reassembled_record(session_key, msg_id, hdr, 9, False)

    if supplemental_records:
        packets.extend(supplemental_records)
        packets.sort(key=lambda pkt: (
            pkt.get("frame_number") is None,
            pkt.get("frame_number") if pkt.get("frame_number") is not None else float("inf")
        ))
        print(f"Supplemented {len(supplemental_records)} SMB2 records from reassembled TCP streams")

    records_after = len(packets)
    if records_after - records_before > 3:
        print(f"Read {total_packets} packets and extracted {records_after - records_before} records")
    print(f"\nExtraction complete: {packet_counter} packets with SMB2, {records_after} SMB2 records extracted")
    return packets


def read_pcap_basic_legacy(input_pcap: str) -> List[Dict[str, Any]]:
    from scapy.all import rdpcap

    """
    Đọc PCAP bằng scapy, lọc SMB2, extract thông tin frame/IP/TCP/SMB2 cơ bản.
    Hỗ trợ extract nhiều layer SMB2 trong một packet.
    Hiển thị progress percent.
    """
    input_path = Path(input_pcap)
    if not input_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file PCAP: {input_pcap}")

    packets: List[Dict[str, Any]] = []

    print("Loading PCAP file...")
    capture_raw = rdpcap(str(input_path))
    # capture_tcp = sniff(offline=str(input_path), session=TCPSession)
    
    # Build tcp_responses lookup cho READ fallback
    # New Fix [
    print("Reassembling TCP streams...")
    tcp_responses, tcp_write_requests = reassemble_tcp_streams(capture_raw)
    # print(f"READ responses: {len(tcp_responses)}, WRITE requests: {len(tcp_write_requests)}")
    # New Fix ]

    total_packets = len(capture_raw)
    print(f"Total packets loaded: {total_packets}")

    packet_counter = 0
    smb2_counter = 0
    records_before = len(packets)

    for idx, packet in enumerate(capture_raw):
        # if (idx + 1) % 10 == 0 or idx == total_packets - 1:
        #     print_progress(idx + 1, total_packets, "Reading packets")

        if not packet.haslayer(SMB2_Header):
            continue

        packet_counter += 1
        basic_info = get_basic_packet_info(packet)
        session_key = (basic_info["src_ip"], basic_info["dst_ip"],
               basic_info["src_port"], basic_info["dst_port"])
        # basic_info["frame_number"] = packet_counter
        basic_info["frame_number"] = idx + 1

        # Extract SMB2 layer + payload layer bên dưới
        raw_bytes = bytes(packet[SMB2_Header])
        pos = 0
        while pos < len(raw_bytes):
            magic = raw_bytes.find(b'\xfeSMB', pos)
            if magic == -1:
                break

            smb2_hdr = SMB2_Header(raw_bytes[magic:])
            mid = safe_get(smb2_hdr, "MID")
            # print(f"[READER] type(mid)={type(mid)} mid={mid}")
            is_response = bool((safe_get(smb2_hdr, "Flags") or 0) & 0x01)
            cmd = safe_get(smb2_hdr, "Command")

            if is_response and str(cmd) == "8" and mid in tcp_responses.get(session_key, {}):
                payload_pkt = tcp_responses[session_key][mid]
            elif not is_response and str(cmd) == "9":
                session_writes = tcp_write_requests.get(session_key, {})
                # print(f"[WRITE LOOKUP] mid={mid} session_key={session_key} in_dict={mid in session_writes} available_mids={list(session_writes.keys())[:5]}")
                if mid in session_writes:
                    payload_pkt = tcp_write_requests[session_key][mid]
            else:
                payload_pkt = smb2_hdr

            payload_layer = _find_smb2_payload_layer(payload_pkt)

            record = basic_info.copy()
            record.update(get_smb2_info(smb2_hdr))
            record.update(get_smb2_payload(
                payload_layer,
                raw_smb2=raw_bytes[magic:],
                cmd=cmd,
                is_response=is_response,
            ))
            
            record.update(get_smb2_create_metadata(payload_layer)) # Get metadata from CREATE response and Close response
            record.update(get_smb2_metadata_scf(
                payload_layer,
                raw_smb2=raw_bytes[magic:],
                cmd=cmd,
                is_response=is_response,
            ))
            packets.append(record)
            smb2_counter += 1

            # Advance đến SMB2 message tiếp theo
            next_cmd = safe_get(smb2_hdr, "NextCommand")
            if next_cmd and int(next_cmd) > 0:
                pos = magic + int(next_cmd)
            else:
                break
        
    seen_messages = set()
    request_frames = {}
    for record in packets:
        msg_id = safe_int(record.get("smb2_message_id"))
        cmd = safe_int(record.get("smb2_command"))
        is_response = record.get("smb2_is_response")
        session_key = (
            record.get("src_ip"), record.get("dst_ip"),
            record.get("src_port"), record.get("dst_port")
        )
        seen_messages.add((session_key, msg_id, cmd, is_response))
        if is_response is False and msg_id is not None:
            request_frames[(session_key, msg_id)] = record.get("frame_number")

    supplemental_records = []

    def add_reassembled_record(session_key, msg_id, hdr, fallback_cmd, is_response):
        cmd = safe_int(safe_get(hdr, "Command"), fallback_cmd)
        if (session_key, msg_id, cmd, is_response) in seen_messages:
            return

        reverse_key = (session_key[1], session_key[0], session_key[3], session_key[2])
        request_frame = request_frames.get((reverse_key if is_response else session_key, msg_id))
        frame_number = (request_frame + 0.1) if request_frame is not None else None

        payload_layer = _find_smb2_payload_layer(hdr)
        record = {
            "frame_number": frame_number,
            "timestamp": None,
            "highest_layer": "SMB2",
            "src_ip": session_key[0],
            "dst_ip": session_key[1],
            "src_port": session_key[2],
            "dst_port": session_key[3],
            "tcp_stream": None,
            "has_smb2": True,
        }
        record.update(get_smb2_info(hdr))
        record.update(get_smb2_payload(
            payload_layer,
            raw_smb2=bytes(hdr),
            cmd=cmd,
            is_response=is_response,
        ))
        record.update(get_smb2_create_metadata(payload_layer))
        supplemental_records.append(record)
        seen_messages.add((session_key, msg_id, cmd, is_response))

    for session_key, responses in tcp_responses.items():
        for msg_id, hdr in responses.items():
            add_reassembled_record(session_key, msg_id, hdr, 8, True)

    for session_key, requests in tcp_write_requests.items():
        for msg_id, hdr in requests.items():
            add_reassembled_record(session_key, msg_id, hdr, 9, False)

    if supplemental_records:
        packets.extend(supplemental_records)
        packets.sort(key=lambda pkt: (
            pkt.get("frame_number") is None,
            pkt.get("frame_number") if pkt.get("frame_number") is not None else float("inf")
        ))
        print(f"Supplemented {len(supplemental_records)} SMB2 records from reassembled TCP streams")

    records_after = len(packets)
    if records_after - records_before > 3:
        print(f"Packet {idx+1}: {records_after - records_before} records")
    print(f"\nExtraction complete: {packet_counter} packets with SMB2, {records_after} SMB2 records extracted")
    
    # # Đếm compound packets
    # compound_count = 0
    # for p in capture_raw:
    #     if not p.haslayer(SMB2_Header):
    #         continue
    #     # Check nếu có nhiều SMB2 header liên tiếp
    #     raw_bytes = bytes(p[SMB2_Header])
    #     count = raw_bytes.count(b'\xfeSMB')  # SMB2 magic bytes
    #     if count > 1:
    #         compound_count += 1
    #         print(f"Compound packet: {count} SMB2 messages")

    # print(f"Total compound packets: {compound_count}")
    
    # # Check field names
    # for p in capture_raw:
    #     if p.haslayer(SMB2_Header):
    #         print("SMB2 fields:", p[SMB2_Header].fields.keys())
    #         break

    # # Check compound packets extracted
    # extracted_mids = set(r["smb2_message_id"] for r in packets)
    # print(f"Unique MIDs extracted: {len(extracted_mids)}")
    
    # from collections import Counter
    # mid_counts = Counter(r["smb2_message_id"] for r in packets)
    # print("MID distribution:", dict(mid_counts.most_common(10)))
    # print(f"Total records: {len(packets)}, Unique MIDs: {len(mid_counts)}")
    
    return packets


def enrich_with_request_mapping(packets):
    """
    Mapping SMB2 request <-> response theo MessageId + flow.

    Mục tiêu:
    1. Copy các field quan trọng từ request sang response.
    2. Với CREATE:
       - Request có filename nhưng chưa có FileId.
       - Response có FileId nhưng không có filename.
       => Gắn ngược FileId từ CREATE response về CREATE request.
    3. Lưu FileId -> filename để các packet sau như CLOSE / SET_INFO / READ / WRITE
       có thể biết đang thao tác trên path nào.
    """

    pending = {}       # (client_flow_key, msg_id) -> request packet
    file_context = {}  # (client_flow_key, session_id, tree_id, file_id_key) -> context

    def flow_key(pkt):
        """
        Flow theo hướng packet hiện tại.
        """
        return (
            pkt.get("src_ip"),
            pkt.get("dst_ip"),
            pkt.get("src_port"),
            pkt.get("dst_port"),
        )

    def reverse_flow_key(pkt):
        """
        Flow đảo chiều, dùng để response tìm lại request.
        """
        return (
            pkt.get("dst_ip"),
            pkt.get("src_ip"),
            pkt.get("dst_port"),
            pkt.get("src_port"),
        )

    def client_flow_key(pkt):
        """
        Chuẩn hóa flow về hướng client -> server.
        - Request: src là client, dst là server.
        - Response: src là server, dst là client, nên phải đảo lại.
        """
        if pkt.get("smb2_is_response") is True:
            return reverse_flow_key(pkt)

        return flow_key(pkt)

    def file_id_to_key(file_id):
        """
        Chuẩn hóa FileId để dùng làm dict key.
        FileId trong parser có thể là bytes, bytearray, memoryview hoặc string.
        """
        if file_id is None:
            return None

        if isinstance(file_id, bytes):
            return file_id.hex()

        if isinstance(file_id, bytearray):
            return bytes(file_id).hex()

        if isinstance(file_id, memoryview):
            return file_id.tobytes().hex()

        return str(file_id)

    def build_file_context_key(pkt, file_id, forced_client_flow=None):
        fid_key = file_id_to_key(file_id)

        if fid_key is None:
            return None

        return (
            forced_client_flow or client_flow_key(pkt),
            pkt.get("smb2_session_id"),
            pkt.get("smb2_tree_id"),
            fid_key,
        )

    def copy_field(src, dst, field):
        if src.get(field) is not None and dst.get(field) is None:
            dst[field] = src.get(field)

    def attach_file_context(pkt):
        """
        Nếu packet có FileId, thử gắn filename đã biết từ CREATE trước đó.
        Áp dụng cho CLOSE / SET_INFO / READ / WRITE / QUERY_INFO.
        """
        file_id = pkt.get("smb2_file_id") or pkt.get("mapped_file_id")
        ctx_key = build_file_context_key(pkt, file_id)

        if ctx_key is None:
            return

        ctx = file_context.get(ctx_key)

        if not ctx:
            return

        if pkt.get("mapped_filename") is None and ctx.get("filename") is not None:
            pkt["mapped_filename"] = ctx.get("filename")

        # Giữ tương thích với code cũ đang đọc smb2_filename.
        # Không overwrite nếu packet đã có smb2_filename thật.
        if pkt.get("smb2_filename") is None and ctx.get("filename") is not None:
            pkt["smb2_filename"] = ctx.get("filename")

        if pkt.get("mapped_file_id") is None and ctx.get("file_id") is not None:
            pkt["mapped_file_id"] = ctx.get("file_id")

    scf_fields = [
        "smb2_desired_access_raw",
        "smb2_desired_access",

        "smb2_create_file_attributes_raw",
        "smb2_create_file_attributes",

        "smb2_share_access_raw",
        "smb2_share_access",

        "smb2_create_disposition_raw",
        "smb2_create_disposition",

        "smb2_create_options_raw",
        "smb2_create_options",

        "smb2_info_type",
        "smb2_file_info_class_raw",
        "smb2_file_info_class",

        "smb2_delete_pending",
        "smb2_disposition_flags_raw",
        "smb2_disposition_flags",
        "smb2_rename_target",

        "smb2_query_directory_flags_raw",
        "smb2_query_directory_flags",
        "smb2_query_directory_pattern",
    ]

    request_to_response_fields = [
        "smb2_file_id",
        "mapped_file_id",

        # READ/WRITE context
        "smb2_offset",
        "smb2_length",
        "smb2_read_blob",

        # path context
        "smb2_filename",
        "mapped_filename",

        # QUERY_INFO context
        "smb2_query_info_type",
        "smb2_query_file_class",

        # SET_INFO semantic context
        "smb2_set_info_data",
        "smb2_rename_target",
        "smb2_delete_pending",
        "smb2_disposition_flags_raw",
        "smb2_disposition_flags",
        "smb2_truncate_size",
    ]

    for pkt in packets:
        msg_id = pkt.get("smb2_message_id")
        is_response = pkt.get("smb2_is_response")

        # Trước hết, nếu packet đã có FileId thì thử gắn filename từ context.
        attach_file_context(pkt)

        # Không dùng "if not msg_id" vì MessageId = 0 là hợp lệ.
        if msg_id is None:
            continue

        current_client_flow = client_flow_key(pkt)

        # REQUEST
        if is_response is False:
            pending[(current_client_flow, msg_id)] = pkt

            # Nếu request đã có FileId, ví dụ READ/WRITE/CLOSE/SET_INFO,
            # thì thử enrich filename theo FileId.
            attach_file_context(pkt)
            continue

        # RESPONSE
        if is_response is True:
            req = pending.get((current_client_flow, msg_id))

            if not req:
                continue

            # 1. Copy SCF fields từ request sang response.
            for field in scf_fields:
                copy_field(req, pkt, field)

            # 2. Copy các field request quan trọng sang response.
            for field in request_to_response_fields:
                copy_field(req, pkt, field)

            # 3. Nếu request có filename, response nên có mapped_filename.
            if req.get("smb2_filename") is not None and pkt.get("mapped_filename") is None:
                pkt["mapped_filename"] = req.get("smb2_filename")

            # 4. Nếu response là CREATE response và có FileId do server cấp,
            #    gắn ngược FileId đó vào CREATE request.
            if (
                req.get("smb2_command_name") == "CREATE"
                and pkt.get("smb2_command_name") == "CREATE"
                and pkt.get("smb2_file_id") is not None
            ):
                create_file_id = pkt.get("smb2_file_id")

                req["smb2_file_id"] = create_file_id
                req["mapped_file_id"] = create_file_id
                req["smb2_create_action"] = pkt.get("smb2_create_action")

                pkt["mapped_file_id"] = create_file_id

                if req.get("smb2_filename") is not None:
                    pkt["mapped_filename"] = req.get("smb2_filename")

                # Lưu FileId -> filename để các request sau như CLOSE cùng FileId
                # có thể map ngược ra path.
                ctx_key = build_file_context_key(
                    req,
                    create_file_id,
                    forced_client_flow=current_client_flow,
                )

                if ctx_key is not None:
                    file_context[ctx_key] = {
                        "filename": req.get("smb2_filename"),
                        "file_id": create_file_id,
                        "create_frame": req.get("frame_number"),
                        "create_timestamp": req.get("timestamp"),
                        "create_options_raw": req.get("smb2_create_options_raw"),
                        "desired_access_raw": req.get("smb2_desired_access_raw"),
                    }
                    
                    attach_file_context(req)

            # 5. Sau khi response được bổ sung FileId, thử attach context lại.
            attach_file_context(pkt)

    return packets

def enrich_with_file_metadata_mapping(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    create_metadata_by_file_id: Dict[Any, Dict[str, Any]] = {}
    metadata_fields = [
        "smb2_create_time",
        "smb2_last_access_time", 
        "smb2_last_write_time",
        "smb2_change_time",
        "smb2_allocation_size",
        "smb2_end_of_file",
        "smb2_file_attributes",
        "smb2_oplock_level",
        "smb2_create_action",
    ]

    for pkt in packets:
        file_id = pkt.get("smb2_file_id") or pkt.get("mapped_file_id")
        if file_id is None:
            continue

        cmd = pkt.get("smb2_command_name")
        is_response = pkt.get("smb2_is_response")

        # Chỉ lưu metadata từ CREATE response
        if cmd == "CREATE" and is_response is True:
            create_metadata_by_file_id[file_id] = {
                field: pkt.get(field)
                for field in metadata_fields
                if pkt.get(field) is not None
            }
            continue

        # Chỉ enrich READ/WRITE từ CREATE metadata, không dùng CLOSE
        if cmd in ("READ", "WRITE", "CLOSE", "SET_INFO", "QUERY_INFO"):
            metadata = create_metadata_by_file_id.get(file_id)
            if not metadata:
                continue
            for field, value in metadata.items():
                if pkt.get(field) is None:
                    pkt[field] = value
                # print(pkt)
                # print("-" * 40)

    return packets

def enrich_with_query_info_timestamps(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for pkt in packets:
        if pkt.get("smb2_command_name") != "QUERY_INFO":
            continue
        if not pkt.get("smb2_is_response"):
            continue
        if pkt.get("smb2_query_info_type") != 1:        # phải là SMB2_0_INFO_FILE
            continue
        if pkt.get("smb2_query_file_class") not in (4, 34):  # Basic hoặc NetworkOpen
            continue

        val = pkt.get("smb2_query_info_response_data")
        if not val or len(val) < 32:
            continue

        pkt["smb2_create_time"]      = filetime_to_unix(struct.unpack("<Q", val[0:8])[0])
        pkt["smb2_last_access_time"] = filetime_to_unix(struct.unpack("<Q", val[8:16])[0])
        pkt["smb2_last_write_time"]  = filetime_to_unix(struct.unpack("<Q", val[16:24])[0])
        pkt["smb2_change_time"]      = filetime_to_unix(struct.unpack("<Q", val[24:32])[0])
        
        # print(f"Enriched QUERY_INFO with timestamps: create={pkt['smb2_create_time']}, last_access={pkt['smb2_last_access_time']}, last_write={pkt['smb2_last_write_time']}, change={pkt['smb2_change_time']}")

    return packets

def write_json(data: Any, output_path: str) -> None:
    """
    Ghi JSON UTF-8 đẹp, dễ đọc.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def default_serializer(obj):
        if isinstance(obj, bytes):
            return obj.hex()
        if hasattr(obj, '__float__'):
            return float(obj)
        if hasattr(obj, '__int__'):
            return int(obj)
        return str(obj)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=default_serializer)


def parse_pcap_to_json(
    input_pcap: str,
    output_json: str,
    timestamp_mode: str = "hybrid",
    snapshot_at: float = None,
    snapshot_time_source: str = "network",
    snapshot_include_deleted: bool = True,
    reader: str = "streaming",
) -> None:
    if reader == "streaming":
        packets = read_pcap_reconstruction_streaming(input_pcap)
    elif reader == "legacy":
        packets = read_pcap_basic(input_pcap)
    else:
        raise ValueError(f"Unsupported PCAP reader: {reader}")

    packets = enrich_with_request_mapping(packets)
    packets = enrich_with_file_metadata_mapping(packets)
    packets = enrich_with_query_info_timestamps(packets)

    file_table = process_packets(
        packets,
        timestamp_mode=timestamp_mode,
    )

    tree = build_tree(file_table)

    result = export_files(file_table, tree)
    
    if snapshot_at is not None:
        result["snapshot"] = build_snapshot(
            file_table,
            snapshot_at=snapshot_at,
            time_source=snapshot_time_source,
            include_deleted=snapshot_include_deleted,
        )

    write_json(result, output_json)
    
    return file_table, result

# def parse_pcap_to_json(input_pcap: str, output_json: str) -> None:
#     packets = read_pcap_basic(input_pcap)
#     packets = enrich_with_request_mapping(packets)
#     # Step 1: build session (optional)
#     session = SMBSession()
#     session.build(packets)
    
#     # Step 2: reconstruct files
#     file_table = process_packets(packets)

#     # Step 3: export
#     result = export_files(file_table)

#     write_json(result, output_json)

# def parse_pcap_to_json(input_pcap: str, output_json: str) -> None: # Only use this function for debugging and testing
#     """
#     Hàm chính cho CLI gọi.
#     """
#     packets = read_pcap_basic(input_pcap)
#     packets = enrich_with_request_mapping(packets)
#     write_json(packets, output_json)
