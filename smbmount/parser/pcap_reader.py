import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional
from scapy.all import rdpcap, TCP, Raw, SMB2_Header, sniff
from smbmount.reconstruct.content import process_packets
from smbmount.output.fs_export import export_files
from smbmount.reconstruct.hierarchy import build_tree
from smbmount.parser.utils import *
from smbmount.parser.smb2_constants import *
from smbmount.parser.smb2_extractors import *
from smbmount.parser.tcp_reassembler import reassemble_tcp_streams

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

def read_pcap_basic(input_pcap: str) -> List[Dict[str, Any]]:
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
    pending = {}  # (session_key, msg_id) → pkt

    for pkt in packets:
        msg_id = pkt.get("smb2_message_id")
        is_response = pkt.get("smb2_is_response")
        
        if not msg_id:
            continue

        # Build session key từ packet
        session_key = (
            pkt.get("src_ip"), pkt.get("dst_ip"),
            pkt.get("src_port"), pkt.get("dst_port")
        )
        # Response có src/dst ngược với request
        reverse_key = (
            pkt.get("dst_ip"), pkt.get("src_ip"),
            pkt.get("dst_port"), pkt.get("src_port")
        )

        if not is_response:
            pending[(session_key, msg_id)] = pkt
        else:
            req = pending.get((reverse_key, msg_id))
            if not req:
                continue
            
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

                "smb2_query_directory_flags_raw",
                "smb2_query_directory_flags",
                "smb2_query_directory_pattern",
            ]

            for field in scf_fields:
                if req.get(field) is not None and pkt.get(field) is None:
                    pkt[field] = req.get(field)
            
                          
            # copy thông tin quan trọng từ request
            if req.get("smb2_file_id") is not None:
                pkt["smb2_file_id"] = req.get("smb2_file_id")
            if req.get("smb2_offset") is not None:
                pkt["smb2_offset"] = req.get("smb2_offset")
            if req.get("smb2_length") is not None:
                pkt["smb2_length"] = req.get("smb2_length")
            if req.get("smb2_filename") is not None:
                pkt["smb2_filename"] = req.get("smb2_filename")
            if req.get("smb2_query_info_type") is not None:
                pkt["smb2_query_info_type"] = req["smb2_query_info_type"]
            if req.get("smb2_query_file_class") is not None:
                pkt["smb2_query_file_class"] = req["smb2_query_file_class"]

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
        file_id = pkt.get("smb2_file_id")
        if not file_id:
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
        if cmd in ("READ", "WRITE"):
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


def parse_pcap_to_json(input_pcap: str, output_json: str) -> None:
    packets = read_pcap_basic(input_pcap)
    packets = enrich_with_request_mapping(packets)
    packets = enrich_with_file_metadata_mapping(packets)
    packets = enrich_with_query_info_timestamps(packets)

    file_table = process_packets(packets)

    tree = build_tree(file_table)

    result = export_files(file_table, tree)

    write_json(result, output_json)

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
