from scapy.all import PcapReader, TCP, IP, IPv6
import argparse
import json
from datetime import datetime, timezone


SMB2_SIGNATURE = b"\xfeSMB"


COMMAND_MAP = {
    0: "NEGOTIATE",
    1: "SESSION_SETUP",
    2: "LOGOFF",
    3: "TREE_CONNECT",
    4: "TREE_DISCONNECT",
    5: "CREATE",
    6: "CLOSE",
    7: "FLUSH",
    8: "READ",
    9: "WRITE",
    10: "LOCK",
    11: "IOCTL",
    12: "CANCEL",
    13: "ECHO",
    14: "QUERY_DIRECTORY",
    15: "CHANGE_NOTIFY",
    16: "QUERY_INFO",
    17: "SET_INFO",
    18: "OPLOCK_BREAK",
}


CREATE_DISPOSITION_MAP = {
    0x00000000: "FILE_SUPERSEDE",
    0x00000001: "FILE_OPEN",
    0x00000002: "FILE_CREATE",
    0x00000003: "FILE_OPEN_IF",
    0x00000004: "FILE_OVERWRITE",
    0x00000005: "FILE_OVERWRITE_IF",
}


CREATE_OPTIONS_FLAGS = {
    0x00000001: "FILE_DIRECTORY_FILE",
    0x00000002: "FILE_WRITE_THROUGH",
    0x00000004: "FILE_SEQUENTIAL_ONLY",
    0x00000008: "FILE_NO_INTERMEDIATE_BUFFERING",
    0x00000010: "FILE_SYNCHRONOUS_IO_ALERT",
    0x00000020: "FILE_SYNCHRONOUS_IO_NONALERT",
    0x00000040: "FILE_NON_DIRECTORY_FILE",
    0x00000080: "FILE_CREATE_TREE_CONNECTION",
    0x00000100: "FILE_COMPLETE_IF_OPLOCKED",
    0x00000200: "FILE_NO_EA_KNOWLEDGE",
    0x00000400: "FILE_OPEN_REMOTE_INSTANCE",
    0x00000800: "FILE_RANDOM_ACCESS",
    0x00001000: "FILE_DELETE_ON_CLOSE",
    0x00002000: "FILE_OPEN_BY_FILE_ID",
    0x00004000: "FILE_OPEN_FOR_BACKUP_INTENT",
    0x00008000: "FILE_NO_COMPRESSION",
    0x00010000: "FILE_OPEN_REQUIRING_OPLOCK",
    0x00020000: "FILE_DISALLOW_EXCLUSIVE",
    0x00100000: "FILE_RESERVE_OPFILTER",
    0x00200000: "FILE_OPEN_REPARSE_POINT",
    0x00400000: "FILE_OPEN_NO_RECALL",
    0x00800000: "FILE_OPEN_FOR_FREE_SPACE_QUERY",
}


DESIRED_ACCESS_FLAGS = {
    0x00000001: "FILE_READ_DATA",
    0x00000002: "FILE_WRITE_DATA",
    0x00000004: "FILE_APPEND_DATA",
    0x00000008: "FILE_READ_EA",
    0x00000010: "FILE_WRITE_EA",
    0x00000020: "FILE_EXECUTE",
    0x00000040: "FILE_DELETE_CHILD",
    0x00000080: "FILE_READ_ATTRIBUTES",
    0x00000100: "FILE_WRITE_ATTRIBUTES",
    0x00010000: "DELETE",
    0x00020000: "READ_CONTROL",
    0x00040000: "WRITE_DAC",
    0x00080000: "WRITE_OWNER",
    0x00100000: "SYNCHRONIZE",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x02000000: "MAXIMUM_ALLOWED",
    0x10000000: "GENERIC_ALL",
    0x20000000: "GENERIC_EXECUTE",
    0x40000000: "GENERIC_WRITE",
    0x80000000: "GENERIC_READ",
}


FILE_INFO_CLASS_MAP = {
    4: "FileBasicInformation",
    5: "FileStandardInformation",
    9: "FileNameInformation",
    13: "FileDispositionInformation",
    18: "FileAllInformation",
    20: "FileEndOfFileInformation",
    34: "FileNetworkOpenInformation",
    48: "FileNormalizedNameInformation",
    64: "FileDispositionInformationEx",
}


def u16(data: bytes, off: int):
    if off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "little")


def u32(data: bytes, off: int):
    if off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little")


def u64(data: bytes, off: int):
    if off + 8 > len(data):
        return None
    return int.from_bytes(data[off:off + 8], "little")


def hex_bytes(data: bytes):
    return data.hex() if data is not None else None


def flags_to_names(value, mapping):
    if value is None:
        return []
    return [name for bit, name in mapping.items() if value & bit]


def win_filetime_to_iso(value):
    if not value:
        return None

    try:
        unix_ts = (value - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
    except Exception:
        return None


def get_ip_info(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst

    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst

    return None, None


def find_smb2_offsets(tcp_payload: bytes):
    """
    Return offsets of SMB2 headers inside this TCP payload.

    Handles:
    - direct SMB2 payload
    - NetBIOS Session Service prefix
    - compound SMB2 via NextCommand
    """
    offsets = []

    first = tcp_payload.find(SMB2_SIGNATURE)
    if first < 0:
        return offsets

    current = first

    while current >= 0 and current + 64 <= len(tcp_payload):
        if tcp_payload[current:current + 4] != SMB2_SIGNATURE:
            break

        offsets.append(current)

        next_command = u32(tcp_payload, current + 20)

        if not next_command:
            break

        current = current + next_command

    return offsets


def parse_smb2_header(data: bytes, base: int):
    cmd = u16(data, base + 12)
    flags = u32(data, base + 16)
    next_command = u32(data, base + 20)

    return {
        "smb2_header_offset": base,
        "smb2_protocol_id": data[base:base + 4].hex(),
        "smb2_structure_size": u16(data, base + 4),
        "smb2_credit_charge": u16(data, base + 6),
        "smb2_channel_sequence_or_status": u32(data, base + 8),
        "smb2_command": cmd,
        "smb2_command_name": COMMAND_MAP.get(cmd, f"UNKNOWN_{cmd}"),
        "smb2_credit_request_response": u16(data, base + 14),
        "smb2_flags": flags,
        "smb2_is_response": bool(flags & 0x00000001) if flags is not None else None,
        "smb2_next_command": next_command,
        "smb2_message_id": u64(data, base + 24),
        "smb2_process_id": u32(data, base + 32),
        "smb2_tree_id": u32(data, base + 36),
        "smb2_session_id": u64(data, base + 40),
        "smb2_signature": data[base + 48:base + 64].hex(),
    }


def decode_utf16le(raw: bytes):
    if not raw:
        return None

    try:
        return raw.decode("utf-16le", errors="ignore").rstrip("\x00")
    except Exception:
        return None


def parse_create_request(data: bytes, base: int):
    body = base + 64

    desired_access = u32(data, body + 24)
    create_disposition = u32(data, body + 36)
    create_options = u32(data, body + 40)

    name_offset = u16(data, body + 44)
    name_length = u16(data, body + 46)

    name_raw = None
    filename = None

    if name_offset is not None and name_length is not None:
        start = base + name_offset
        end = start + name_length
        if 0 <= start <= end <= len(data):
            name_raw = data[start:end]
            filename = decode_utf16le(name_raw)

    return {
        "body_type": "CREATE_REQUEST",
        "smb2_structure_size_body": u16(data, body),
        "smb2_requested_oplock_level": data[body + 3] if body + 3 < len(data) else None,
        "smb2_impersonation_level": u32(data, body + 4),
        "smb2_desired_access_raw": desired_access,
        "smb2_desired_access": flags_to_names(desired_access, DESIRED_ACCESS_FLAGS),
        "smb2_file_attributes": u32(data, body + 28),
        "smb2_share_access": u32(data, body + 32),
        "smb2_create_disposition_raw": create_disposition,
        "smb2_create_disposition": CREATE_DISPOSITION_MAP.get(create_disposition, str(create_disposition)),
        "smb2_create_options_raw": create_options,
        "smb2_create_options": flags_to_names(create_options, CREATE_OPTIONS_FLAGS),
        "smb2_name_offset": name_offset,
        "smb2_name_length": name_length,
        "smb2_filename_raw": hex_bytes(name_raw),
        "smb2_filename": filename,
        "smb2_create_contexts_offset": u32(data, body + 48),
        "smb2_create_contexts_length": u32(data, body + 52),
    }


def parse_create_response(data: bytes, base: int):
    body = base + 64

    creation_time = u64(data, body + 8)
    last_access_time = u64(data, body + 16)
    last_write_time = u64(data, body + 24)
    change_time = u64(data, body + 32)

    file_id_raw = data[body + 64:body + 80] if body + 80 <= len(data) else None

    return {
        "body_type": "CREATE_RESPONSE",
        "smb2_structure_size_body": u16(data, body),
        "smb2_create_action": u32(data, body + 4),
        "smb2_creation_time_raw": creation_time,
        "smb2_creation_time": win_filetime_to_iso(creation_time),
        "smb2_last_access_time_raw": last_access_time,
        "smb2_last_access_time": win_filetime_to_iso(last_access_time),
        "smb2_last_write_time_raw": last_write_time,
        "smb2_last_write_time": win_filetime_to_iso(last_write_time),
        "smb2_change_time_raw": change_time,
        "smb2_change_time": win_filetime_to_iso(change_time),
        "smb2_allocation_size": u64(data, body + 40),
        "smb2_end_of_file": u64(data, body + 48),
        "smb2_file_attributes": u32(data, body + 56),
        "smb2_file_id": hex_bytes(file_id_raw),
    }


def parse_read_request(data: bytes, base: int):
    body = base + 64
    file_id_raw = data[body + 16:body + 32] if body + 32 <= len(data) else None

    return {
        "body_type": "READ_REQUEST",
        "smb2_structure_size_body": u16(data, body),
        "smb2_length": u32(data, body + 4),
        "smb2_offset": u64(data, body + 8),
        "smb2_file_id": hex_bytes(file_id_raw),
    }


def parse_write_request(data: bytes, base: int):
    body = base + 64
    file_id_raw = data[body + 16:body + 32] if body + 32 <= len(data) else None

    data_offset = u16(data, body + 2)
    length = u32(data, body + 4)

    write_data = None
    if data_offset is not None and length is not None:
        start = base + data_offset
        end = start + length
        if 0 <= start <= end <= len(data):
            write_data = data[start:end]

    return {
        "body_type": "WRITE_REQUEST",
        "smb2_structure_size_body": u16(data, body),
        "smb2_data_offset": data_offset,
        "smb2_length": length,
        "smb2_offset": u64(data, body + 8),
        "smb2_file_id": hex_bytes(file_id_raw),
        "smb2_write_data_preview_hex": hex_bytes(write_data[:64]) if write_data else None,
    }


def parse_query_info_request(data: bytes, base: int):
    body = base + 64
    file_id_raw = data[body + 24:body + 40] if body + 40 <= len(data) else None

    info_type = data[body + 2] if body + 2 < len(data) else None
    file_info_class = data[body + 3] if body + 3 < len(data) else None

    return {
        "body_type": "QUERY_INFO_REQUEST",
        "smb2_structure_size_body": u16(data, body),
        "smb2_query_info_type": info_type,
        "smb2_query_file_class_raw": file_info_class,
        "smb2_query_file_class": FILE_INFO_CLASS_MAP.get(file_info_class, str(file_info_class)),
        "smb2_file_info_class_raw": file_info_class,
        "smb2_file_info_class": FILE_INFO_CLASS_MAP.get(file_info_class, str(file_info_class)),
        "smb2_output_buffer_length": u32(data, body + 4),
        "smb2_input_buffer_offset": u16(data, body + 8),
        "smb2_input_buffer_length": u32(data, body + 12),
        "smb2_additional_information": u32(data, body + 16),
        "smb2_flags_query_info": u32(data, body + 20),
        "smb2_file_id": hex_bytes(file_id_raw),
    }


def parse_set_info_request(data: bytes, base: int):
    body = base + 64
    file_id_raw = data[body + 16:body + 32] if body + 32 <= len(data) else None

    info_type = data[body + 2] if body + 2 < len(data) else None
    file_info_class = data[body + 3] if body + 3 < len(data) else None

    buffer_length = u32(data, body + 4)
    buffer_offset = u16(data, body + 8)

    buffer_raw = None
    if buffer_offset is not None and buffer_length is not None:
        start = base + buffer_offset
        end = start + buffer_length
        if 0 <= start <= end <= len(data):
            buffer_raw = data[start:end]

    delete_pending = None
    if file_info_class in (13, 64) and buffer_raw:
        delete_pending = buffer_raw[0] != 0

    return {
        "body_type": "SET_INFO_REQUEST",
        "smb2_structure_size_body": u16(data, body),
        "smb2_info_type": info_type,
        "smb2_file_info_class_raw": file_info_class,
        "smb2_file_info_class": FILE_INFO_CLASS_MAP.get(file_info_class, str(file_info_class)),
        "smb2_buffer_length": buffer_length,
        "smb2_buffer_offset": buffer_offset,
        "smb2_additional_information": u32(data, body + 12),
        "smb2_file_id": hex_bytes(file_id_raw),
        "smb2_buffer_preview_hex": hex_bytes(buffer_raw[:64]) if buffer_raw else None,
        "smb2_delete_pending": delete_pending,
    }


def parse_query_directory_request(data: bytes, base: int):
    body = base + 64
    file_id_raw = data[body + 16:body + 32] if body + 32 <= len(data) else None

    file_info_class = data[body + 2] if body + 2 < len(data) else None

    name_offset = u16(data, body + 32)
    name_length = u16(data, body + 34)

    name_raw = None
    filename = None

    if name_offset is not None and name_length is not None:
        start = base + name_offset
        end = start + name_length
        if 0 <= start <= end <= len(data):
            name_raw = data[start:end]
            filename = decode_utf16le(name_raw)

    return {
        "body_type": "QUERY_DIRECTORY_REQUEST",
        "smb2_structure_size_body": u16(data, body),
        "smb2_file_info_class_raw": file_info_class,
        "smb2_file_info_class": FILE_INFO_CLASS_MAP.get(file_info_class, str(file_info_class)),
        "smb2_flags_query_directory": data[body + 3] if body + 3 < len(data) else None,
        "smb2_file_index": u32(data, body + 4),
        "smb2_file_id": hex_bytes(file_id_raw),
        "smb2_output_buffer_length": u32(data, body + 28),
        "smb2_name_offset": name_offset,
        "smb2_name_length": name_length,
        "smb2_filename_raw": hex_bytes(name_raw),
        "smb2_filename": filename,
    }


def parse_close_request(data: bytes, base: int):
    body = base + 64
    file_id_raw = data[body + 8:body + 24] if body + 24 <= len(data) else None

    return {
        "body_type": "CLOSE_REQUEST",
        "smb2_structure_size_body": u16(data, body),
        "smb2_close_flags": u16(data, body + 2),
        "smb2_file_id": hex_bytes(file_id_raw),
    }


def parse_smb2_body(data: bytes, base: int, header: dict):
    cmd = header.get("smb2_command")
    is_response = header.get("smb2_is_response")

    try:
        if cmd == 5 and not is_response:
            return parse_create_request(data, base)

        if cmd == 5 and is_response:
            return parse_create_response(data, base)

        if cmd == 8 and not is_response:
            return parse_read_request(data, base)

        if cmd == 9 and not is_response:
            return parse_write_request(data, base)

        if cmd == 16 and not is_response:
            return parse_query_info_request(data, base)

        if cmd == 17 and not is_response:
            return parse_set_info_request(data, base)

        if cmd == 14 and not is_response:
            return parse_query_directory_request(data, base)

        if cmd == 6 and not is_response:
            return parse_close_request(data, base)

        return {
            "body_type": f"{header.get('smb2_command_name')}_{'RESPONSE' if is_response else 'REQUEST'}",
            "note": "Body parser not implemented for this command/response type",
        }

    except Exception as e:
        return {
            "body_parse_error": str(e),
        }


def packet_to_debug_record(pkt, frame_number: int):
    if TCP not in pkt:
        return {
            "frame_number": frame_number,
            "error": "No TCP layer",
        }

    tcp_payload = bytes(pkt[TCP].payload)

    if not tcp_payload:
        return {
            "frame_number": frame_number,
            "error": "Empty TCP payload",
        }

    offsets = find_smb2_offsets(tcp_payload)

    src_ip, dst_ip = get_ip_info(pkt)

    base_result = {
        "frame_number": frame_number,
        "timestamp": float(pkt.time),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": pkt[TCP].sport,
        "dst_port": pkt[TCP].dport,
        "tcp_payload_len": len(tcp_payload),
        "tcp_payload_preview_hex": tcp_payload[:128].hex(),
    }

    if not offsets:
        base_result["error"] = "No SMB2 signature in TCP payload"
        return base_result

    messages = []

    for off in offsets:
        header = parse_smb2_header(tcp_payload, off)
        body = parse_smb2_body(tcp_payload, off, header)

        flat = {}
        flat.update(header)
        flat.update(body)

        messages.append(flat)

    base_result["smb2_messages"] = messages

    return base_result


def extract_smb2_frame(pcap_file: str, frame_number: int):
    if frame_number <= 0:
        return {"error": "frame_number must be >= 1"}

    with PcapReader(pcap_file) as pcap:
        for idx, pkt in enumerate(pcap, start=1):
            if idx == frame_number:
                return packet_to_debug_record(pkt, idx)

    return {
        "error": "frame_number out of range",
        "requested_frame_number": frame_number,
        "hint": "This frame number is larger than the number of packets in the pcap/pcapng.",
    }


def scan_smb2_frames(pcap_file: str, limit: int = 50):
    results = []

    with PcapReader(pcap_file) as pcap:
        for idx, pkt in enumerate(pcap, start=1):
            if TCP not in pkt:
                continue

            payload = bytes(pkt[TCP].payload)

            if SMB2_SIGNATURE not in payload:
                continue

            record = packet_to_debug_record(pkt, idx)

            summary = {
                "frame_number": idx,
                "timestamp": record.get("timestamp"),
                "src_ip": record.get("src_ip"),
                "dst_ip": record.get("dst_ip"),
                "src_port": record.get("src_port"),
                "dst_port": record.get("dst_port"),
                "commands": [
                    {
                        "command": msg.get("smb2_command_name"),
                        "is_response": msg.get("smb2_is_response"),
                        "filename": msg.get("smb2_filename"),
                        "desired_access": msg.get("smb2_desired_access"),
                        "create_disposition": msg.get("smb2_create_disposition"),
                        "create_options": msg.get("smb2_create_options"),
                        "file_info_class": msg.get("smb2_file_info_class"),
                        "file_id": msg.get("smb2_file_id"),
                    }
                    for msg in record.get("smb2_messages", [])
                ],
            }

            results.append(summary)

            if len(results) >= limit:
                break

    return results


def main():
    parser = argparse.ArgumentParser(description="Debug SMB2 fields from PCAP/PCAPNG using raw Scapy TCP payload parsing.")
    parser.add_argument("pcap", help="Input PCAP/PCAPNG file")
    parser.add_argument("--frame", type=int, help="Frame number exactly as Wireshark shows")
    parser.add_argument("--scan", action="store_true", help="Scan SMB2 frames and print compact summary")
    parser.add_argument("--limit", type=int, default=50, help="Limit for --scan")
    args = parser.parse_args()

    if args.scan:
        data = scan_smb2_frames(args.pcap, args.limit)
    elif args.frame:
        data = extract_smb2_frame(args.pcap, args.frame)
    else:
        data = {
            "error": "Use either --frame N or --scan",
            "examples": [
                "python debug.py ./data/pcaps/Sample2.pcapng --scan --limit 20",
                "python debug.py ./data/pcaps/Sample2.pcapng --frame 624",
            ],
        }

    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()