from scapy.all import PcapReader, TCP, IP, IPv6
import argparse
import json

from scapy.all import *
from smbmount.parser.tcp_reassembler import reassemble_tcp_streams


# =======================
# Utils
# =======================

def format_flags(flags):
    if isinstance(flags, int):
        return hex(flags)
    return str(flags)


def fileid_to_hex(fid_obj):
    """
    Convert SMB2_FILEID object -> Wireshark format
    """
    try:
        persistent = fid_obj.fields["Persistent"]
        volatile = fid_obj.fields["Volatile"]

        p_bytes = persistent.to_bytes(8, "little")
        v_bytes = volatile.to_bytes(8, "little")

        full = p_bytes + v_bytes

        return (
            full[0:4].hex() + "-" +
            full[4:6].hex() + "-" +
            full[6:8].hex() + "-" +
            full[8:10].hex() + "-" +
            full[10:16].hex()
        )
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
    pcap_file = "./data/pcaps/Sample2.pcapng"
    # frame_number = 624

    # data = extract_smb2_frame(pcap_file, frame_number)
    # print(json.dumps(data, indent=2, default=str))
    
    capture_raw = rdpcap("../pcapFS_reproduce/pcapFS_reproduce/samples/smb2-peter.pcap")
    tcp_responses, tcp_write_requests = reassemble_tcp_streams(capture_raw)

    print(f"MID 54 in tcp_responses: {54 in tcp_responses}")
    if 54 in tcp_responses:
        hdr = tcp_responses[54]
        from scapy.layers.smb2 import SMB2_Read_Response
        if hdr.haslayer(SMB2_Read_Response):
            data_len = hdr[SMB2_Read_Response].DataLen
            blob = b""
            for name, val in hdr[SMB2_Read_Response].Buffer:
                if name == "Data":
                    blob = val
                    break
            print(f"DataLen={data_len} actual={len(blob)} match={len(blob)==data_len}")