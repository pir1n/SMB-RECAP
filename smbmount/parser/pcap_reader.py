import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from smbmount.core.session import SMBSession
from smbmount.reconstruct.content import process_packets
from smbmount.output.fs_export import export_files


import pyshark


SMB2_COMMAND_MAP = {
    "0": "NEGOTIATE",
    "1": "SESSION_SETUP",
    "2": "LOGOFF",
    "3": "TREE_CONNECT",
    "4": "TREE_DISCONNECT",
    "5": "CREATE",
    "6": "CLOSE",
    "7": "FLUSH",
    "8": "READ",
    "9": "WRITE",
    "10": "LOCK",
    "11": "IOCTL",
    "12": "CANCEL",
    "13": "ECHO",
    "14": "QUERY_DIRECTORY",
    "15": "CHANGE_NOTIFY",
    "16": "QUERY_INFO",
    "17": "SET_INFO",
}


def safe_get(layer: Any, field_name: str, default: Optional[Any] = None) -> Optional[Any]:
    """
    Lấy field từ pyshark layer một cách an toàn.
    Nếu field không tồn tại thì trả về default.
    """
    try:
        value = getattr(layer, field_name)
        if value == "":
            return default
        return value
    except Exception:
        return default


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    """
    Convert value sang int nếu có thể.
    Hỗ trợ cả string decimal và hex dạng 0x...
    """
    if value is None:
        return default

    try:
        text = str(value)
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    except Exception:
        return default

def parse_timestamp(value: Any) -> Optional[float]:
    """
    Convert timestamp của pyshark/tshark về Unix epoch seconds.

    Hỗ trợ cả:
    - 1710000000.123456
    - 2026-04-28T10:14:23.918258600Z
    """
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    # Trường hợp timestamp là epoch dạng số
    try:
        return float(text)
    except ValueError:
        pass

    # Trường hợp ISO timestamp dạng 2026-04-28T10:14:23.918258600Z
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    # Python datetime chỉ hỗ trợ microsecond 6 chữ số,
    # trong khi tshark có thể trả nanosecond 9 chữ số.
    if "." in text:
        date_part, rest = text.split(".", 1)

        if "+" in rest:
            frac, tz = rest.split("+", 1)
            frac = frac[:6].ljust(6, "0")
            text = f"{date_part}.{frac}+{tz}"
        elif "-" in rest:
            frac, tz = rest.split("-", 1)
            frac = frac[:6].ljust(6, "0")
            text = f"{date_part}.{frac}-{tz}"
        else:
            frac = rest[:6].ljust(6, "0")
            text = f"{date_part}.{frac}"

    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.timestamp()

def get_basic_packet_info(packet: Any) -> Dict[str, Any]:
    """
    Extract metadata chung của frame/IP/TCP.
    """
    frame_number = safe_get(packet.frame_info, "number")
    timestamp = safe_get(packet.frame_info, "time_epoch")

    result = {
        "frame_number": safe_int(frame_number),
        "timestamp": parse_timestamp(timestamp),
        "highest_layer": getattr(packet, "highest_layer", None),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "tcp_stream": None,
        "has_smb2": hasattr(packet, "smb2"),
    }

    if hasattr(packet, "ip"):
        result["src_ip"] = safe_get(packet.ip, "src")
        result["dst_ip"] = safe_get(packet.ip, "dst")

    if hasattr(packet, "ipv6"):
        result["src_ip"] = safe_get(packet.ipv6, "src")
        result["dst_ip"] = safe_get(packet.ipv6, "dst")

    if hasattr(packet, "tcp"):
        result["src_port"] = safe_int(safe_get(packet.tcp, "srcport"))
        result["dst_port"] = safe_int(safe_get(packet.tcp, "dstport"))
        result["tcp_stream"] = safe_int(safe_get(packet.tcp, "stream"))

    return result


def get_smb2_info(packet: Any) -> Dict[str, Any]:
    result = {
        "smb2_command": None,
        "smb2_command_name": None,
        "smb2_message_id": None,
        "smb2_tree_id": None,
        "smb2_session_id": None,
        "smb2_is_response": None,
        "smb2_status": None,
        "smb2_response_to": None,   # 👈 thêm
    }

    if not hasattr(packet, "smb2"):
        return result

    smb2 = packet.smb2

    cmd = safe_get(smb2, "cmd")
    msg_id = safe_get(smb2, "msg_id")
    tree_id = safe_get(smb2, "tid")
    session_id = safe_get(smb2, "sesid")
    response_flag = safe_get(smb2, "flags_response")
    status = safe_get(smb2, "nt_status")
    response_to = safe_get(smb2, "response_to")  # 👈 thêm

    result["smb2_command"] = str(cmd) if cmd is not None else None
    result["smb2_command_name"] = SMB2_COMMAND_MAP.get(str(cmd), "UNKNOWN") if cmd is not None else None
    result["smb2_message_id"] = str(msg_id) if msg_id is not None else None
    result["smb2_tree_id"] = str(tree_id) if tree_id is not None else None
    result["smb2_session_id"] = str(session_id) if session_id is not None else None

    if response_flag is not None:
        result["smb2_is_response"] = str(response_flag) == "True"

    result["smb2_status"] = str(status) if status is not None else None
    result["smb2_response_to"] = safe_int(response_to)  # 👈 thêm

    return result

def get_smb2_payload(packet: Any) -> Dict[str, Any]:
    if not hasattr(packet, "smb2"):
        return {}

    smb2 = packet.smb2

    return {
        "smb2_file_id": safe_get(smb2, "fid"),
        "smb2_filename": safe_get(smb2, "filename"),
        "smb2_offset": safe_int(safe_get(smb2, "file_offset")),   # 👈 sửa đúng field
        "smb2_length": safe_int(safe_get(smb2, "read_length")),    # 👈 request
        "smb2_read_blob": safe_get(smb2, "read_blob"),             # 👈 response data
    }

def read_pcap_basic(input_pcap: str) -> List[Dict[str, Any]]:
    """
    Đọc PCAP, lọc SMB2, extract thông tin frame/IP/TCP/SMB2 cơ bản.
    """
    input_path = Path(input_pcap)

    if not input_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file PCAP: {input_pcap}")

    packets: List[Dict[str, Any]] = []

    capture = pyshark.FileCapture(
        input_path,
        display_filter="smb2",
        keep_packets=False
    )

    try:
        for packet in capture:
            record = get_basic_packet_info(packet)
            record.update(get_smb2_info(packet))
            record.update(get_smb2_payload(packet))
            packets.append(record)
    finally:
        capture.close()

    return packets


def enrich_with_request_mapping(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Gắn lại fid/offset cho response bằng msg_id
    """
    pending: Dict[str, Dict[str, Any]] = {}

    for pkt in packets:
        msg_id = pkt.get("smb2_message_id")
        is_response = pkt.get("smb2_is_response")

        if not msg_id:
            continue

        # 👉 REQUEST
        if not is_response:
            pending[msg_id] = pkt

        # 👉 RESPONSE
        else:
            req = pending.get(msg_id)

            if not req:
                continue

            # copy thông tin quan trọng từ request
            pkt["mapped_file_id"] = req.get("smb2_file_id")
            pkt["mapped_offset"] = req.get("smb2_offset")
            pkt["mapped_length"] = req.get("smb2_length")
            pkt["mapped_filename"] = req.get("smb2_filename")

    return packets

def write_json(data: Any, output_path: str) -> None:
    """
    Ghi JSON UTF-8 đẹp, dễ đọc.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def parse_pcap_to_json(input_pcap: str, output_json: str) -> None:
    packets = read_pcap_basic(input_pcap)
    packets = enrich_with_request_mapping(packets)
    # Step 1: build session (optional)
    session = SMBSession()
    session.build(packets)
    
    # Step 2: reconstruct files
    file_table = process_packets(packets)

    # Step 3: export
    result = export_files(file_table)

    write_json(result, output_json)

# def parse_pcap_to_json(input_pcap: str, output_json: str) -> None:
#     """
#     Hàm chính cho CLI gọi.
#     """
#     packets = read_pcap_basic(input_pcap)
#     packets = enrich_with_request_mapping(packets)
#     write_json(packets, output_json)