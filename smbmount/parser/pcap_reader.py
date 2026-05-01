import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from smbmount.core.session import SMBSession
from smbmount.reconstruct.content import process_packets
from smbmount.output.fs_export import export_files

from scapy.all import rdpcap, TCP, Raw, SMB2_Header, sniff
from scapy.layers.smb2 import SMB2_Create_Request, SMB2_Create_Response
from scapy.layers.smb2 import SMB2_Read_Request, SMB2_Read_Response
from scapy.layers.smb2 import SMB2_Write_Request, SMB2_Write_Response
from scapy.sessions import TCPSession


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
    Lấy field từ scapy layer một cách an toàn.
    Nếu field không tồn tại thì trả về default.
    """
    try:
        if layer is None:
            return default
        
        value = getattr(layer, field_name, default)
        if value is None or value == "":
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

def print_progress(current: int, total: int, prefix: str = "Processing") -> None:
    """
    Hiển thị progress bar với phần trăm hoàn thành.
    """
    if total == 0:
        percent = 0
    else:
        percent = int((current / total) * 100)
    
    bar_length = 40
    filled_length = int((current / total) * bar_length) if total > 0 else 0
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    
    print(f"\r{prefix}: [{bar}] {percent}% ({current}/{total})", end="", flush=True)
    
    if current == total:
        print()  # New line at end

def get_basic_packet_info(packet: Any) -> Dict[str, Any]:
    """
    Extract metadata chung của IP/TCP từ scapy packet.
    """
    result = {
        "frame_number": None,
        "timestamp": packet.time if hasattr(packet, 'time') else None,
        "highest_layer": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "tcp_stream": None,
        "has_smb2": packet.haslayer(SMB2_Header),
    }

    # IP layer
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        result["src_ip"] = ip_layer.src
        result["dst_ip"] = ip_layer.dst
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        result["src_ip"] = ip_layer.src
        result["dst_ip"] = ip_layer.dst

    # TCP layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        result["src_port"] = tcp_layer.sport
        result["dst_port"] = tcp_layer.dport

    if packet.haslayer(SMB2_Header):
        result["highest_layer"] = "SMB2"

    return result


def get_smb2_info(smb2_layer: Any) -> Dict[str, Any]:
    """
    Extract SMB2 header information từ scapy SMB2_Header layer.
    Dùng field names tương thích với code hiện có.
    """
    result = {
        "smb2_command": None,
        "smb2_command_name": None,
        "smb2_message_id": None,
        "smb2_tree_id": None,
        "smb2_session_id": None,
        "smb2_is_response": None,
        "smb2_status": None,
        "smb2_response_to": None,
    }

    if smb2_layer is None:
        return result

    try:
        cmd = safe_get(smb2_layer, "Command")
        msg_id = safe_get(smb2_layer, "MessageId")
        tree_id = safe_get(smb2_layer, "TreeId")
        session_id = safe_get(smb2_layer, "SessionId")
        flags = safe_get(smb2_layer, "Flags")
        status = safe_get(smb2_layer, "Status")

        result["smb2_command"] = str(cmd) if cmd is not None else None
        result["smb2_command_name"] = SMB2_COMMAND_MAP.get(str(cmd), "UNKNOWN") if cmd is not None else None
        result["smb2_message_id"] = str(msg_id) if msg_id is not None else None
        result["smb2_tree_id"] = str(tree_id) if tree_id is not None else None
        result["smb2_session_id"] = str(session_id) if session_id is not None else None

        if flags is not None:
            result["smb2_is_response"] = bool(flags & 0x01)

        result["smb2_status"] = str(status) if status is not None else None

    except Exception:
        pass

    return result

def get_smb2_payload(smb2_layer: Any) -> Dict[str, Any]:
    """
    Extract SMB2 payload từ scapy SMB2 layers (Create/Read/Write).
    """
    result = {
        "smb2_file_id": None,
        "smb2_filename": None,
        "smb2_offset": None,
        "smb2_length": None,
        "smb2_read_blob": None,
    }

    if smb2_layer is None:
        return result

    try:
        # Handle CREATE request
        if isinstance(smb2_layer, SMB2_Create_Request):
            result["smb2_filename"] = safe_get(smb2_layer, "FileName")

        # Handle CREATE response
        elif isinstance(smb2_layer, SMB2_Create_Response):
            result["smb2_file_id"] = safe_get(smb2_layer, "FileId")

        # Handle READ request
        elif isinstance(smb2_layer, SMB2_Read_Request):
            result["smb2_file_id"] = safe_get(smb2_layer, "FileId")
            result["smb2_offset"] = safe_int(safe_get(smb2_layer, "Offset"))
            result["smb2_length"] = safe_int(safe_get(smb2_layer, "Length"))

        # Handle READ response
        elif isinstance(smb2_layer, SMB2_Read_Response):
            result["smb2_read_blob"] = safe_get(smb2_layer, "Buffer")

        # Handle WRITE request
        elif isinstance(smb2_layer, SMB2_Write_Request):
            result["smb2_file_id"] = safe_get(smb2_layer, "FileId")
            result["smb2_offset"] = safe_int(safe_get(smb2_layer, "Offset"))
            result["smb2_length"] = safe_int(safe_get(smb2_layer, "Length"))

        # Handle WRITE response
        elif isinstance(smb2_layer, SMB2_Write_Response):
            pass

    except Exception:
        pass

    return result

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

    try:
        print("Loading PCAP file...")
        capture = rdpcap(str(input_path))
        total_packets = len(capture)
        print(f"Total packets loaded: {total_packets}")
    except Exception as e:
        raise Exception(f"Lỗi khi đọc PCAP: {e}")

    packet_counter = 0
    smb2_counter = 0
    
    for idx, packet in enumerate(capture):
        # Print progress every 10 packets or on last packet
        if (idx + 1) % 10 == 0 or idx == total_packets - 1:
            print_progress(idx + 1, total_packets, "Reading packets")
        
        if not packet.haslayer(SMB2_Header):
            continue

        packet_counter += 1
        
        # Get basic packet info (IP/TCP/timestamp)
        basic_info = get_basic_packet_info(packet)
        basic_info["frame_number"] = packet_counter

        # Extract all SMB2 layers in this packet
        smb2_layers = []
        current_layer = packet[SMB2_Header]
        
        while current_layer is not None:
            smb2_layers.append(current_layer)
            # Try to get next SMB2 layer
            if current_layer.haslayer(SMB2_Header):
                current_layer = current_layer[SMB2_Header]
            else:
                current_layer = None

        # Process each SMB2 layer
        for smb2_layer in smb2_layers:
            record = basic_info.copy()
            record.update(get_smb2_info(smb2_layer))
            record.update(get_smb2_payload(smb2_layer))
            packets.append(record)
            smb2_counter += 1

    print(f"\nExtraction complete: {packet_counter} packets with SMB2, {smb2_counter} SMB2 records extracted")
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

def parse_pcap_to_json(input_pcap: str, output_json: str) -> None:
    """
    Hàm chính cho CLI gọi.
    """
    packets = read_pcap_basic(input_pcap)
    packets = enrich_with_request_mapping(packets)
    write_json(packets, output_json)