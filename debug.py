from scapy.all import sniff
from scapy.layers.smb2 import (
    SMB2_Header,
    SMB2_Create_Request, SMB2_Create_Response,
    SMB2_Read_Request, SMB2_Read_Response,
    SMB2_Write_Request, SMB2_Write_Response
)
from scapy.sessions import TCPSession
import json


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
        return str(fid_obj)


# =======================
# Core extractor
# =======================

def extract_fields(layer):
    result = {}

    for field_name, field_value in layer.fields.items():
        try:
            # ===== FileId special handling =====
            if field_name.lower() == "fileid":
                result["FileId"] = fileid_to_hex(field_value)

            # ===== bytes =====
            elif isinstance(field_value, bytes):
                result[field_name] = field_value.hex()

            # ===== nested object (rare) =====
            elif hasattr(field_value, "fields"):
                result[field_name] = {
                    k: (v.hex() if isinstance(v, bytes) else v)
                    for k, v in field_value.fields.items()
                }

            # ===== flags =====
            elif field_name.lower() == "flags":
                result[field_name] = format_flags(field_value)

            else:
                result[field_name] = field_value

        except Exception as e:
            result[field_name] = f"<error: {e}>"

    return result


# =======================
# Main logic
# =======================

def extract_smb2_frame(pcap_file: str, frame_number: int):
    # ✅ FIX 1: dùng TCP reassembly
    packets = sniff(offline=pcap_file, session=TCPSession)

    if frame_number > len(packets):
        return {"error": "frame_number out of range"}

    pkt = packets[frame_number - 1]

    if not pkt.haslayer(SMB2_Header):
        return {"error": "No SMB2 in this frame"}

    header_layer = pkt[SMB2_Header]

    result = {
        "frame_number": frame_number,
        "header": extract_fields(header_layer),
        "body": {}
    }

    # =======================
    # Command detection
    # =======================

    COMMAND_MAP = {
        0: "NEGOTIATE",
        1: "SESSION_SETUP",
        3: "TREE_CONNECT",
        5: "CREATE",
        8: "READ",
        9: "WRITE",
        14: "QUERY_DIRECTORY"
    }

    cmd = header_layer.Command
    result["header"]["CommandName"] = COMMAND_MAP.get(cmd, f"UNKNOWN_{cmd}")

    # =======================
    # Body parsing
    # =======================

    if pkt.haslayer(SMB2_Create_Request):
        result["body"]["CREATE_REQUEST"] = extract_fields(pkt[SMB2_Create_Request])

    if pkt.haslayer(SMB2_Create_Response):
        result["body"]["CREATE_RESPONSE"] = extract_fields(pkt[SMB2_Create_Response])

    if pkt.haslayer(SMB2_Read_Request):
        result["body"]["READ_REQUEST"] = extract_fields(pkt[SMB2_Read_Request])

    if pkt.haslayer(SMB2_Read_Response):
        result["body"]["READ_RESPONSE"] = extract_fields(pkt[SMB2_Read_Response])

    if pkt.haslayer(SMB2_Write_Request):
        result["body"]["WRITE_REQUEST"] = extract_fields(pkt[SMB2_Write_Request])

    if pkt.haslayer(SMB2_Write_Response):
        result["body"]["WRITE_RESPONSE"] = extract_fields(pkt[SMB2_Write_Response])

    return result


# =======================
# Run
# =======================

if __name__ == "__main__":
    pcap_file = "./data/pcaps/Sample2.pcapng"
    frame_number = 624

    data = extract_smb2_frame(pcap_file, frame_number)
    print(json.dumps(data, indent=2, default=str))