import struct
from typing import Any, Dict, Optional
 
from scapy.all import TCP, SMB2_Header
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
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
 
from smbmount.parser.utils import safe_get, safe_int, filetime_to_unix, decode_smb_filename
from smbmount.parser.smb2_constants import SMB2_COMMAND_MAP, FILE_INFO_CLASSES_WITH_TIMESTAMPS

def close_request_file_id(raw_smb2: bytes) -> Optional[bytes]:
    """
    SMB2 CLOSE request payload:
    header 64 bytes, then StructureSize/Flags/Reserved 8 bytes, then FileId 16 bytes.
    """
    start = 64 + 8
    end = start + 16
    if len(raw_smb2) < end:
        return None
    return raw_smb2[start:end]

def create_request_filename(raw_smb2: bytes) -> Optional[str]:
    """
    SMB2 CREATE request stores filename at NameOffset/NameLength.
    Offsets are relative to the beginning of the SMB2 header.
    """
    if len(raw_smb2) < 64 + 56:
        return None

    name_offset = int.from_bytes(raw_smb2[64 + 44:64 + 46], "little")
    name_length = int.from_bytes(raw_smb2[64 + 46:64 + 48], "little")
    if name_offset <= 0 or name_length <= 0:
        return None

    end = name_offset + name_length
    if end > len(raw_smb2):
        return None

    return decode_smb_filename(raw_smb2[name_offset:end])

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
        msg_id = safe_get(smb2_layer, "MID")
        tree_id = safe_get(smb2_layer, "TID")
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

def get_smb2_payload(smb2_layer: Any, raw_smb2: Optional[bytes] = None,
                     cmd: Optional[Any] = None, is_response: Optional[bool] = None) -> Dict[str, Any]:
    result = {
        "smb2_file_id": None,
        "smb2_filename": None,
        "smb2_offset": None,
        "smb2_length": None,
        "smb2_read_blob": None,
        "smb2_query_info_type": None,
        "smb2_query_file_class": None,
        "smb2_query_info_response_data": None,
    }

    if smb2_layer is None:
        return result

    try:
        if isinstance(smb2_layer, SMB2_Create_Request):
            # Filename nằm trong Buffer, không phải FileName
            buffer = safe_get(smb2_layer, "Buffer", [])
            for name, val in buffer:
                if name == "Name":
                    result["smb2_filename"] = decode_smb_filename(val)
                    # result["smb2_filename"] = val
                    break

        elif isinstance(smb2_layer, SMB2_Create_Response):
            # FileId phải convert sang bytes để dùng làm key
            fid = safe_get(smb2_layer, "FileId")
            result["smb2_file_id"] = bytes(fid) if fid is not None else None

        elif isinstance(smb2_layer, SMB2_Read_Request):
            fid = safe_get(smb2_layer, "FileId")
            result["smb2_file_id"] = bytes(fid) if fid is not None else None
            result["smb2_offset"] = safe_int(safe_get(smb2_layer, "Offset"))
            result["smb2_length"] = safe_int(safe_get(smb2_layer, "Length"))

        elif isinstance(smb2_layer, SMB2_Read_Response):
            # Extract data từ Buffer tuple list
            buffer = safe_get(smb2_layer, "Buffer", [])
            data_len = safe_int(safe_get(smb2_layer, "DataLen"), 0)
            
            for name, val in buffer:
                if name == "Data":
                    result["smb2_read_blob"] = val[:data_len] if data_len else val
                    break

        elif isinstance(smb2_layer, SMB2_Write_Request):
            fid = safe_get(smb2_layer, "FileId")
            result["smb2_file_id"] = bytes(fid) if fid is not None else None
            result["smb2_offset"] = safe_int(safe_get(smb2_layer, "Offset"))
            result["smb2_length"] = safe_int(safe_get(smb2_layer, "DataLen"))
            
            # Extract write data
            buffer = safe_get(smb2_layer, "Buffer", [])
            for name, val in buffer:
                if name == "Data":
                    result["smb2_read_blob"] = val
                    # print(result["smb2_file_id"], result["smb2_offset"], result["smb2_length"])
                    # print(val)
                    # print("-" * 40)
                    # break
        elif isinstance(smb2_layer, SMB2_Query_Info_Request):
            result["smb2_query_info_type"]  = safe_int(safe_get(smb2_layer, "InfoType"))
            result["smb2_query_file_class"] = safe_int(safe_get(smb2_layer, "FileInfoClass"))
        
        elif isinstance(smb2_layer, SMB2_Query_Info_Response):
            buffer = safe_get(smb2_layer, "Buffer", [])
            for name, val in buffer:
                if name == "Output":
                    result["smb2_query_info_response_data"] = val
                    break
        
        elif isinstance(smb2_layer, SMB2_Set_Info_Request):
            info_type   = safe_int(safe_get(smb2_layer, "InfoType"))
            file_class  = safe_int(safe_get(smb2_layer, "FileInfoClass"))
            # print(smb2_layer.fields)

            if info_type == 1 and file_class in FILE_INFO_CLASSES_WITH_TIMESTAMPS:
                raw_buffer = safe_get(smb2_layer, "Buffer", [])
                for name, val in raw_buffer:
                    if name == "Data" and len(val) >= 32:
                        result["smb2_create_time"]      = filetime_to_unix(struct.unpack("<Q", val[0:8])[0])
                        result["smb2_last_access_time"] = filetime_to_unix(struct.unpack("<Q", val[8:16])[0])
                        result["smb2_last_write_time"]  = filetime_to_unix(struct.unpack("<Q", val[16:24])[0])
                        result["smb2_change_time"]      = filetime_to_unix(struct.unpack("<Q", val[24:32])[0])
                        # print(f"Extracted timestamps from SET_INFO: create={result['smb2_create_time']}, last_access={result['smb2_last_access_time']}, last_write={result['smb2_last_write_time']}, change={result['smb2_change_time']}")
                        break
                
        elif SMB2_Close_Request is not None and isinstance(smb2_layer, SMB2_Close_Request):
            fid = safe_get(smb2_layer, "FileId")
            result["smb2_file_id"] = bytes(fid) if fid is not None else None
        
        # elif SMB2_Close_Response is not None and isinstance(smb2_layer, SMB2_Close_Response):
        #     result["smb2_last_write_time"] = filetime_to_unix(safe_get(smb2_layer, "LastWriteTime"))
        #     result["smb2_change_time"] = filetime_to_unix(safe_get(smb2_layer, "ChangeTime"))
    
            
        
    except Exception:
        pass

    if (
        result["smb2_file_id"] is None
        and str(cmd) == "6"
        and is_response is False
        and raw_smb2 is not None
    ):
        result["smb2_file_id"] = close_request_file_id(raw_smb2)

    if (
        result["smb2_filename"] is None
        and str(cmd) == "5"
        and is_response is False
        and raw_smb2 is not None
    ):
        result["smb2_filename"] = create_request_filename(raw_smb2)

    return result

def get_smb2_create_metadata(smb2_layer: Any) -> Dict[str, Any]:
    """
    Extract metadata từ SMB2 CREATE response.

    Các field chính trong SMB2 CREATE Response:
    - CreationTime
    - LastAccessTime
    - LastWriteTime
    - ChangeTime
    - AllocationSize
    - EndOfFile
    - FileAttributes
    - OplockLevel
    - CreateAction
    - FileId
    """
    result = {
        "smb2_create_time": None,
        "smb2_last_access_time": None,
        "smb2_last_write_time": None,
        "smb2_change_time": None,
        "smb2_allocation_size": None,
        "smb2_end_of_file": None,
        "smb2_file_attributes": None,
        "smb2_oplock_level": None,
        "smb2_create_action": None,
    }

    # if smb2_layer is None or not isinstance(smb2_layer, SMB2_Create_Response:
    #     return result
    
    if smb2_layer is None:
        return result
    if not isinstance(smb2_layer, (SMB2_Create_Response, SMB2_Close_Response)):
        return result
    
    # if isinstance(smb2_layer, SMB2_Close_Response):
    #     print(smb2_layer.fields)
    
    try:
        result["smb2_create_time"] = filetime_to_unix(
            safe_get(smb2_layer, "CreationTime")
        )
        result["smb2_last_access_time"] = filetime_to_unix(
            safe_get(smb2_layer, "LastAccessTime")
        )
        result["smb2_last_write_time"] = filetime_to_unix(
            safe_get(smb2_layer, "LastWriteTime")
        )
        result["smb2_change_time"] = filetime_to_unix(
            safe_get(smb2_layer, "ChangeTime")
        )

        result["smb2_allocation_size"] = safe_int(
            safe_get(smb2_layer, "AllocationSize")
        )
        result["smb2_end_of_file"] = safe_int(
            safe_get(smb2_layer, "EndOfFile")
        )
        result["smb2_file_attributes"] = safe_int(
            safe_get(smb2_layer, "FileAttributes")
        )
        result["smb2_oplock_level"] = safe_int(
            safe_get(smb2_layer, "OplockLevel")
        )
        result["smb2_create_action"] = safe_int(
            safe_get(smb2_layer, "CreateAction")
        )

    except Exception:
        pass

    return result