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
    SMB2_Query_Directory_Request,
    SMB2_Set_Info_Request,
)
try:
    from scapy.layers.smb2 import SMB2_Query_Directory_Response
except ImportError:
    SMB2_Query_Directory_Response = None
try:
    from scapy.layers.smb2 import SMB2_Close_Request, SMB2_Close_Response
except ImportError:
    SMB2_Close_Request = None
    SMB2_Close_Response = None
 
from smbmount.shared.parser.utils import safe_get, safe_int, filetime_to_unix, decode_smb_filename
from smbmount.shared.parser.smb2_constants import (
    SMB2_COMMAND_MAP,
    FILE_INFO_CLASSES_WITH_TIMESTAMPS,
    SMB2_FILE_INFO_CLASS,
    CREATE_DISPOSITION_MAP,
    CREATE_OPTIONS_FLAGS,
    DESIRED_ACCESS_FLAGS,
    FILE_ATTRIBUTE_FLAGS,
    SHARE_ACCESS_FLAGS,
    FILE_DISPOSITION_EX_FLAGS,
    QUERY_DIRECTORY_FLAGS,
)

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

## Helper functions to extract specific fields from raw SMB2 payloads when scapy parsing is not sufficient.
def u8(data: bytes, off: int):
    if data is None or off >= len(data):
        return None
    return data[off]


def u16(data: bytes, off: int):
    if data is None or off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "little")


def u32(data: bytes, off: int):
    if data is None or off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little")


def bytes_range(data: bytes, start: int, length: int):
    if data is None:
        return None
    end = start + length
    if start < 0 or end > len(data):
        return None
    return data[start:end]


def flags_to_names(value, mapping):
    value = safe_int(value)
    if value is None:
        return []
    return [name for bit, name in mapping.items() if value & bit]


def normalize_file_id(fid):
    if fid is None:
        return None
    try:
        return bytes(fid)
    except Exception:
        return fid

def field_to_bytes(value):
    if value is None:
        return b""

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, memoryview):
        return value.tobytes()

    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return value.encode(errors="ignore")

    if isinstance(value, list):
        chunks = []

        for item in value:
            if isinstance(item, tuple) and len(item) == 2:
                _, item_value = item
            else:
                item_value = item

            chunk = field_to_bytes(item_value)
            if chunk:
                chunks.append(chunk)

        return b"".join(chunks)

    try:
        return bytes(value)
    except Exception:
        return b""


def buffer_data_to_bytes(buffer):
    """
    Scapy SMB2 Buffer thường là list tuple:
    [("Data", b"...")] hoặc [("Output", b"...")]
    """
    if not buffer:
        return b""

    if isinstance(buffer, (bytes, bytearray, memoryview, str)):
        return field_to_bytes(buffer)

    if isinstance(buffer, list):
        for name, val in buffer:
            if name in ("Data", "Output", "Buffer"):
                return field_to_bytes(val)

    return field_to_bytes(buffer)


def decode_utf16le_name(raw):
    if not raw:
        return None

    try:
        return raw.decode("utf-16le", errors="ignore").rstrip("\x00")
    except Exception:
        return None


def parse_file_rename_information(data):
    """
    FILE_RENAME_INFORMATION / FILE_RENAME_INFORMATION_EX.

    Layout phổ biến:
    0      ReplaceIfExists hoặc Flags
    8      RootDirectory
    16     FileNameLength
    20     FileName UTF-16LE
    """
    if not data or len(data) < 20:
        return None

    name_len = u32(data, 16)
    if not name_len:
        return None

    raw_name = bytes_range(data, 20, name_len)
    return decode_utf16le_name(raw_name)


def parse_file_disposition_information(data):
    """
    FileDispositionInformation: 1 byte DeletePending.
    FileDispositionInformationEx: 4 bytes flags.
    """
    if not data:
        return None, None, None

    delete_pending = bool(data[0])
    flags_raw = None
    flags = None

    if len(data) >= 4:
        flags_raw = u32(data, 0)
        if flags_raw:
            flags = flags_to_names(flags_raw, FILE_DISPOSITION_EX_FLAGS)
            delete_pending = bool(flags_raw & 0x00000001)

    return delete_pending, flags_raw, flags


def parse_file_size_information(data):
    """
    FileAllocationInformation / FileEndOfFileInformation:
    8 bytes little-endian integer.
    """
    if not data or len(data) < 8:
        return None

    try:
        return struct.unpack("<q", data[:8])[0]
    except Exception:
        return None


def set_info_request_file_id(raw_smb2: bytes) -> Optional[bytes]:
    """
    SMB2 SET_INFO request:
    Header 64 bytes.
    Payload layout:
      StructureSize: 2
      InfoType: 1
      FileInfoClass: 1
      BufferLength: 4
      BufferOffset: 2
      Reserved: 2
      AdditionalInformation: 4
      FileId: 16

    FileId offset = 64 + 16.
    """
    start = 64 + 16
    end = start + 16

    if raw_smb2 is None or len(raw_smb2) < end:
        return None

    return raw_smb2[start:end]


QUERY_DIRECTORY_NAME_LAYOUTS = {
    1: (60, 64),   # FileDirectoryInformation
    2: (60, 68),   # FileFullDirectoryInformation
    3: (60, 94),   # FileBothDirectoryInformation
    12: (8, 12),   # FileNamesInformation
    37: (60, 104), # FileIdBothDirectoryInformation
    38: (60, 80),  # FileIdFullDirectoryInformation
}


def query_directory_response_data(raw_smb2: bytes) -> Optional[bytes]:
    """Return the exact QUERY_DIRECTORY output buffer from an SMB2 response."""
    if raw_smb2 is None or len(raw_smb2) < 72:
        return None
    offset = u16(raw_smb2, 64 + 2)
    length = u32(raw_smb2, 64 + 4)
    if offset is None or length is None or length == 0:
        return b""
    return bytes_range(raw_smb2, offset, length)


def parse_query_directory_entries(data: bytes, file_info_class: Optional[int]):
    """Walk variable-sized directory records using NextEntryOffset.

    Malformed/truncated pages stop parsing instead of guessing an entry count.
    """
    layout = QUERY_DIRECTORY_NAME_LAYOUTS.get(safe_int(file_info_class))
    if not data or layout is None:
        return []
    name_length_offset, name_offset = layout
    names = []
    cursor = 0
    visited = set()
    while cursor < len(data) and cursor not in visited:
        visited.add(cursor)
        if cursor + name_offset > len(data):
            break
        next_offset = u32(data, cursor)
        name_length = u32(data, cursor + name_length_offset)
        if name_length is None:
            break
        raw_name = bytes_range(data, cursor + name_offset, name_length)
        if raw_name is None:
            break
        name = decode_smb_filename(raw_name)
        if name is not None:
            names.append(name)
        if not next_offset:
            break
        if next_offset < name_offset or cursor + next_offset > len(data):
            break
        cursor += next_offset
    return names
# End of helper functions

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

        "smb2_info_type": None,
        "smb2_file_info_class_raw": None,
        "smb2_file_info_class": None,

        "smb2_set_info_data": None,
        "smb2_rename_target": None,
        "smb2_delete_pending": None,
        "smb2_disposition_flags_raw": None,
        "smb2_disposition_flags": None,
        "smb2_truncate_size": None,
        "smb2_query_directory_response_data": None,
        "smb2_query_entry_count": None,
        "smb2_query_returned_names": None,
        "smb2_query_end_of_search": None,
        "smb2_query_total_bytes": None,
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
                    # print(f"[EXTRACT] DataLen={data_len} val_len={len(val) if val else 0} blob_len={len(result['smb2_read_blob']) if result['smb2_read_blob'] else 0}")
                    break
            # if safe_int(safe_get(smb2_layer, "DataLen")) == 1048576:
            #     print(f"[EXTRACTOR] DataLen=1048576 blob_len={len(result['smb2_read_blob']) if result['smb2_read_blob'] else 0}")

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

        elif isinstance(smb2_layer, SMB2_Query_Directory_Request):
            fid = safe_get(smb2_layer, "FileId")
            result["smb2_file_id"] = bytes(fid) if fid is not None else None

        elif (
            SMB2_Query_Directory_Response is not None
            and isinstance(smb2_layer, SMB2_Query_Directory_Response)
        ):
            data = buffer_data_to_bytes(safe_get(smb2_layer, "Buffer", []))
            result["smb2_query_directory_response_data"] = data
            result["smb2_query_total_bytes"] = len(data)
        
        elif isinstance(smb2_layer, SMB2_Query_Info_Response):
            buffer = safe_get(smb2_layer, "Buffer", [])
            for name, val in buffer:
                if name == "Output":
                    result["smb2_query_info_response_data"] = val
                    break
        
        elif isinstance(smb2_layer, SMB2_Set_Info_Request):
            fid = safe_get(smb2_layer, "FileId")
            result["smb2_file_id"] = bytes(fid) if fid is not None else None

            info_type = safe_int(safe_get(smb2_layer, "InfoType"))
            file_class = safe_int(safe_get(smb2_layer, "FileInfoClass"))

            result["smb2_info_type"] = info_type
            result["smb2_file_info_class_raw"] = file_class
            result["smb2_file_info_class"] = SMB2_FILE_INFO_CLASS.get(
                file_class,
                str(file_class) if file_class is not None else None,
            )

            data = buffer_data_to_bytes(safe_get(smb2_layer, "Buffer", []))
            result["smb2_set_info_data"] = data

            # Timestamp SET_INFO: FileBasicInformation, FileAllInformation, ...
            if info_type == 1 and file_class in FILE_INFO_CLASSES_WITH_TIMESTAMPS:
                if data and len(data) >= 32:
                    result["smb2_create_time"] = filetime_to_unix(struct.unpack("<Q", data[0:8])[0])
                    result["smb2_last_access_time"] = filetime_to_unix(struct.unpack("<Q", data[8:16])[0])
                    result["smb2_last_write_time"] = filetime_to_unix(struct.unpack("<Q", data[16:24])[0])
                    result["smb2_change_time"] = filetime_to_unix(struct.unpack("<Q", data[24:32])[0])

            # Rename
            if file_class in (10, 11):
                result["smb2_rename_target"] = parse_file_rename_information(data)

            # Delete / rmdir
            elif file_class in (13, 64):
                delete_pending, flags_raw, flags = parse_file_disposition_information(data)
                result["smb2_delete_pending"] = delete_pending
                result["smb2_disposition_flags_raw"] = flags_raw
                result["smb2_disposition_flags"] = flags

            # Truncate / allocation resize
            elif file_class in (20, 21):
                result["smb2_truncate_size"] = parse_file_size_information(data)
                
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
        result["smb2_file_id"] is None
        and str(cmd) == "17"
        and is_response is False
        and raw_smb2 is not None
    ):
        result["smb2_file_id"] = set_info_request_file_id(raw_smb2)

    if (
        not result["smb2_file_id"]
        and str(cmd) == "14"
        and is_response is False
        and raw_smb2 is not None
    ):
        # QUERY_DIRECTORY has FileId at the same fixed request offset as CLOSE:
        # SMB2 header (64) + StructureSize/Class/Flags/FileIndex (8).
        result["smb2_file_id"] = close_request_file_id(raw_smb2)

    if str(cmd) == "14" and is_response is True and raw_smb2 is not None:
        data = result["smb2_query_directory_response_data"]
        if data is None:
            data = query_directory_response_data(raw_smb2)
            result["smb2_query_directory_response_data"] = data
        if data is not None:
            result["smb2_query_total_bytes"] = len(data)
    
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

def get_smb2_metadata_scf(
    smb2_layer: Any,
    raw_smb2: Optional[bytes] = None,
    cmd: Optional[Any] = None,
    is_response: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Extract semantic fields cần cho SCF.

    Các field chính:
    - CREATE Request:
        smb2_desired_access
        smb2_create_disposition
        smb2_create_options

    - QUERY_INFO Request:
        smb2_query_info_type
        smb2_query_file_class
        smb2_file_info_class

    - SET_INFO Request:
        smb2_info_type
        smb2_file_info_class
        smb2_delete_pending

    Ưu tiên Scapy layer nếu có.
    Nếu Scapy không expose field thì fallback raw SMB2 offset.
    """

    result = {
        "smb2_desired_access_raw": None,
        "smb2_desired_access": None,

        "smb2_create_file_attributes_raw": None,
        "smb2_create_file_attributes": None,

        "smb2_share_access_raw": None,
        "smb2_share_access": None,

        "smb2_create_disposition_raw": None,
        "smb2_create_disposition": None,

        "smb2_create_options_raw": None,
        "smb2_create_options": None,

        "smb2_info_type": None,
        "smb2_file_info_class_raw": None,
        "smb2_file_info_class": None,

        "smb2_delete_pending": None,
        "smb2_disposition_flags_raw": None,
        "smb2_disposition_flags": None,
        "smb2_rename_target": None,

        "smb2_query_directory_flags_raw": None,
        "smb2_query_directory_flags": None,
        "smb2_query_directory_pattern": None,
    }

    cmd_str = str(cmd) if cmd is not None else None

    try:
        if smb2_layer is not None and isinstance(smb2_layer, SMB2_Create_Request):
            desired_access = safe_int(safe_get(smb2_layer, "DesiredAccess"))
            file_attributes = safe_int(safe_get(smb2_layer, "FileAttributes"))
            share_access = safe_int(safe_get(smb2_layer, "ShareAccess"))
            create_disposition = safe_int(safe_get(smb2_layer, "CreateDisposition"))
            create_options = safe_int(safe_get(smb2_layer, "CreateOptions"))

            result["smb2_desired_access_raw"] = desired_access
            result["smb2_desired_access"] = flags_to_names(
                desired_access,
                DESIRED_ACCESS_FLAGS,
            )

            result["smb2_create_file_attributes_raw"] = file_attributes
            result["smb2_create_file_attributes"] = flags_to_names(
                file_attributes,
                FILE_ATTRIBUTE_FLAGS,
            )

            result["smb2_share_access_raw"] = share_access
            result["smb2_share_access"] = flags_to_names(
                share_access,
                SHARE_ACCESS_FLAGS,
            )

            result["smb2_create_disposition_raw"] = create_disposition
            result["smb2_create_disposition"] = CREATE_DISPOSITION_MAP.get(
                create_disposition,
                str(create_disposition) if create_disposition is not None else None,
            )

            result["smb2_create_options_raw"] = create_options
            result["smb2_create_options"] = flags_to_names(
                create_options,
                CREATE_OPTIONS_FLAGS,
            )

        elif smb2_layer is not None and isinstance(smb2_layer, SMB2_Query_Info_Request):
            info_type = safe_int(safe_get(smb2_layer, "InfoType"))
            file_class = safe_int(safe_get(smb2_layer, "FileInfoClass"))

            result["smb2_info_type"] = info_type
            result["smb2_query_info_type"] = info_type
            result["smb2_query_file_class"] = file_class
            result["smb2_file_info_class_raw"] = file_class
            result["smb2_file_info_class"] = SMB2_FILE_INFO_CLASS.get(
                file_class,
                str(file_class) if file_class is not None else None,
            )

        elif smb2_layer is not None and isinstance(smb2_layer, SMB2_Set_Info_Request):
            info_type = safe_int(safe_get(smb2_layer, "InfoType"))
            file_class = safe_int(safe_get(smb2_layer, "FileInfoClass"))

            result["smb2_info_type"] = info_type
            result["smb2_file_info_class_raw"] = file_class
            result["smb2_file_info_class"] = SMB2_FILE_INFO_CLASS.get(
                file_class,
                str(file_class) if file_class is not None else None,
            )

            raw_buffer = safe_get(smb2_layer, "Buffer", [])
            for name, val in raw_buffer:
                if name == "Data" and val:
                    # FileDispositionInformation: 1 byte DeletePending
                    if file_class == 13:
                        result["smb2_delete_pending"] = bool(val[0])

                    # FileDispositionInformationEx: 4 bytes flags
                    elif file_class == 64 and len(val) >= 4:
                        disposition_flags = struct.unpack("<I", val[:4])[0]
                        result["smb2_disposition_flags_raw"] = disposition_flags
                        result["smb2_disposition_flags"] = flags_to_names(
                            disposition_flags,
                            FILE_DISPOSITION_EX_FLAGS,
                        )
                        result["smb2_delete_pending"] = bool(disposition_flags & 0x00000001)

                    elif file_class in (10, 65):
                        name_offset = 20 if file_class == 10 else 24
                        length_offset = 16 if file_class == 10 else 20
                        if len(val) >= name_offset:
                            name_length = u32(val, length_offset)
                            if name_length:
                                name_bytes = bytes_range(val, name_offset, name_length)
                                if name_bytes:
                                    result["smb2_rename_target"] = decode_smb_filename(name_bytes)

                    break

    except Exception:
        pass

    # Fallback raw SMB2 parser.
    # raw_smb2 phải bắt đầu tại FE 53 4D 42.
    if raw_smb2 is None or len(raw_smb2) < 64:
        return result

    try:
        # CREATE Request
        if cmd_str == "5" and is_response is False:
            desired_access = u32(raw_smb2, 64 + 24)
            file_attributes = u32(raw_smb2, 64 + 28)
            share_access = u32(raw_smb2, 64 + 32)
            create_disposition = u32(raw_smb2, 64 + 36)
            create_options = u32(raw_smb2, 64 + 40)

            if result["smb2_desired_access_raw"] is None:
                result["smb2_desired_access_raw"] = desired_access
                result["smb2_desired_access"] = flags_to_names(
                    desired_access,
                    DESIRED_ACCESS_FLAGS,
                )

            if result["smb2_create_file_attributes_raw"] is None:
                result["smb2_create_file_attributes_raw"] = file_attributes
                result["smb2_create_file_attributes"] = flags_to_names(
                    file_attributes,
                    FILE_ATTRIBUTE_FLAGS,
                )

            if result["smb2_share_access_raw"] is None:
                result["smb2_share_access_raw"] = share_access
                result["smb2_share_access"] = flags_to_names(
                    share_access,
                    SHARE_ACCESS_FLAGS,
                )

            if result["smb2_create_disposition_raw"] is None:
                result["smb2_create_disposition_raw"] = create_disposition
                result["smb2_create_disposition"] = CREATE_DISPOSITION_MAP.get(
                    create_disposition,
                    str(create_disposition) if create_disposition is not None else None,
                )

            if result["smb2_create_options_raw"] is None:
                result["smb2_create_options_raw"] = create_options
                result["smb2_create_options"] = flags_to_names(
                    create_options,
                    CREATE_OPTIONS_FLAGS,
                )

        # QUERY_INFO Request
        elif cmd_str == "16" and is_response is False:
            info_type = u8(raw_smb2, 64 + 2)
            file_class = u8(raw_smb2, 64 + 3)

            result["smb2_info_type"] = info_type
            result["smb2_query_info_type"] = info_type
            result["smb2_query_file_class"] = file_class
            result["smb2_file_info_class_raw"] = file_class
            result["smb2_file_info_class"] = SMB2_FILE_INFO_CLASS.get(
                file_class,
                str(file_class) if file_class is not None else None,
            )

        # SET_INFO Request
        elif cmd_str == "17" and is_response is False:
            info_type = u8(raw_smb2, 64 + 2)
            file_class = u8(raw_smb2, 64 + 3)
            buffer_length = u32(raw_smb2, 64 + 4)
            buffer_offset = u16(raw_smb2, 64 + 8)

            result["smb2_info_type"] = info_type
            result["smb2_file_info_class_raw"] = file_class
            result["smb2_file_info_class"] = SMB2_FILE_INFO_CLASS.get(
                file_class,
                str(file_class) if file_class is not None else None,
            )

            if buffer_offset is not None and buffer_length is not None:
                buf = bytes_range(raw_smb2, buffer_offset, buffer_length)

                if file_class == 13 and buf:
                    result["smb2_delete_pending"] = bool(buf[0])

                elif file_class == 64 and buf and len(buf) >= 4:
                    disposition_flags = struct.unpack("<I", buf[:4])[0]
                    result["smb2_disposition_flags_raw"] = disposition_flags
                    result["smb2_disposition_flags"] = flags_to_names(
                        disposition_flags,
                        FILE_DISPOSITION_EX_FLAGS,
                    )
                    result["smb2_delete_pending"] = bool(disposition_flags & 0x00000001)

                elif file_class in (10, 65) and buf:
                    name_offset = 20 if file_class == 10 else 24
                    length_offset = 16 if file_class == 10 else 20
                    if len(buf) >= name_offset:
                        name_length = u32(buf, length_offset)
                        if name_length:
                            name_bytes = bytes_range(buf, name_offset, name_length)
                            if name_bytes:
                                result["smb2_rename_target"] = decode_smb_filename(name_bytes)

        # QUERY_DIRECTORY Request
        elif cmd_str == "14" and is_response is False:
            file_class = u8(raw_smb2, 64 + 2)
            query_flags = u8(raw_smb2, 64 + 3)
            name_offset = u16(raw_smb2, 64 + 24)
            name_length = u16(raw_smb2, 64 + 26)

            result["smb2_file_info_class_raw"] = file_class
            result["smb2_file_info_class"] = SMB2_FILE_INFO_CLASS.get(
                file_class,
                str(file_class) if file_class is not None else None,
            )

            result["smb2_query_directory_flags_raw"] = query_flags
            result["smb2_query_directory_flags"] = flags_to_names(
                query_flags,
                QUERY_DIRECTORY_FLAGS,
            )

            if name_offset is not None and name_length:
                pattern_bytes = bytes_range(raw_smb2, name_offset, name_length)
                if pattern_bytes:
                    result["smb2_query_directory_pattern"] = decode_smb_filename(pattern_bytes)

    except Exception:
        pass

    return result
