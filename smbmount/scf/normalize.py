SCF_SCHEMA_VERSION = "scf-v2"


def canonical_value(value):
    """
    Convert value về dạng ổn định để hash.
    Không hash filename/path/content vì các field đó quá động.
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        return "1" if value else "0"

    if isinstance(value, int):
        return f"0x{value:08x}"

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(str(v) for v in value))

    return str(value)


def first_present(pkt, *names):
    for name in names:
        if pkt.get(name) is not None:
            return canonical_value(pkt.get(name))
    return ""


def safe_int(value):
    if value is None:
        return None

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int):
        return value

    try:
        return int(str(value), 0)
    except Exception:
        return None


def has_flag(pkt, field, flag):
    value = safe_int(pkt.get(field))
    return bool(value is not None and value & flag)


def disposition_family(value):
    value = safe_int(value)
    return {
        0x00000000: "supersede",
        0x00000001: "open",
        0x00000002: "create",
        0x00000003: "open_if",
        0x00000004: "overwrite",
        0x00000005: "overwrite_if",
    }.get(value, "unknown")


def create_result(value):
    value = safe_int(value)
    return {
        0x00000000: "superseded",
        0x00000001: "opened",
        0x00000002: "created",
        0x00000003: "overwritten",
    }.get(value, "unknown")


def info_class_name(pkt):
    return first_present(
        pkt,
        "smb2_file_info_class",
        "smb2_query_file_class",
        "smb2_file_info_class_raw",
    )


def file_target_type(pkt):
    options = safe_int(pkt.get("smb2_create_options_raw"))
    attributes = safe_int(pkt.get("smb2_create_file_attributes_raw"))

    if options is not None:
        if options & 0x00000001:
            return "directory"
        if options & 0x00000040:
            return "file"

    if attributes is not None and attributes & 0x00000010:
        return "directory"

    return "unknown"


def create_intents(pkt):
    access = safe_int(pkt.get("smb2_desired_access_raw")) or 0
    options = safe_int(pkt.get("smb2_create_options_raw")) or 0

    intents = []
    if access & (0x00000001 | 0x80000000):
        intents.append("read")
    if access & (0x00000002 | 0x00000004 | 0x40000000):
        intents.append("write")
    if access & 0x00010000:
        intents.append("delete")
    if access & (0x00000080 | 0x00000100):
        intents.append("metadata")
    if options & 0x00001000:
        intents.append("delete_on_close")
    return sorted(set(intents))


def io_length_class(pkt):
    length = safe_int(pkt.get("smb2_length"))
    if length is None:
        return "unknown"
    if length == 0:
        return "zero"
    return "nonzero"


def io_size_class(pkt):
    length = safe_int(pkt.get("smb2_length"))
    if length is None:
        return "unknown"
    if length == 0:
        return "zero"
    if length <= 64:
        return "tiny"
    if length <= 4096:
        return "small"
    if length <= 65536:
        return "medium"
    return "large"


def packet_features(pkt):
    """
    Build a stable semantic feature vector for SMB Command Fingerprinting.

    The vector avoids volatile values such as path, file id, offset, length and
    data bytes. It keeps command parameters that describe user intent.
    """
    cmd = pkt.get("smb2_command_name") or "UNKNOWN"
    features = {
        "schema": SCF_SCHEMA_VERSION,
        "command": cmd,
    }

    if cmd == "CREATE":
        features.update({
            "access_mask": first_present(pkt, "smb2_desired_access_raw", "smb2_desired_access"),
            "access_intents": create_intents(pkt),
            "file_attributes": first_present(pkt, "smb2_create_file_attributes_raw", "smb2_create_file_attributes"),
            "share_access": first_present(pkt, "smb2_share_access_raw", "smb2_share_access"),
            "create_disposition": first_present(pkt, "smb2_create_disposition_raw", "smb2_create_disposition"),
            "disposition_family": disposition_family(pkt.get("smb2_create_disposition_raw")),
            "create_action": first_present(pkt, "smb2_create_action"),
            "create_result": create_result(pkt.get("smb2_create_action")),
            "create_options": first_present(pkt, "smb2_create_options_raw", "smb2_create_options"),
            "target_type": file_target_type(pkt),
            "delete_on_close": has_flag(pkt, "smb2_create_options_raw", 0x00001000),
        })
        return features

    if cmd == "QUERY_INFO":
        features.update({
            "info_type": first_present(pkt, "smb2_query_info_type", "smb2_info_type"),
            "file_info_class": info_class_name(pkt),
        })
        return features

    if cmd == "SET_INFO":
        features.update({
            "info_type": first_present(pkt, "smb2_info_type"),
            "file_info_class": info_class_name(pkt),
            "delete_pending": canonical_value(pkt.get("smb2_delete_pending")),
            "disposition_flags": first_present(pkt, "smb2_disposition_flags_raw", "smb2_disposition_flags"),
            "rename_target_present": bool(pkt.get("smb2_rename_target")),
        })
        return features

    if cmd == "QUERY_DIRECTORY":
        features.update({
            "file_info_class": info_class_name(pkt),
            "query_flags": first_present(pkt, "smb2_query_directory_flags_raw", "smb2_query_directory_flags"),
            "pattern_class": query_pattern_class(pkt.get("smb2_query_directory_pattern")),
        })
        return features

    if cmd in ("READ", "WRITE"):
        features["io"] = cmd.lower()
        features["length_class"] = io_length_class(pkt)
        features["io_size_class"] = io_size_class(pkt)
        return features

    if cmd in ("CLOSE", "FLUSH", "TREE_CONNECT", "TREE_DISCONNECT", "SESSION_SETUP", "LOGOFF"):
        return features

    return features


def query_pattern_class(pattern):
    if pattern is None:
        return "none"

    text = str(pattern)
    if text in ("*", "*.*"):
        return "wildcard"
    if "*" in text or "?" in text:
        return "glob"
    return "literal"


def normalize_features(features):
    parts = []
    for key in sorted(features):
        value = features[key]
        parts.append(f"{key}={canonical_value(value)}")
    return "|".join(parts)


def normalize_packet(pkt):
    return normalize_features(packet_features(pkt))


def normalize_packet_v1(pkt):
    cmd = pkt.get("smb2_command_name")

    if cmd == "CREATE":
        return "|".join([
            "CREATE",

            # AccessMask
            first_present(pkt, "smb2_desired_access_raw", "smb2_desired_access"),

            # FileAttributes trong CREATE request, không dùng FileAttributes response
            first_present(pkt, "smb2_create_file_attributes_raw", "smb2_create_file_attributes"),

            # ShareAccess
            first_present(pkt, "smb2_share_access_raw", "smb2_share_access"),

            # CreateDisposition
            first_present(pkt, "smb2_create_disposition_raw", "smb2_create_disposition"),

            # CreateOptions
            first_present(pkt, "smb2_create_options_raw", "smb2_create_options"),
        ])

    if cmd == "QUERY_INFO":
        return "|".join([
            "QUERY_INFO",
            first_present(pkt, "smb2_query_info_type", "smb2_info_type"),
            first_present(pkt, "smb2_file_info_class_raw", "smb2_file_info_class", "smb2_query_file_class"),
        ])

    if cmd == "SET_INFO":
        return "|".join([
            "SET_INFO",
            first_present(pkt, "smb2_info_type"),
            first_present(pkt, "smb2_file_info_class_raw", "smb2_file_info_class"),
            first_present(pkt, "smb2_delete_pending"),
            first_present(pkt, "smb2_disposition_flags_raw", "smb2_disposition_flags"),
        ])

    if cmd == "QUERY_DIRECTORY":
        return "|".join([
            "QUERY_DIRECTORY",
            first_present(pkt, "smb2_file_info_class_raw", "smb2_file_info_class"),
            first_present(pkt, "smb2_query_directory_flags_raw", "smb2_query_directory_flags"),
            # Pattern thường là "*"; giữ lại để phân biệt case đặc biệt.
            first_present(pkt, "smb2_query_directory_pattern"),
        ])

    if cmd == "WRITE":
        # Không hash length/offset/data để rule không phụ thuộc kích thước file.
        return "WRITE"

    if cmd == "READ":
        return "READ"

    if cmd == "CLOSE":
        return "CLOSE"

    return cmd or "UNKNOWN"
