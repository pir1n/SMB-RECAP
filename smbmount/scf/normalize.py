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

    if isinstance(value, list):
        return ",".join(sorted(str(v) for v in value))

    return str(value)


def first_present(pkt, *names):
    for name in names:
        if pkt.get(name) is not None:
            return canonical_value(pkt.get(name))
    return ""


def normalize_packet(pkt):
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