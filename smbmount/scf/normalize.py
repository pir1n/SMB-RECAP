def canonical_list(value):
    if value is None:
        return ""

    if isinstance(value, list):
        return ",".join(sorted(str(v) for v in value))

    return str(value)


def normalize_packet(pkt):
    cmd = pkt.get("smb2_command_name")

    if cmd == "CREATE":
        return "|".join([
            "CREATE",
            canonical_list(pkt.get("smb2_desired_access")),
            str(pkt.get("smb2_create_disposition") or ""),
            canonical_list(pkt.get("smb2_create_options")),
        ])

    if cmd == "QUERY_INFO":
        return "|".join([
            "QUERY_INFO",
            str(pkt.get("smb2_query_info_type") or pkt.get("smb2_info_type") or ""),
            str(pkt.get("smb2_file_info_class") or pkt.get("smb2_query_file_class") or ""),
        ])

    if cmd == "SET_INFO":
        return "|".join([
            "SET_INFO",
            str(pkt.get("smb2_file_info_class") or ""),
            str(pkt.get("smb2_delete_pending") or ""),
        ])

    if cmd == "QUERY_DIRECTORY":
        return "|".join([
            "QUERY_DIRECTORY",
            str(pkt.get("smb2_file_info_class") or ""),
        ])

    if cmd == "WRITE":
        return "WRITE"

    if cmd == "READ":
        return "READ"

    if cmd == "CLOSE":
        return "CLOSE"

    return cmd or "UNKNOWN"