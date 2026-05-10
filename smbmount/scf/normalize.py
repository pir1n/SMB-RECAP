def normalize_packet(pkt):

    cmd = pkt.get("smb2_command_name")

    #
    # CREATE
    #
    if cmd == "CREATE":

        return "|".join([
            "CREATE",
            str(pkt.get("smb2_desired_access")),
            str(pkt.get("smb2_create_disposition")),
            str(pkt.get("smb2_create_options")),
        ])

    #
    # QUERY_INFO
    #
    if cmd == "QUERY_INFO":

        return "|".join([
            "QUERY_INFO",
            str(pkt.get("smb2_query_info_type")),
            str(pkt.get("smb2_query_file_class")),
        ])

    #
    # SET_INFO
    #
    if cmd == "SET_INFO":

        return "|".join([
            "SET_INFO",
            str(pkt.get("smb2_file_info_class")),
        ])

    #
    # QUERY_DIRECTORY
    #
    if cmd == "QUERY_DIRECTORY":
        return "QUERY_DIRECTORY"

    #
    # CLOSE
    #
    if cmd == "CLOSE":
        return "CLOSE"

    return cmd or "UNKNOWN"