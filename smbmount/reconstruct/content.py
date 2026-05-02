from smbmount.core.file_table import FileTable


def process_packets(packets):
    table = FileTable()

    for pkt in packets:
        cmd = pkt.get("smb2_command_name")
        file_id = pkt.get("smb2_file_id")
        ts = pkt.get("timestamp")

        if not file_id:
            continue

        file_obj = table.get_or_create(file_id)

        # metadata always update
        file_obj.update_metadata(pkt)

        # CREATE → path
        if cmd == "CREATE":
            filename = pkt.get("smb2_filename")
            if filename:
                file_obj.path = filename

        # WRITE → versioning
        if cmd in ("WRITE", "READ"):
            offset = pkt.get("smb2_offset")
            length = pkt.get("smb2_length")

            if offset is not None and length is not None and pkt.get("smb2_is_response") is True:
                file_obj.write(offset, length, ts)

    return table