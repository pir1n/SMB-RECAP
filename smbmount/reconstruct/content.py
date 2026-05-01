from smbmount.core.file_table import FileTable


def process_packets(packets):
    table = FileTable()

    for pkt in packets:
        cmd = pkt.get("smb2_command_name")
        file_id = pkt.get("smb2_file_id")
        # print(pkt)
        offset = pkt.get("smb2_offset")
        length = pkt.get("smb2_length")
        # print(cmd, file_id, offset, length)
        if not file_id:
            continue

        file_obj = table.get_or_create(file_id)

        # CREATE → lấy filename
        if cmd == "CREATE":
            filename = pkt.get("smb2_filename")
            if filename:
                file_obj.path = filename

        # READ / WRITE → content mapping
        if cmd in ("READ", "WRITE"):
            offset = pkt.get("smb2_offset")
            length = pkt.get("smb2_length")
            if offset is not None and length is not None:
                file_obj.add_chunk(offset, length)

    return table