from smbmount.core.file_table import FileTable
from smbmount.reconstruct.timestamps import TimestampResolver

def status_success(pkt):
    status = pkt.get("smb2_status")
    return status in (0, "0", "0x0", "STATUS_SUCCESS", None)


def get_file_id(pkt):
    return pkt.get("smb2_file_id") or pkt.get("mapped_file_id")


def get_path(pkt):
    return pkt.get("mapped_filename") or pkt.get("smb2_filename")


def safe_int(value, default=0):
    if value is None:
        return default

    try:
        if isinstance(value, str) and value.startswith("0x"):
            return int(value, 16)
        return int(value)
    except Exception:
        return default


def event_timestamp(pkt):
    return pkt.get("timestamp")


def fs_timestamp(pkt):
    return (
        pkt.get("smb2_last_write_time")
        or pkt.get("timestamp")
    )


def is_directory_create(pkt):
    create_options = safe_int(pkt.get("smb2_create_options_raw"))
    file_attrs = safe_int(pkt.get("smb2_file_attributes"))

    # create_options bit 0x1: FILE_DIRECTORY_FILE
    # file_attributes bit 0x10: FILE_ATTRIBUTE_DIRECTORY
    return bool(create_options & 0x00000001) or bool(file_attrs & 0x00000010)


def create_action_is_created(pkt):
    # SMB2 CreateAction: 2 thường là FILE_CREATED
    return safe_int(pkt.get("smb2_create_action"), default=-1) == 2

def process_packets(packets, timestamp_mode="hybrid"):
    ts = TimestampResolver(timestamp_mode)
    table = FileTable()
    last_write_version = {}

    for pkt in packets:
        cmd = pkt.get("smb2_command_name")
        is_response = pkt.get("smb2_is_response")

        file_id = get_file_id(pkt)
        path = get_path(pkt)
        
        event_pkt = ts.annotate_event_packet(pkt)
        version_time = ts.version_time(pkt)
        event_time = ts.event_time(pkt)

        if file_id is None and path is None:
            continue

        if file_id is not None:
            file_obj = table.get_or_create(file_id)
        else:
            file_obj = table.get_or_create_path_context(
                path,
                timestamp=event_time,
                pkt=event_pkt,
            )

        if path:
            table.bind_path(
                file_obj,
                path,
                timestamp=event_time,
            )

        file_obj.update_metadata(pkt)

        # CREATE response success:
        # - bind path
        # - mở version session
        # - phát hiện mkdir nếu có directory create
        if cmd == "CREATE":
            if path:
                table.bind_path(
                    file_obj,
                    path,
                    timestamp=event_time,
                )

            if is_response is True and status_success(pkt):
                if is_directory_create(pkt):
                    file_obj.mark_directory(True)

                    if create_action_is_created(pkt):
                        file_obj.add_event(
                            "mkdir",
                            event_pkt,
                            is_dir=True,
                            evidence={
                                "create_action": pkt.get("smb2_create_action"),
                                "create_options": pkt.get("smb2_create_options"),
                                "create_options_raw": pkt.get("smb2_create_options_raw"),
                            },
                        )

                if path and version_time and path in last_write_version:
                    prev_file_obj, prev_version_idx = last_write_version[path]
                    prev_versions = prev_file_obj.versions.versions

                    if prev_version_idx < len(prev_versions):
                        prev_v = prev_versions[prev_version_idx]

                        if prev_v.last_op == "write" and prev_v.modified != version_time:
                            prev_v.modified = version_time
                            prev_v.snapshot_metadata = ts.snapshot_metadata(
                                prev_file_obj,
                                pkt,
                                size=prev_v.size,
                            )

                    del last_write_version[path]

                file_obj.open(version_time)

            continue

        # READ response success:
        # READ không thay đổi server state, nhưng giữ evidence content nếu có.
        if cmd == "READ" and is_response is True and status_success(pkt):
            offset = pkt.get("smb2_offset")
            length = pkt.get("smb2_length")
            data = pkt.get("smb2_read_blob")

            if offset is not None and length is not None:
                file_obj.add_read(
                    offset,
                    length,
                    data=data,
                    timestamp=version_time,
                    pkt=event_pkt,
                )

                if file_obj.versions.current:
                    file_obj.versions.current.snapshot_metadata = ts.snapshot_metadata(
                        file_obj,
                        pkt,
                        size=file_obj.metadata.size,
                    )

            continue

        # WRITE response success:
        # Dùng response vì đã biết status = success.
        # Data/offset/length đã được copy từ request sang response bởi pcap_reader.
        if cmd == "WRITE" and is_response is True and status_success(pkt):
            offset = pkt.get("smb2_offset")
            length = pkt.get("smb2_length")
            data = pkt.get("smb2_read_blob")

            if offset is not None and length is not None:
                file_obj.add_write(
                    offset,
                    length,
                    data=data,
                    timestamp=version_time,
                    pkt=event_pkt,
                )

                if file_obj.versions.current:
                    file_obj.versions.current.snapshot_metadata = ts.snapshot_metadata(
                        file_obj,
                        pkt,
                        size=file_obj.metadata.size,
                    )

                if file_obj.path:
                    last_write_version[file_obj.path] = (
                        file_obj,
                        len(file_obj.versions.versions) - 1,
                    )

            continue

        # SET_INFO response success:
        # Xử lý rename/delete/truncate nếu parser có field tương ứng.
        if cmd == "SET_INFO" and is_response is True and status_success(pkt):
            file_info_class_raw = safe_int(
                pkt.get("smb2_file_info_class_raw"),
                default=-1,
            )
            file_info_class = pkt.get("smb2_file_info_class")

            # Rename
            if (
                file_info_class_raw in (10, 11)
                or file_info_class in ("FileRenameInformation", "FileRenameInformationEx")
            ):
                new_path = pkt.get("smb2_rename_target")

                if new_path:
                    file_obj.rename(new_path, event_pkt)
                    table.bind_path(
                        file_obj,
                        new_path,
                        timestamp=event_time,
                    )

            # Delete / rmdir
            elif (
                file_info_class_raw == 13
                or file_info_class in ("FileDispositionInformation", "FileDispositionInformationEx")
            ):
                if pkt.get("smb2_delete_pending") is True:
                    file_obj.truncate(new_size, pkt=event_pkt)

            # Truncate / allocation resize
            elif (
                file_info_class_raw in (20, 21)
                or file_info_class in ("FileAllocationInformation", "FileEndOfFileInformation")
            ):
                new_size = pkt.get("smb2_truncate_size")

                if new_size is not None:
                    file_obj.truncate(new_size, pkt=event_pkt)

            else:
                file_obj.update_version_metadata(version_time)
                file_obj.mark_metadata_update(event_pkt)

            continue

        # QUERY_INFO response:
        # Tạm thời chỉ update metadata/version timestamp.
        # Metadata-only/context-only sẽ mở rộng ở phần sau.
        if cmd == "QUERY_INFO" and is_response is True and status_success(pkt):
            file_obj.update_version_metadata(version_time)
            continue

        # CLOSE response:
        # Commit version hiện tại.
        if cmd == "CLOSE" and is_response is True:
            filename = file_obj.path

            if status_success(pkt):
                if filename and version_time and filename in last_write_version:
                    prev_file_obj, prev_version_idx = last_write_version[filename]
                    prev_versions = prev_file_obj.versions.versions

                    if prev_version_idx < len(prev_versions):
                        prev_v = prev_versions[prev_version_idx]

                        if prev_v.last_op == "write":
                            prev_v.modified = version_time
                            prev_v.snapshot_metadata = ts.snapshot_metadata(
                                prev_file_obj,
                                pkt,
                                size=prev_v.size,
                            )

                    del last_write_version[filename]

            file_obj.commit(version_time)
            continue

    # Flush pending WRITE sau khi xử lý hết packets.
    # Quan trọng: block này nằm ngoài vòng for pkt.
    for filename, (pending_file_obj, pending_version_idx) in list(last_write_version.items()):
        prev_versions = pending_file_obj.versions.versions

        if pending_version_idx < len(prev_versions):
            prev_v = prev_versions[pending_version_idx]

            if prev_v.last_op == "write" and prev_v.snapshot_metadata is None:
                prev_v.snapshot_metadata = {
                    "created": pending_file_obj.metadata.created,
                    "modified": prev_v.modified,
                    "accessed": prev_v.modified,
                    "changed": getattr(pending_file_obj.metadata, "changed", None),
                    "size": prev_v.size,
                    "timestamp_mode": timestamp_mode,
                    "version_timestamp_source": "pending_write",
                    "network_timestamp": None,
                }

        del last_write_version[filename]

    return table