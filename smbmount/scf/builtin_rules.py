"""
Built-in semantic SCF rules.

These rules are intentionally operation-level, not packet-level. The author TSV
rules in cmd-rules_author.tsv describe CMD operations as command signatures
such as mkdir, echo >, echo >>, del, rmdir, rename/move, copy, dir. Mirroring
that idea with semantic SCF v2 means a rule should usually require a contextual
CREATE/open followed by the SMB command that carries the user intent.

Avoid broad one-packet rules such as "any WRITE is write_file" because they
inflate false positives when a single shell operation produces several SMB
requests or when writes are subordinate to create/overwrite/copy operations.
"""


BUILTIN_RULES = [
    {
        "id": "cmd_mkdir_directory_created",
        "action": "creation of directory",
        "description": "CMD mkdir: CREATE directory whose response CreateAction is created.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "directory",
                    "create_result": "created",
                },
            },
        ],
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_echo_create_file_created",
        "action": "creation of file",
        "description": "CMD echo > create file: CREATE destination with echo-style access/options, then WRITE echo output.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "access_mask": "0x00120196",
                    "file_attributes": "0x00000080",
                    "share_access": "0x00000001",
                    "create_disposition": "0x00000005",
                    "create_options": "0x00000060",
                },
                "contains": {
                    "access_intents": ["write"],
                },
            },
            {
                "command": "WRITE",
                "features": {
                    "length_class": "nonzero",
                },
            },
        ],
        "max_gap": 8,
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_echo_overwrite_file",
        "action": "overwrite of file",
        "description": "CMD echo > existing file: CREATE file whose response CreateAction is overwritten.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "create_result": "overwritten",
                },
                "contains": {
                    "access_intents": ["write"],
                },
            },
        ],
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_copy_upload_file",
        "action": "upload file",
        "description": "CMD copy to server: CREATE destination using copy-style access/options, then WRITE payload.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "access_mask": "0x0017019f",
                    "file_attributes": "0x00000020",
                    "share_access": "0x00000000",
                    "create_disposition": "0x00000005",
                    "create_options": "0x00000044",
                },
                "any_features": {
                    "create_result": ["created", "overwritten"],
                },
                "contains": {
                    "access_intents": ["read", "write"],
                },
            },
            {
                "command": "WRITE",
                "features": {
                    "length_class": "nonzero",
                },
            },
        ],
        "max_gap": 24,
        "require_success": True,
        "confidence": 0.94,
    },
    {
        "id": "cmd_echo_append_file",
        "action": "append to file",
        "description": "CMD echo >> append: open existing file for write followed by WRITE.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "create_result": "opened",
                },
                "contains": {
                    "access_intents": ["write"],
                },
            },
            {
                "command": "WRITE",
                "features": {
                    "length_class": "nonzero",
                },
            },
        ],
        "max_gap": 12,
        "require_success": True,
        "confidence": 0.95,
    },
    {
        "id": "cmd_more_read_file",
        "action": "read of file",
        "description": "CMD more read/view: CREATE source with more-style create_options 0x00020060, then READ.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "access_mask": "0x00120089",
                    "file_attributes": "0x00000080",
                    "share_access": "0x00000003",
                    "create_disposition": "0x00000001",
                    "create_options": "0x00020060",
                },
                "contains": {
                    "access_intents": ["read"],
                },
            },
            {
                "command": "READ",
                "features": {
                    "length_class": "nonzero",
                },
            },
        ],
        "max_gap": 16,
        "require_success": True,
        "confidence": 0.95,
    },
    {
        "id": "cmd_copy_download_file",
        "action": "download file",
        "description": "CMD copy from server: CREATE source with copy-from-server create_options 0x00200044/share 0x5, then READ.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "access_mask": "0x00120089",
                    "file_attributes": "0x00000000",
                    "share_access": "0x00000005",
                    "create_disposition": "0x00000001",
                    "create_options": "0x00200044",
                },
                "contains": {
                    "access_intents": ["read"],
                },
            },
            {
                "command": "READ",
                "features": {
                    "length_class": "nonzero",
                },
            },
        ],
        "max_gap": 16,
        "require_success": True,
        "confidence": 0.93,
    },
    {
        "id": "cmd_del_delete_on_close_file",
        "action": "deletion of file",
        "description": "CMD del variant: CREATE file with FILE_DELETE_ON_CLOSE.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "delete_on_close": True,
                },
                "contains": {
                    "access_intents": ["delete"],
                },
            },
        ],
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_del_set_info_file",
        "action": "deletion of file",
        "description": "CMD del variant: CREATE file with delete access followed by SET_INFO disposition.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "create_result": "opened",
                },
                "contains": {
                    "access_intents": ["delete"],
                },
            },
            {
                "command": "SET_INFO",
                "features": {
                    "file_info_class": "FileDispositionInformation",
                    "delete_pending": "1",
                },
            },
        ],
        "max_gap": 8,
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_del_set_info_file_ex",
        "action": "deletion of file",
        "description": "CMD del variant: CREATE file with delete access followed by SET_INFO disposition ex.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "file",
                    "create_result": "opened",
                },
                "contains": {
                    "access_intents": ["delete"],
                },
            },
            {
                "command": "SET_INFO",
                "features": {
                    "file_info_class": "FileDispositionInformationEx",
                    "delete_pending": "1",
                },
            },
        ],
        "max_gap": 8,
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_rmdir_set_info_directory",
        "action": "deletion of directory",
        "description": "CMD rmdir: open directory with delete access followed by SET_INFO disposition.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "directory",
                    "create_result": "opened",
                },
                "contains": {
                    "access_intents": ["delete"],
                },
            },
            {
                "command": "SET_INFO",
                "features": {
                    "file_info_class": "FileDispositionInformation",
                    "delete_pending": "1",
                },
            },
        ],
        "max_gap": 10,
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_rmdir_set_info_directory_ex",
        "action": "deletion of directory",
        "description": "CMD rmdir: open directory with delete access followed by SET_INFO disposition ex.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "directory",
                    "create_result": "opened",
                },
                "contains": {
                    "access_intents": ["delete"],
                },
            },
            {
                "command": "SET_INFO",
                "features": {
                    "file_info_class": "FileDispositionInformationEx",
                    "delete_pending": "1",
                },
            },
        ],
        "max_gap": 10,
        "require_success": True,
        "confidence": 0.98,
    },
    {
        "id": "cmd_rename_file",
        "action": "rename or move",
        "description": "CMD ren/move file: SET_INFO FileRenameInformation with rename target.",
        "pattern": [
            {
                "command": "SET_INFO",
                "features": {
                    "file_info_class": "FileRenameInformation",
                    "rename_target_present": True,
                },
            },
        ],
        "require_success": True,
        "confidence": 0.96,
    },
    {
        "id": "cmd_rename_file_ex",
        "action": "rename or move",
        "description": "CMD ren/move file: SET_INFO FileRenameInformationEx with rename target.",
        "pattern": [
            {
                "command": "SET_INFO",
                "features": {
                    "file_info_class": "FileRenameInformationEx",
                    "rename_target_present": True,
                },
            },
        ],
        "require_success": True,
        "confidence": 0.96,
    },
    {
        "id": "cmd_dir_directory_listing",
        "action": "directory listing",
        "description": "CMD dir: open directory then query directory entries.",
        "pattern": [
            {
                "command": "CREATE",
                "features": {
                    "target_type": "directory",
                    "create_result": "opened",
                },
                "contains": {
                    "access_intents": ["read"],
                },
            },
            {
                "command": "QUERY_DIRECTORY",
            },
        ],
        "max_gap": 12,
        "require_success": True,
        "confidence": 0.94,
    },
    {
        "id": "cmd_dir_root_listing",
        "action": "directory listing",
        "description": "CMD dir root/share listing: metadata open followed by QUERY_DIRECTORY.",
        "pattern": [
            {
                "command": "CREATE",
                "contains": {
                    "access_intents": ["metadata"],
                },
            },
            {
                "command": "QUERY_DIRECTORY",
            },
        ],
        "max_gap": 12,
        "require_success": True,
        "confidence": 0.86,
    },
]
