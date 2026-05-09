SMB2_COMMAND_MAP = {
    "0": "NEGOTIATE",
    "1": "SESSION_SETUP",
    "2": "LOGOFF",
    "3": "TREE_CONNECT",
    "4": "TREE_DISCONNECT",
    "5": "CREATE",
    "6": "CLOSE",
    "7": "FLUSH",
    "8": "READ",
    "9": "WRITE",
    "10": "LOCK",
    "11": "IOCTL",
    "12": "CANCEL",
    "13": "ECHO",
    "14": "QUERY_DIRECTORY",
    "15": "CHANGE_NOTIFY",
    "16": "QUERY_INFO",
    "17": "SET_INFO",
}

SMB2_INFO_TYPE = {
    1: "SMB2_0_INFO_FILE",
    2: "SMB2_0_INFO_FILESYSTEM",
    3: "SMB2_0_INFO_SECURITY",
    4: "SMB2_0_INFO_QUOTA",
}

SMB2_FILE_INFO_CLASS = {
    1:  "FileDirectoryInformation",
    2:  "FileFullDirectoryInformation",
    4:  "FileBasicInformation",        # ← có timestamps
    5:  "FileStandardInformation",
    6:  "FileInternalInformation",
    7:  "FileEaInformation",
    8:  "FileAccessInformation",
    11: "FileRenameInformation",
    13: "FileDispositionInformation",
    14: "FilePositionInformation",
    16: "FileFullEaInformation",
    17: "FileModeInformation",
    18: "FileAlignmentInformation",
    19: "FileAllInformation",
    20: "FileAllocationInformation",
    21: "FileEndOfFileInformation",
    22: "FileLinkInformation",
    34: "FileNetworkOpenInformation",  # ← có timestamps
    35: "FileAttributeTagInformation",
}

# Class nào chứa timestamps ở 32 byte đầu
FILE_INFO_CLASSES_WITH_TIMESTAMPS = {4, 34}