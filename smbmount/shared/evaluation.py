import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


CANONICAL_EVENTS = {
    "create_file",
    "create_directory",
    "read_file",
    "write_file",
    "upload_file",
    "download_file",
    "append_file",
    "overwrite_file",
    "delete_file",
    "delete_directory",
    "rename_file",
    "directory_listing",
}


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def read_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8-sig") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSONL: {exc}") from exc
    return rows


def write_jsonl(path, rows):
    ensure_dir(Path(path).parent)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path, data):
    ensure_dir(Path(path).parent)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def read_json_or_jsonl(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text[0] == "[":
        return json.loads(text)
    return read_jsonl(path)


def now_utc_iso():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def normalize_event(value):
    if value is None:
        return None

    text = str(value).strip()
    key = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")

    direct = {
        "create_file": "create_file",
        "creation_of_file": "create_file",
        "create_directory": "create_directory",
        "creation_of_directory": "create_directory",
        "list_directory": "directory_listing",
        "read_file": "read_file",
        "read_of_file": "read_file",
        "read_content": "read_file",
        "download_file": "download_file",
        "download_of_file": "download_file",
        "download_from_share": "download_file",
        "copy_file_from_server": "download_file",
        "copy_from_server": "download_file",
        "copy_file_to_server": "upload_file",
        "copy_to_server": "upload_file",
        "view_file": "read_file",
        "write_file": "write_file",
        "write_to_file": "write_file",
        "upload_file": "upload_file",
        "upload_to_share": "upload_file",
        "append_file": "append_file",
        "append_to_file": "append_file",
        "file_content_modification": "append_file",
        "overwrite_file": "overwrite_file",
        "overwrite_of_file": "overwrite_file",
        "delete_file": "delete_file",
        "remove_file": "delete_file",
        "deletion_of_file": "delete_file",
        "deletion_on_close": "delete_file",
        "delete_on_close": "delete_file",
        "delete_on_close_create": "delete_file",
        "delete_file_set_info": "delete_file",
        "delete_file_set_info_ex": "delete_file",
        "delete_directory": "delete_directory",
        "remove_directory": "delete_directory",
        "deletion_of_directory": "delete_directory",
        "rename_file": "rename_file",
        "move_file": "rename_file",
        "rename_directory": "rename_file",
        "move_directory": "rename_file",
        "rename_of_file": "rename_file",
        "move_of_file": "rename_file",
        "rename_of_directory": "rename_file",
        "move_of_directory": "rename_file",
        "rename_or_move_of_file": "rename_file",
        "rename_or_move_of_directory": "rename_file",
        "rename_or_move": "rename_file",
        "directory_listing": "directory_listing",
    }
    if key in direct:
        return direct[key]

    if "directory" in key and ("list" in key or "query" in key):
        return "directory_listing"
    if "upload" in key:
        return "upload_file"
    if "append" in key:
        return "append_file"
    if "download" in key:
        return "download_file"
    if "view" in key:
        return "read_file"
    if "remove" in key:
        if "director" in key:
            return "delete_directory"
        return "delete_file"
    if "rename" in key or "move" in key:
        return "rename_file"
    if "overwrite" in key or "supersede" in key:
        return "overwrite_file"
    if "write" in key:
        return "write_file"
    if "read" in key:
        return "read_file"
    if "delete" in key or "deletion" in key:
        if "director" in key:
            return "delete_directory"
        return "delete_file"
    if "creat" in key:
        if "director" in key:
            return "create_directory"
        return "create_file"

    return key or None


def normalize_path(path, case_sensitive=False):
    if path is None:
        return None
    text = str(path).strip().replace("\\", "/")
    text = re.sub(r"^[a-zA-Z]:/+", "", text)
    text = re.sub(r"^/+", "", text)
    text = re.sub(r"/+", "/", text).rstrip("/")
    if not case_sensitive:
        text = text.lower()
    return text


def posix_join(*parts):
    return str(PurePosixPath(*[str(part).strip("/\\") for part in parts if str(part).strip("/\\")]))


def windows_path(drive, rel_path):
    drive = drive.rstrip(":\\/")
    return f"{drive}:\\" + str(rel_path).replace("/", "\\")


def ps_quote(value):
    if value is None:
        return "$null"
    return "'" + str(value).replace("'", "''") + "'"


def cmd_quote(value):
    return '"' + str(value).replace('"', '""') + '"'


def sh_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def smb_path(path):
    return str(path).replace("\\", "/")
