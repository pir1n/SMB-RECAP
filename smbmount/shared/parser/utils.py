from typing import Any, Optional
from datetime import datetime, timezone

def safe_get(layer: Any, field_name: str, default: Optional[Any] = None) -> Optional[Any]:
    """
    Lấy field từ scapy layer một cách an toàn.
    Nếu field không tồn tại thì trả về default.
    """
    try:
        if layer is None:
            return default
        
        value = getattr(layer, field_name, default)
        if value is None or value == "":
            return default
        return value
    except Exception:
        return default
    
def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    """
    Convert value sang int nếu có thể.
    Hỗ trợ cả string decimal và hex dạng 0x...
    """
    if value is None:
        return default

    try:
        text = str(value)
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    except Exception:
        return default
    
def parse_timestamp(value: Any) -> Optional[float]:
    """
    Convert timestamp của pyshark/tshark về Unix epoch seconds.

    Hỗ trợ cả:
    - 1710000000.123456
    - 2026-04-28T10:14:23.918258600Z
    """
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    # Trường hợp timestamp là epoch dạng số
    try:
        return float(text)
    except ValueError:
        pass

    # Trường hợp ISO timestamp dạng 2026-04-28T10:14:23.918258600Z
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    # Python datetime chỉ hỗ trợ microsecond 6 chữ số,
    # trong khi tshark có thể trả nanosecond 9 chữ số.
    if "." in text:
        date_part, rest = text.split(".", 1)

        if "+" in rest:
            frac, tz = rest.split("+", 1)
            frac = frac[:6].ljust(6, "0")
            text = f"{date_part}.{frac}+{tz}"
        elif "-" in rest:
            frac, tz = rest.split("-", 1)
            frac = frac[:6].ljust(6, "0")
            text = f"{date_part}.{frac}-{tz}"
        else:
            frac = rest[:6].ljust(6, "0")
            text = f"{date_part}.{frac}"

    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.timestamp()

def filetime_to_unix(value: Any) -> Optional[float]:
    """
    Convert Windows FILETIME timestamp sang Unix epoch seconds.

    SMB2 CREATE response dùng FILETIME:
    số 100-nanosecond intervals tính từ 1601-01-01 UTC.
    """
    filetime = safe_int(value)
    if filetime is None or filetime == 0:
        return None
    return (filetime / 10_000_000) - 11644473600

def decode_smb_filename(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        for encoding in ("utf-16-le", "utf-8"):
            try:
                text = value.decode(encoding).rstrip("\x00")
                return text if text else None
            except UnicodeDecodeError:
                continue
    return str(value) if value else None

def print_progress(current: int, total: int, prefix: str = "Processing") -> None:
    """
    Hiển thị progress bar với phần trăm hoàn thành.
    """
    if total == 0:
        percent = 0
    else:
        percent = int((current / total) * 100)
    
    bar_length = 40
    filled_length = int((current / total) * bar_length) if total > 0 else 0
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    
    print(f"\r{prefix}: [{bar}] {percent}% ({current}/{total})", end="", flush=True)
    
    if current == total:
        print()  # New line at end