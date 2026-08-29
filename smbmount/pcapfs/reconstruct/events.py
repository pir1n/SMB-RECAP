from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class FileEvent:
    op: str
    timestamp: Optional[float] = None
    timestamp_source: Optional[str] = None
    network_timestamp: Optional[float] = None
    fs_timestamp: Optional[float] = None
    timestamp_mode: Optional[str] = None
    
    frame_number: Optional[float] = None

    path: Optional[str] = None
    old_path: Optional[str] = None
    new_path: Optional[str] = None

    file_id: Optional[str] = None
    is_dir: bool = False

    size_before: Optional[int] = None
    size_after: Optional[int] = None

    source_command: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "op": self.op,
            "timestamp": self.timestamp,
            "timestamp_source": self.timestamp_source,
            "network_timestamp": self.network_timestamp,
            "fs_timestamp": self.fs_timestamp,
            "timestamp_mode": self.timestamp_mode,
            "frame_number": self.frame_number,
            "path": self.path,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "file_id": self.file_id,
            "is_dir": self.is_dir,
            "size_before": self.size_before,
            "size_after": self.size_after,
            "smb_command": self.source_command,
            "evidence": self.evidence,
        }