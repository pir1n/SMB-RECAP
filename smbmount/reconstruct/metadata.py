from typing import Dict
class FileMetadata:
    def __init__(self):
        self.created = None
        self.modified = None
        self.accessed = None
        self.size = 0
        
    def update_from_packet(self, pkt: Dict):
        
        ts = pkt.get("timestamp")
        
        if ts:
            if self.created is None:
                self.created = ts
            self.modified = ts
            self.accessed = ts
            
        length = pkt.get("smb2_length")
        offset = pkt.get("smb2_offset")
        
        if length is not None and offset is not None:
            self.size = max(self.size, offset + length)
        