from typing import Dict


class FileMetadata:
    def __inti__(self):
        self.created = None
        self.mofified = None
        self.accessed = None
        self.size = 0
        
    def update_from_packet(self, pkt: Dict):
        
        ts = pkt.get("timestamp")
        
        if ts:
            if self.created is None:
                self.created = ts