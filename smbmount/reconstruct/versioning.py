class FileVersion:
    def __init__(self, version_id: int):
        self.version_id = version_id
        self.size = 0
        self.modified = None
        self.chunks = []
        
    def add_chunk(self, offset, length):
        self.chunks.append((offset, length))
        if offset is not None and length is not None:
            self.size = max(self.size, offset + length)
            
class VersionManager:
    def __init__(self):
        self.versions = []
        self.current = None
        
    def start_new_version(self, timestamp):
        version_id = len(self.versions) + 1
        v = FileVersion(version_id)
        v.modified = timestamp
        self.versions.append(v)
        self.current = v
    
    def add_write(self, offset, length, timestamp):
        if self.current is None:
            self.start_new_version(timestamp)
        
        if self.current.modified != timestamp:
            self.start_new_version(timestamp)
        
        self.current.add_chunk(offset, length)