from typing import Dict
from smbmount.reconstruct.metadata import FileMetadata
from smbmount.reconstruct.versioning import VersionManager


class FileObject:
    def __init__(self, file_id: str):
        self.file_id = file_id
        self.path = None
        self.metadata = FileMetadata()
        self.versions = VersionManager()

    def update_metadata(self, pkt):
        self.metadata.update_from_packet(pkt)

    def write(self, offset, length, timestamp):
        self.versions.add_write(offset, length, timestamp)


class FileTable:
    def __init__(self):
        self.files: Dict[str, FileObject] = {}

    def get_or_create(self, file_id: str) -> FileObject:
        if file_id not in self.files:
            self.files[file_id] = FileObject(file_id)
        return self.files[file_id]