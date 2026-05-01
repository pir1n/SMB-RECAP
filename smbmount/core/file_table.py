from typing import Dict


class FileObject:
    def __init__(self, file_id: str):
        self.file_id = file_id
        self.path = None
        self.chunks = []
        self.size = 0

    def add_chunk(self, offset: int, length: int):
        self.chunks.append((offset, length))
        if offset is not None and length is not None:
            self.size = max(self.size, offset + length)


class FileTable:
    def __init__(self):
        self.files: Dict[str, FileObject] = {}

    def get_or_create(self, file_id: str) -> FileObject:
        if file_id not in self.files:
            self.files[file_id] = FileObject(file_id)
        return self.files[file_id]