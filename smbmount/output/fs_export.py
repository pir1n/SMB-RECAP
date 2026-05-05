def export_files(file_table, tree):
    files = []

    for f in file_table.files.values():
        versions = []

        for v in f.versions.versions:
            versions.append({
                "version": v.version_id,
                "size": v.size,
                "modified": v.modified,
                "chunks": v.chunks
            })

        files.append({
            "file_id": f.file_id,
            "path": f.path,
            "metadata": {
                "created": f.metadata.created,
                "modified": f.metadata.modified,
                "accessed": f.metadata.accessed,
                "size": f.metadata.size,
            },
            "versions": versions
        })

    return {
        "files": files,
        "tree": tree
    }