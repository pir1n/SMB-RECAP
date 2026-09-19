def insert_path(tree, path):
    if not path:
        return

    parts = path.strip("\\").split("\\")

    node = tree
    for part in parts:
        if part not in node:
            node[part] = {}
        node = node[part]


def build_tree(file_table):
    tree = {}

    for f in file_table.files.values():
        insert_path(tree, f.path)

    return tree