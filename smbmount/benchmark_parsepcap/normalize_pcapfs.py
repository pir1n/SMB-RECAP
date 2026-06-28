import hashlib
import json
import os
import re
from pathlib import Path
from collections import defaultdict


VERSION_SUFFIX_RE = re.compile(r"^(?P<base>.+)@(?P<version>\d+)$")


def norm_path(path):
    if not path:
        return "unknown"
    return str(path).replace("/", "\\").strip("\\")


def md5_file(path):
    h = hashlib.md5()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


def parse_versioned_name(relative_path):
    """
    Input:
      share/a.txt
      share/a.txt@0
      share/a.txt@1

    Output:
      ("share/a.txt", None)
      ("share/a.txt", 0)
      ("share/a.txt", 1)
    """
    relative_path = norm_path(relative_path)

    parent = os.path.dirname(relative_path)
    name = os.path.basename(relative_path)

    match = VERSION_SUFFIX_RE.match(name)

    if not match:
        return relative_path, None

    base_name = match.group("base")
    version = int(match.group("version"))

    if parent:
        base_path = os.path.join(parent, base_name)
    else:
        base_path = base_name

    return norm_path(base_path), version


def strip_to_scenario(path, scenario_dir=None):
    path = norm_path(path)

    if not scenario_dir:
        return path

    parts = [p for p in path.split("\\") if p]

    if scenario_dir in parts:
        idx = parts.index(scenario_dir)
        return "\\".join(parts[idx:])

    return None


def is_noise_file(base_path):
    lower = norm_path(base_path).lower()

    return (
        lower.endswith(".meta")
        or "smb.control.meta" in lower
        or lower.endswith("desktop.ini")
        or lower.endswith("autorun.inf")
    )


def normalize_pcapfs(mount_root, scenario_dir=None):
    """
    Convert filesystem view của pcapFS mount về common benchmark schema.

    pcapFS không có semantic event, nên:
    - op = None
    - version_kind = 'content'
    - events = []
    """
    mount_root = Path(mount_root)
    grouped = defaultdict(list)

    for root, dirs, files in os.walk(mount_root):
        for filename in files:
            abs_path = Path(root) / filename

            try:
                rel_path = abs_path.relative_to(mount_root)
            except ValueError:
                continue

            rel_path_text = str(rel_path)

            base_path, version = parse_versioned_name(rel_path_text)

            if is_noise_file(base_path):
                continue

            base_path = strip_to_scenario(
                base_path,
                scenario_dir=scenario_dir,
            )

            if base_path is None:
                continue

            try:
                size = abs_path.stat().st_size
                file_md5 = md5_file(abs_path)
            except Exception:
                continue

            grouped[base_path].append({
                "version": version,
                "size": size,
                "md5": file_md5,
                "source_path": norm_path(rel_path_text),
            })

    normalized_files = []

    for path, versions in grouped.items():
        explicit_versions = [v for v in versions if v["version"] is not None]
        plain_versions = [v for v in versions if v["version"] is None]

        final_versions = []

        if explicit_versions:
            for idx, v in enumerate(sorted(explicit_versions, key=lambda x: x["version"])):
                final_versions.append({
                    "version": idx,
                    "op": None,
                    "version_kind": "content",
                    "size": v["size"],
                    "md5": v["md5"],
                    "metadata": {
                        "source_path": v["source_path"],
                        "pcapfs_version": v["version"],
                    },
                })
        else:
            for idx, v in enumerate(plain_versions):
                final_versions.append({
                    "version": idx,
                    "op": None,
                    "version_kind": "content",
                    "size": v["size"],
                    "md5": v["md5"],
                    "metadata": {
                        "source_path": v["source_path"],
                    },
                })

        normalized_files.append({
            "path": norm_path(path),
            "is_dir": False,
            "deleted": False,
            "object_type": "file",
            "versions": final_versions,
            "events": [],
        })

    normalized_files.sort(key=lambda x: x["path"])

    return {
        "tool": "pcapFS",
        "files": normalized_files,
        "events": [],
    }


def write_normalized_pcapfs(mount_root, output_json_path, scenario_dir=None):
    result = normalize_pcapfs(
        mount_root,
        scenario_dir=scenario_dir,
    )

    output_path = Path(output_json_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    return result