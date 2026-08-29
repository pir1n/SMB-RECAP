#!/usr/bin/env python3
"""Convert shell-ground-truth-v1 CMD history to canonical SMB action ground truth."""

import argparse
import json
import ntpath
import re
from pathlib import Path, PureWindowsPath


def clean(value):
    return str(value or "").strip().strip('"')


def is_share(value):
    return clean(value).casefold().startswith("z:")


def share_path(value):
    value = clean(value).replace("/", "\\")
    value = re.sub(r"^[zZ]:\\*", "", value)
    normalized = ntpath.normpath(value) if value else ""
    return "" if normalized == "." else normalized.strip("\\")


def resolve(value, cwd):
    value = clean(value)
    if re.match(r"^[A-Za-z]:", value):
        return ntpath.normpath(value)
    return ntpath.normpath(ntpath.join(cwd, value))


def command_words(command):
    return re.findall(r'"[^"]*"|\S+', command)


def make(row, op_id, event, path, target=None, **extra):
    item = {
        "run_id": "User_action",
        "op_id": op_id,
        "client": "cmd",
        "event": event,
        "path": share_path(path),
        "target_path": share_path(target) if target else None,
        "start_time": row["started_at"],
        "end_time": row["ended_at"],
        "status": "success",
        "command": row["command"],
        "source_session_id": row.get("session_id"),
        "source_sequence": row.get("sequence"),
        "source_exit_code": row.get("exit_code"),
    }
    item.update(extra)
    return item


def classify(row, index):
    command = clean(row.get("command"))
    low = command.casefold()
    cwd = clean(row.get("cwd_before"))
    cwd_on_share = is_share(cwd)
    op_id = f"shell-{index:03d}"

    # CMD performs output redirection before launching TYPE. The command fails,
    # but the capture session confirmed that the empty share file was created.
    failed_redirection_side_effect = (
        low == "type null > rc4.py" and cwd_on_share
    )
    if not row.get("success", False) and not failed_redirection_side_effect:
        return [], "failed_or_interrupted"

    if failed_redirection_side_effect:
        return [make(row, op_id, "create_file", resolve("rc4.py", cwd),
                     side_effect_despite_command_failure=True)], None

    if not cwd_on_share and not ("z:\\" in low):
        return [], "local_only"

    if cwd_on_share and (low == "dir" or low.startswith("dir ")):
        return [make(row, op_id, "directory_listing", cwd)], None
    if cwd_on_share and low.startswith("tree"):
        return [make(row, op_id, "directory_listing", cwd,
                     operation_variant="recursive_tree")], None
    if cwd_on_share and low.startswith(("type ", "more ")):
        operand = command.split(maxsplit=1)[1]
        return [make(row, op_id, "read_file", resolve(operand, cwd))], None
    if cwd_on_share and low.startswith(("mkdir ", "md ")):
        operand = command.split(maxsplit=1)[1]
        return [make(row, op_id, "create_directory", resolve(operand, cwd))], None
    if cwd_on_share and low.startswith("rmdir "):
        operand = re.sub(r"(?i)^rmdir\s+(?:/[sq]\s+)*", "", command)
        return [make(row, op_id, "delete_directory", resolve(operand, cwd))], None
    if cwd_on_share and low.startswith(("del ", "erase ")):
        operand = re.sub(r"(?i)^(?:del|erase)\s+(?:/[fq]\s+)*", "", command)
        return [make(row, op_id, "delete_file", resolve(operand, cwd))], None
    if cwd_on_share and low.startswith(("ren ", "rename ")):
        words = command_words(command)
        if len(words) >= 3:
            source = resolve(words[1], cwd)
            target = resolve(words[2], ntpath.dirname(source))
            return [make(row, op_id, "rename_file", source, target)], None

    if cwd_on_share and low.startswith("echo "):
        append = re.search(r">>\s*(.+)$", command)
        overwrite = re.search(r"(?<!>)>\s*(.+)$", command)
        if append:
            return [make(row, op_id, "append_file", resolve(append.group(1), cwd))], None
        if overwrite:
            target = resolve(overwrite.group(1), cwd)
            # The caller resolves create versus overwrite from the preceding
            # command state. CREATE response semantics remain the detector's
            # independent source of truth.
            return [make(row, op_id, "create_file", target,
                         operation_variant="shell_redirect_replace")], None

    if low.startswith(("copy ", "move ")):
        words = [word.strip('"') for word in command_words(command)]
        verb = words.pop(0).casefold()
        operands = [word for word in words if not re.fullmatch(r"/[a-z]+", word, re.I)]
        if len(operands) < 2:
            return [], "unparsed_copy_move"
        source_raw, target_raw = operands[0], operands[1]
        source = resolve(source_raw, cwd)
        target = resolve(target_raw, cwd)
        source_share, target_share = is_share(source), is_share(target)

        if source_share and not target_share:
            events = [make(row, op_id, "download_file", source)]
            if verb == "move":
                events.append(make(row, op_id + "-delete", "delete_file", source,
                                   operation_variant="cross_volume_move_cleanup"))
            return events, None
        if not source_share and target_share:
            # A destination without a suffix is an existing directory in these
            # recorded commands; COPY then preserves the source basename.
            if not PureWindowsPath(target).suffix:
                target = ntpath.join(target, PureWindowsPath(source).name)
            return [make(row, op_id, "upload_file", target)], None
        if source_share and target_share:
            if target_raw.endswith(("\\", "/")) or not PureWindowsPath(target).suffix:
                target = ntpath.join(target, PureWindowsPath(source).name)
            event = "rename_file" if verb == "move" else "create_file"
            return [make(row, op_id, event, source if verb == "move" else target,
                         target if verb == "move" else None)], None

    return [], "non_scoreable"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    source_rows = [json.loads(line) for line in args.source.read_text(
        encoding="utf-8-sig").splitlines() if line.strip()]
    actions, audit = [], []
    known_existing_paths = set()
    for index, row in enumerate(source_rows, 1):
        classified, reason = classify(row, index)

        # Maintain only state proven by earlier recorded commands. This avoids
        # filename-specific labels and correctly handles a failed command whose
        # output redirection nevertheless created a file.
        for item in classified:
            path_key = share_path(item.get("path")).casefold()
            target_key = share_path(item.get("target_path")).casefold()
            if item.get("operation_variant") == "shell_redirect_replace":
                item["event"] = (
                    "overwrite_file" if path_key in known_existing_paths
                    else "create_file"
                )
            event = item["event"]
            if event in {
                "read_file", "append_file", "create_file", "overwrite_file",
                "upload_file", "write_file",
            } and path_key:
                known_existing_paths.add(path_key)
            elif event == "delete_file" and path_key:
                known_existing_paths.discard(path_key)
            elif event == "rename_file":
                if path_key:
                    known_existing_paths.discard(path_key)
                if target_key:
                    known_existing_paths.add(target_key)

        actions.extend(classified)
        audit.append({
            "source_index": index,
            "command": row.get("command"),
            "classification": [item["event"] for item in classified],
            "paths": [item["path"] for item in classified],
            "excluded_reason": reason,
        })

    output = args.out_dir / "canonical_ground_truth.jsonl"
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        for row in actions:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    summary = {
        "source_rows": len(source_rows),
        "canonical_actions": len(actions),
        "by_event": {},
        "audit": audit,
    }
    for row in actions:
        summary["by_event"][row["event"]] = summary["by_event"].get(row["event"], 0) + 1
    (args.out_dir / "ground_truth_conversion_audit.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if key != "audit"}))


if __name__ == "__main__":
    main()
