#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

from common import ensure_dir, read_jsonl, sh_quote, smb_path


def smb_arg(value):
    text = smb_path(value)
    if any(ch.isspace() for ch in text) or any(ch in text for ch in ['"', "'"]):
        return '"' + text.replace('"', '\\"') + '"'
    return text


def smbclient_command_for_op(op, local_dir):
    path = smb_path(op["path"])
    event = op["event"]
    if event == "create_directory":
        return f"mkdir {smb_arg(path)}"
    if event in {"create_file", "upload_file", "write_file", "append_file", "overwrite_file"}:
        local_file = upload_local_path(local_dir, op)
        return f"put {smb_arg(local_file)} {smb_arg(path)}"
    if event == "download_file":
        out_file = download_local_path(local_dir, op)
        return f"get {smb_arg(path)} {smb_arg(out_file)}"
    if event == "read_file":
        out_file = download_local_path(local_dir, op)
        return f"get {smb_arg(path)} {smb_arg(out_file)}"
    if event == "rename_file":
        return f"rename {smb_arg(path)} {smb_arg(op['target_path'])}"
    if event == "directory_listing":
        return f"ls {smb_arg(path)}"
    if event == "delete_file":
        return f"del {smb_arg(path)}"
    if event == "delete_directory":
        return f"rmdir {smb_arg(path)}"
    raise ValueError(f"unsupported event: {event}")


def upload_local_path(local_dir, op=None):
    return f"{local_dir}/u"


def download_local_path(local_dir, op=None):
    return f"{local_dir}/d"


def write_text_lf(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def render(plan, out_script, out_commands, server, share, auth_file, local_dir, stop_on_error, progress_every=1):
    run_id = plan[0]["run_id"] if plan else "smbclient_run"
    service = f"//{server}/{share}"

    batch_lines = []
    for op in plan:
        batch_lines.append(f"# op_id={op['op_id']} event={op['event']}")
        batch_lines.append(smbclient_command_for_op(op, local_dir))
    batch_lines.append("quit")

    shell_lines = [
        "#!/usr/bin/env bash",
        "set -u",
        "SCRIPT_DIR=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"",
        f"RUN_ID={sh_quote(run_id)}",
        "CLIENT=smbclient",
        f"TOTAL_OPS={len(plan)}",
        "OP_INDEX=0",
        f"PROGRESS_EVERY={max(1, int(progress_every))}",
        "GT_PATH=\"$SCRIPT_DIR/../../ground_truth/${RUN_ID}.jsonl\"",
        f"LOCAL_DIR={sh_quote(local_dir)}",
        f"SERVICE={sh_quote(service)}",
        f"AUTH_FILE={sh_quote(auth_file)}",
        "mkdir -p \"$(dirname \"$GT_PATH\")\" \"$LOCAL_DIR\"",
        "rm -f \"$LOCAL_DIR\"/upload_*.dat \"$LOCAL_DIR\"/download_*.dat \"$LOCAL_DIR\"/op_*.dat \"$LOCAL_DIR\"/out_*.dat \"$LOCAL_DIR\"/u \"$LOCAL_DIR\"/d",
        "rm -f \"$GT_PATH\"",
        "",
        "log_op() {",
        "  python3 - \"$GT_PATH\" <<'PY'",
        "import json, os, sys",
        "target = os.environ.get('SCF_TARGET_PATH') or None",
        "exit_code = int(os.environ.get('SCF_EXIT', '1'))",
        "record = {",
        "    'run_id': os.environ['SCF_RUN_ID'],",
        "    'op_id': int(os.environ['SCF_OP_ID']),",
        "    'client': os.environ['SCF_CLIENT'],",
        "    'event': os.environ['SCF_EVENT'],",
        "    'path': os.environ['SCF_PATH'],",
        "    'target_path': target,",
        "    'status': 'success' if exit_code == 0 else 'failed',",
        "    'start_time': os.environ['SCF_START'],",
        "    'end_time': os.environ['SCF_END'],",
        "    'command': os.environ['SCF_COMMAND'],",
        "    'exit_code': exit_code,",
        "    'operation_variant': os.environ.get('SCF_VARIANT') or '',",
        "}",
        "with open(sys.argv[1], 'a', encoding='utf-8') as fh:",
        "    fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + '\\n')",
        "PY",
        "}",
        "",
        "write_local_file() {",
        "  local op_id=\"$1\" size=\"$2\" seed=\"$3\"",
        "  python3 - \"$LOCAL_DIR/u\" \"$size\" \"$seed\" <<'PY'",
        "import os, sys",
        "path, size_text, seed = sys.argv[1], sys.argv[2], sys.argv[3]",
        "size = int(size_text)",
        "if size <= 0:",
        "    size = 4",
        "with open(path, 'wb') as fh:",
        "    fh.write(os.urandom(size))",
        "PY",
        "}",
        "",
        "run_op() {",
        "  local op_id=\"$1\" event=\"$2\" path_value=\"$3\" target_path=\"$4\" variant=\"$5\" command_text=\"$6\" file_size=\"$7\" local_source_op_id=\"${8:-}\"",
        "  OP_INDEX=$((OP_INDEX + 1))",
        "  if [[ \"$PROGRESS_EVERY\" -le 1 || \"$OP_INDEX\" -eq \"$TOTAL_OPS\" || $((OP_INDEX % PROGRESS_EVERY)) -eq 0 ]]; then",
        "    printf '[%s/%s] op_id=%s event=%s path=%s\\n' \"$OP_INDEX\" \"$TOTAL_OPS\" \"$op_id\" \"$event\" \"$path_value\"",
        "  fi",
        "  if [[ \"$event\" == \"upload_file\" && -n \"$local_source_op_id\" ]]; then",
        "    cp -f \"$LOCAL_DIR/d\" \"$LOCAL_DIR/u\"",
        "  else",
        "    case \"$event\" in create_file|upload_file|write_file|append_file|overwrite_file) write_local_file \"$op_id\" \"$file_size\" \"$RUN_ID:$op_id:\" ;; esac",
        "  fi",
        "  export SCF_RUN_ID=\"$RUN_ID\" SCF_CLIENT=\"$CLIENT\" SCF_OP_ID=\"$op_id\" SCF_EVENT=\"$event\" SCF_PATH=\"$path_value\" SCF_TARGET_PATH=\"$target_path\" SCF_VARIANT=\"$variant\" SCF_COMMAND=\"$command_text\"",
        "  export SCF_START=\"$(date -u +'%Y-%m-%dT%H:%M:%S.%6NZ')\"",
        "  if [[ -n \"$AUTH_FILE\" ]]; then",
        "    smbclient \"$SERVICE\" -A \"$AUTH_FILE\" -m SMB3 -c \"$command_text\"",
        "  else",
        "    smbclient \"$SERVICE\" -N -m SMB3 -c \"$command_text\"",
        "  fi",
        "  export SCF_EXIT=\"$?\"",
        "  export SCF_END=\"$(date -u +'%Y-%m-%dT%H:%M:%S.%6NZ')\"",
        "  log_op",
    ]
    if stop_on_error:
        shell_lines.append("  if [[ \"$SCF_EXIT\" -ne 0 ]]; then exit \"$SCF_EXIT\"; fi")
    shell_lines.extend(["}", ""])

    for op in plan:
        command = smbclient_command_for_op(op, local_dir)
        if op.get("log_ground_truth") is False:
            shell_lines.append(f"# setup op_id={op['op_id']} event={op['event']}")
            continue
        shell_lines.append(
            "run_op "
            f"{op['op_id']} "
            f"{sh_quote(op['event'])} "
            f"{sh_quote(op['path'])} "
            f"{sh_quote(op.get('target_path') or '')} "
            f"{sh_quote(op.get('operation_variant') or '')} "
            f"{sh_quote(command)} "
            f"{int(op.get('file_size') or 0)} "
            f"{sh_quote(str(op.get('local_source_op_id') or ''))}"
        )

    ensure_dir(Path(out_script).parent)
    write_text_lf(out_script, "\n".join(shell_lines) + "\n")
    try:
        os.chmod(out_script, 0o755)
    except OSError:
        pass

    ensure_dir(Path(out_commands).parent)
    write_text_lf(out_commands, "\n".join(batch_lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Render smbclient workloads and per-operation ground-truth wrapper.")
    parser.add_argument("plan_jsonl")
    parser.add_argument("--out-dir", default="data/eval/generated/workloads/smbclient")
    parser.add_argument("--server", default="SERVER")
    parser.add_argument("--share", default="SMB_EVAL")
    parser.add_argument("--auth-file", default="")
    parser.add_argument("--local-dir", default="/tmp/smbmount_scf_eval")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--progress-every", type=int, default=1, help="Print progress every N operations. Default prints every operation.")
    args = parser.parse_args()

    plan = read_jsonl(args.plan_jsonl)
    run_id = plan[0]["run_id"] if plan else Path(args.plan_jsonl).stem
    out_dir = Path(args.out_dir)
    render(
        plan=plan,
        out_script=out_dir / f"{run_id}.sh",
        out_commands=out_dir / f"{run_id}.smbclient",
        server=args.server,
        share=args.share,
        auth_file=args.auth_file,
        local_dir=args.local_dir,
        stop_on_error=not args.continue_on_error,
        progress_every=max(1, args.progress_every),
    )
    print(out_dir / f"{run_id}.sh")
    print(out_dir / f"{run_id}.smbclient")


if __name__ == "__main__":
    main()
