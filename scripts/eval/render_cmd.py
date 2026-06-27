#!/usr/bin/env python3
import argparse
from pathlib import Path

from common import cmd_quote, ensure_dir, read_jsonl, windows_path


def upload_local_path(local_dir, op=None):
    return str(Path(local_dir) / "u")


def download_local_path(local_dir, op=None):
    return str(Path(local_dir) / "d")


def cmd_for_op(op, drive, local_dir):
    path = windows_path(drive, op["path"])
    content = (op.get("content_sample") or f"scf-op-{op['op_id']}").replace("\n", " ")[:200]
    event = op["event"]

    if event == "create_directory":
        return f"mkdir {cmd_quote(path)}"
    if event == "create_file":
        return f"> {cmd_quote(path)} echo {content}"
    if event == "upload_file":
        return f"copy /Y /B {cmd_quote(upload_local_path(local_dir, op))} {cmd_quote(path)} > nul"
    if event == "write_file":
        return f">> {cmd_quote(path)} echo {content}"
    if event == "append_file":
        return f">> {cmd_quote(path)} echo {content}"
    if event == "download_file":
        return f"copy /Y /B {cmd_quote(path)} {cmd_quote(download_local_path(local_dir, op))} > nul"
    if event == "read_file":
        return f"more {cmd_quote(path)} > nul"
    if event == "overwrite_file":
        return f"> {cmd_quote(path)} echo {content}"
    if event == "rename_file":
        if op.get("operation_variant") == "move":
            return f"move /Y {cmd_quote(path)} {cmd_quote(windows_path(drive, op['target_path']))} > nul"
        target_name = Path(op["target_path"]).name
        return f"ren {cmd_quote(path)} {cmd_quote(target_name)}"
    if event == "directory_listing":
        return f"dir {cmd_quote(path)} > nul"
    if event == "delete_file":
        return f"del /f /q {cmd_quote(path)}"
    if event == "delete_directory":
        return f"rmdir {cmd_quote(path)}"
    raise ValueError(f"unsupported event: {event}")


def cmd_set_value(value):
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("^", "^^").replace("%", "%%")
    for char in ('&', '<', '>', '|', '"'):
        text = text.replace(char, f"^{char}")
    return text


def render(plan, out_file, drive, stop_on_error):
    run_id = plan[0]["run_id"] if plan else "cmd_run"
    local_dir = str(Path(out_file).parent / "local" / run_id)
    lines = [
        "@echo off",
        "setlocal EnableExtensions",
        f"set \"SCF_RUN_ID={run_id}\"",
        "set \"SCF_CLIENT=cmd\"",
        "set \"SCF_SCRIPT_DIR=%~dp0\"",
        f"set \"SCF_LOCAL_DIR={local_dir}\"",
        f"set \"SCF_GT=%SCF_SCRIPT_DIR%..\\..\\ground_truth\\{run_id}.jsonl\"",
        "if not exist \"%SCF_SCRIPT_DIR%..\\..\\ground_truth\" mkdir \"%SCF_SCRIPT_DIR%..\\..\\ground_truth\"",
        "if not exist \"%SCF_LOCAL_DIR%\" mkdir \"%SCF_LOCAL_DIR%\"",
        "del /f /q \"%SCF_LOCAL_DIR%\\upload_*.dat\" > nul 2> nul",
        "del /f /q \"%SCF_LOCAL_DIR%\\download_*.dat\" > nul 2> nul",
        "del /f /q \"%SCF_LOCAL_DIR%\\op_*.dat\" > nul 2> nul",
        "del /f /q \"%SCF_LOCAL_DIR%\\out_*.dat\" > nul 2> nul",
        "del /f /q \"%SCF_LOCAL_DIR%\\u\" > nul 2> nul",
        "del /f /q \"%SCF_LOCAL_DIR%\\d\" > nul 2> nul",
        "if exist \"%SCF_GT%\" del \"%SCF_GT%\"",
        "",
    ]

    for op in plan:
        if op["event"] == "upload_file":
            if op.get("local_source_op_id"):
                source = download_local_path(local_dir, op)
                target = upload_local_path(local_dir, op)
                lines.extend([
                    f"copy /Y /B {cmd_quote(source)} {cmd_quote(target)} > nul",
                    "",
                ])
            else:
                lines.extend([
                    f"set \"SCF_LOCAL_FILE={upload_local_path(local_dir, op)}\"",
                    f"set \"SCF_LOCAL_SIZE={int(op.get('file_size') or 4)}\"",
                    "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$p=$env:SCF_LOCAL_FILE; $n=[int]$env:SCF_LOCAL_SIZE; $d=Split-Path $p; New-Item -ItemType Directory -Path $d -Force | Out-Null; $b=New-Object byte[] $n; for($i=0; $i -lt $n; $i++){ $b[$i]=65+($i %% 26) }; [IO.File]::WriteAllBytes($p,$b)\"",
                    "",
                ])

        command = cmd_for_op(op, drive, local_dir)
        if op.get("log_ground_truth") is False:
            lines.extend([
                f"rem setup op_id={op['op_id']} event={op['event']}",
                command,
                "set \"SCF_EXIT=%ERRORLEVEL%\"",
            ])
            if stop_on_error:
                lines.append("if not \"%SCF_EXIT%\"==\"0\" exit /b %SCF_EXIT%")
            lines.append("")
            continue
        lines.extend([
            f"rem op_id={op['op_id']} event={op['event']}",
            f"set \"SCF_OP_ID={op['op_id']}\"",
            f"set \"SCF_EVENT={op['event']}\"",
            f"set \"SCF_PATH={op['path']}\"",
            f"set \"SCF_TARGET_PATH={op.get('target_path') or ''}\"",
            f"set \"SCF_VARIANT={op.get('operation_variant') or ''}\"",
            f"set \"SCF_COMMAND={cmd_set_value(command)}\"",
            "for /f \"delims=\" %%I in ('powershell -NoProfile -Command \"[DateTime]::UtcNow.ToString('o')\"') do set \"SCF_START=%%I\"",
            command,
            "set \"SCF_EXIT=%ERRORLEVEL%\"",
            "call :log_op",
        ])
        if stop_on_error:
            lines.append("if not \"%SCF_EXIT%\"==\"0\" exit /b %SCF_EXIT%")
        lines.append("")

    lines.extend([
        "exit /b 0",
        "",
        ":log_op",
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$target=$env:SCF_TARGET_PATH; if ($target -eq '') { $target=$null }; $status=if ([int]$env:SCF_EXIT -eq 0) { 'success' } else { 'failed' }; $record=[ordered]@{run_id=$env:SCF_RUN_ID; op_id=[int]$env:SCF_OP_ID; client=$env:SCF_CLIENT; event=$env:SCF_EVENT; path=$env:SCF_PATH; target_path=$target; status=$status; start_time=$env:SCF_START; end_time=(Get-Date).ToUniversalTime().ToString('o'); command=$env:SCF_COMMAND; exit_code=[int]$env:SCF_EXIT; operation_variant=$env:SCF_VARIANT}; $record | ConvertTo-Json -Compress | Add-Content -Encoding UTF8 -Path $env:SCF_GT\"",
        "exit /b 0",
        "",
    ])

    ensure_dir(Path(out_file).parent)
    Path(out_file).write_text("\r\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Render a CMD workload that logs SCF ground truth JSONL.")
    parser.add_argument("plan_jsonl")
    parser.add_argument("--out-dir", default="data/eval/generated/workloads/cmd")
    parser.add_argument("--drive", default="Z")
    parser.add_argument("--continue-on-error", action="store_true")
    args = parser.parse_args()

    plan = read_jsonl(args.plan_jsonl)
    run_id = plan[0]["run_id"] if plan else Path(args.plan_jsonl).stem
    out_file = Path(args.out_dir) / f"{run_id}.cmd"
    render(plan, out_file, args.drive, stop_on_error=not args.continue_on_error)
    print(out_file)


if __name__ == "__main__":
    main()
