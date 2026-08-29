#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from smbmount.shared.evaluation import cmd_quote, ensure_dir, ps_quote, read_jsonl, windows_path


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
    for char in ("&", "<", ">", "|", '"'):
        text = text.replace(char, f"^{char}")
    return text


def ps_value(value):
    return "$null" if value is None else ps_quote(value)


def should_show_progress(index, total, progress_every):
    if progress_every <= 1:
        return True
    return index == total or index % progress_every == 0


def fast_sidecar_path(out_file):
    path = Path(out_file)
    return path.with_name(f"{path.stem}_fast.ps1")


def render_fast(plan, out_file, drive, stop_on_error, progress_every):
    run_id = plan[0]["run_id"] if plan else "cmd_run"
    local_dir = str(Path(out_file).parent / "local" / run_id)
    ps_file = fast_sidecar_path(out_file)

    launcher_lines = [
        "@echo off",
        "setlocal EnableExtensions",
        f"powershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0{ps_file.name}\" %*",
        "exit /b %ERRORLEVEL%",
        "",
    ]

    lines = [
        "$ErrorActionPreference = 'Stop'",
        f"$RunId = {ps_quote(run_id)}",
        "$Client = 'cmd'",
        f"$TotalOps = {len(plan)}",
        "$OpIndex = 0",
        f"$LocalDir = {ps_quote(local_dir)}",
        f"$GroundTruthPath = Join-Path $PSScriptRoot '..\\..\\ground_truth\\{run_id}.jsonl'",
        "New-Item -ItemType Directory -Path (Split-Path $GroundTruthPath) -Force | Out-Null",
        "New-Item -ItemType Directory -Path $LocalDir -Force | Out-Null",
        "foreach ($Pattern in @('upload_*.dat', 'download_*.dat', 'op_*.dat', 'out_*.dat', 'u', 'd')) {",
        "    Remove-Item -Path (Join-Path $LocalDir $Pattern) -Force -ErrorAction SilentlyContinue",
        "}",
        "Remove-Item -Path $GroundTruthPath -Force -ErrorAction SilentlyContinue",
        "$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)",
        "$GroundTruthWriter = New-Object System.IO.StreamWriter($GroundTruthPath, $false, $Utf8NoBom)",
        "",
        "function New-ScfLocalFile {",
        "    param([string]$Path, [int]$Size)",
        "    New-Item -ItemType Directory -Path (Split-Path $Path) -Force | Out-Null",
        "    if ($Size -le 0) { $Size = 4 }",
        "    $bytes = New-Object byte[] $Size",
        "    for ($i = 0; $i -lt $Size; $i++) { $bytes[$i] = 65 + ($i % 26) }",
        "    [IO.File]::WriteAllBytes($Path, $bytes)",
        "}",
        "",
        "function Write-ScfRecord {",
        "    param($Record)",
        "    $GroundTruthWriter.WriteLine(($Record | ConvertTo-Json -Compress))",
        "}",
        "",
        "function Invoke-CmdScfOp {",
        "    param(",
        "        [int]$OpId,",
        "        [string]$Event,",
        "        [string]$PathValue,",
        "        [AllowNull()][string]$TargetPath,",
        "        [string]$Variant,",
        "        [string]$CommandText,",
        "        [bool]$LogGroundTruth",
        "    )",
        "    $start = (Get-Date).ToUniversalTime().ToString('o')",
        "    & cmd.exe /d /s /c $CommandText",
        "    $exitCode = $LASTEXITCODE",
        "    if ($LogGroundTruth) {",
        "        $record = [ordered]@{",
        "            run_id = $RunId",
        "            op_id = $OpId",
        "            client = $Client",
        "            event = $Event",
        "            path = $PathValue",
        "            target_path = $TargetPath",
        "            status = $(if ($exitCode -eq 0) { 'success' } else { 'failed' })",
        "            start_time = $start",
        "            end_time = (Get-Date).ToUniversalTime().ToString('o')",
        "            command = $CommandText",
        "            exit_code = $exitCode",
        "            operation_variant = $Variant",
        "        }",
        "        Write-ScfRecord $record",
        "    }",
    ]
    if stop_on_error:
        lines.append("    if ($exitCode -ne 0) { throw \"SCF operation $OpId failed with exit code $exitCode\" }")
    lines.extend(["}", "", "try {"])

    for index, op in enumerate(plan, start=1):
        if op["event"] == "upload_file":
            if op.get("local_source_op_id"):
                lines.append(
                    f"    Copy-Item -Path {ps_quote(download_local_path(local_dir, op))} -Destination {ps_quote(upload_local_path(local_dir, op))} -Force"
                )
            else:
                lines.append(
                    f"    New-ScfLocalFile -Path {ps_quote(upload_local_path(local_dir, op))} -Size {int(op.get('file_size') or 4)}"
                )

        command = cmd_for_op(op, drive, local_dir)
        lines.append(f"    # op_id={op['op_id']} event={op['event']}")
        lines.append("    $OpIndex += 1")
        if should_show_progress(index, len(plan), progress_every):
            lines.append(
                f"    Write-Host (\"[{{0}}/{{1}}] op_id={op['op_id']} event={op['event']} path={op['path']}\" -f $OpIndex, $TotalOps)"
            )
        lines.append(
            "    Invoke-CmdScfOp "
            f"-OpId {op['op_id']} "
            f"-Event {ps_quote(op['event'])} "
            f"-PathValue {ps_quote(op['path'])} "
            f"-TargetPath {ps_value(op.get('target_path'))} "
            f"-Variant {ps_quote(op.get('operation_variant') or '')} "
            f"-CommandText {ps_quote(command)} "
            f"-LogGroundTruth ${str(op.get('log_ground_truth') is not False).lower()}"
        )
        lines.append("")

    lines.extend([
        "} finally {",
        "    $GroundTruthWriter.Flush()",
        "    $GroundTruthWriter.Dispose()",
        "}",
        "",
    ])

    ensure_dir(Path(out_file).parent)
    Path(out_file).write_text("\r\n".join(launcher_lines), encoding="utf-8")
    Path(ps_file).write_text("\n".join(lines), encoding="utf-8")


def render(plan, out_file, drive, stop_on_error, fast_mode=False, progress_every=1):
    if fast_mode:
        render_fast(plan, out_file, drive, stop_on_error, progress_every)
        return

    run_id = plan[0]["run_id"] if plan else "cmd_run"
    local_dir = str(Path(out_file).parent / "local" / run_id)
    lines = [
        "@echo off",
        "setlocal EnableExtensions",
        f"set \"SCF_RUN_ID={run_id}\"",
        "set \"SCF_CLIENT=cmd\"",
        f"set \"SCF_TOTAL_OPS={len(plan)}\"",
        "set \"SCF_OP_INDEX=0\"",
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

    for index, op in enumerate(plan, start=1):
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
        progress_line = None
        if should_show_progress(index, len(plan), progress_every):
            progress_line = (
                f"echo [%SCF_OP_INDEX%/%SCF_TOTAL_OPS%] "
                f"op_id={op['op_id']} event={op['event']} path={cmd_set_value(op['path'])}"
            )
        if op.get("log_ground_truth") is False:
            lines.extend([
                f"rem setup op_id={op['op_id']} event={op['event']}",
                "set /a SCF_OP_INDEX+=1",
            ])
            if progress_line:
                lines.append(progress_line)
            lines.extend([
                command,
                "set \"SCF_EXIT=%ERRORLEVEL%\"",
            ])
            if stop_on_error:
                lines.append("if not \"%SCF_EXIT%\"==\"0\" exit /b %SCF_EXIT%")
            lines.append("")
            continue
        lines.extend([
            f"rem op_id={op['op_id']} event={op['event']}",
            "set /a SCF_OP_INDEX+=1",
        ])
        if progress_line:
            lines.append(progress_line)
        lines.extend([
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
    parser.add_argument("--fast-workload", action="store_true", help="Generate a CMD launcher plus persistent PowerShell logger for faster runs.")
    parser.add_argument("--progress-every", type=int, default=1, help="Print progress every N operations. Default prints every operation.")
    args = parser.parse_args()

    plan = read_jsonl(args.plan_jsonl)
    run_id = plan[0]["run_id"] if plan else Path(args.plan_jsonl).stem
    out_file = Path(args.out_dir) / f"{run_id}.cmd"
    render(
        plan,
        out_file,
        args.drive,
        stop_on_error=not args.continue_on_error,
        fast_mode=args.fast_workload,
        progress_every=max(1, args.progress_every),
    )
    print(out_file)
    if args.fast_workload:
        print(fast_sidecar_path(out_file))


if __name__ == "__main__":
    main()
