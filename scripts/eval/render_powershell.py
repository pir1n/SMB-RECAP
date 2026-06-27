#!/usr/bin/env python3
import argparse
from pathlib import Path

from common import ensure_dir, ps_quote, read_jsonl, windows_path


def local_path(local_dir, op, prefix):
    return str(Path(local_dir) / f"{prefix}_{op['op_id']:06d}.dat")


def local_path_for_id(local_dir, op_id, prefix):
    return str(Path(local_dir) / f"{prefix}_{int(op_id):06d}.dat")


def upload_local_path(local_dir, op):
    return local_path(local_dir, op, "upload")


def ps_for_op(op, drive, local_dir):
    path = windows_path(drive, op["path"])
    content = (op.get("content_sample") or f"scf-op-{op['op_id']}").replace("\n", " ")[:200].replace("'", "''")
    event = op["event"]

    if event == "create_directory":
        return f"New-Item -ItemType Directory -Path {ps_quote(path)} -Force | Out-Null"
    if event == "create_file":
        return f"New-Item -ItemType File -Path {ps_quote(path)} -Force | Out-Null"
    if event == "upload_file":
        return f"Copy-Item -Path {ps_quote(upload_local_path(local_dir, op))} -Destination {ps_quote(path)} -Force"
    if event == "write_file":
        return f"Add-Content -Path {ps_quote(path)} -Value {ps_quote(content)}"
    if event == "append_file":
        return f"Add-Content -Path {ps_quote(path)} -Value {ps_quote(content)}"
    if event == "download_file":
        return f"Copy-Item -Path {ps_quote(path)} -Destination {ps_quote(local_path(local_dir, op, 'download'))} -Force"
    if event == "read_file":
        return f"Get-Content -Path {ps_quote(path)} | Out-Null"
    if event == "overwrite_file":
        return f"Set-Content -Path {ps_quote(path)} -Value {ps_quote(content)}"
    if event == "rename_file":
        if op.get("operation_variant") == "move":
            return f"Move-Item -Path {ps_quote(path)} -Destination {ps_quote(windows_path(drive, op['target_path']))} -Force"
        return f"Rename-Item -Path {ps_quote(path)} -NewName {ps_quote(Path(op['target_path']).name)}"
    if event == "directory_listing":
        return f"Get-ChildItem -Path {ps_quote(path)} | Out-Null"
    if event == "delete_file":
        return f"Remove-Item -Path {ps_quote(path)} -Force"
    if event == "delete_directory":
        return f"Remove-Item -Path {ps_quote(path)} -Force"
    raise ValueError(f"unsupported event: {event}")


def render(plan, out_file, drive, stop_on_error):
    run_id = plan[0]["run_id"] if plan else "powershell_run"
    local_dir = str(Path(out_file).parent / "local" / run_id)
    lines = [
        "$ErrorActionPreference = 'Stop'",
        f"$RunId = {ps_quote(run_id)}",
        "$Client = 'powershell'",
        f"$LocalDir = {ps_quote(local_dir)}",
        f"$GroundTruthPath = Join-Path $PSScriptRoot '..\\..\\ground_truth\\{run_id}.jsonl'",
        "New-Item -ItemType Directory -Path (Split-Path $GroundTruthPath) -Force | Out-Null",
        "New-Item -ItemType Directory -Path $LocalDir -Force | Out-Null",
        "Remove-Item -Path $GroundTruthPath -Force -ErrorAction SilentlyContinue",
        "",
        "function New-ScfLocalFile {",
        "    param([string]$Path, [int]$Size)",
        "    New-Item -ItemType Directory -Path (Split-Path $Path) -Force | Out-Null",
        "    $bytes = New-Object byte[] $Size",
        "    for ($i = 0; $i -lt $Size; $i++) { $bytes[$i] = 65 + ($i % 26) }",
        "    [IO.File]::WriteAllBytes($Path, $bytes)",
        "}",
        "",
        "function Invoke-ScfOp {",
        "    param(",
        "        [int]$OpId,",
        "        [string]$Event,",
        "        [string]$PathValue,",
        "        [AllowNull()][string]$TargetPath,",
        "        [string]$Variant,",
        "        [string]$CommandText,",
        "        [scriptblock]$Body",
        "    )",
        "    $start = (Get-Date).ToUniversalTime().ToString('o')",
        "    $exitCode = 0",
        "    $errorText = $null",
        "    try {",
        "        & $Body",
        "    } catch {",
        "        $exitCode = 1",
        "        $errorText = $_.Exception.Message",
        "    }",
        "    $record = [ordered]@{",
        "        run_id = $RunId",
        "        op_id = $OpId",
        "        client = $Client",
        "        event = $Event",
        "        path = $PathValue",
        "        target_path = $TargetPath",
        "        status = $(if ($exitCode -eq 0) { 'success' } else { 'failed' })",
        "        start_time = $start",
        "        end_time = (Get-Date).ToUniversalTime().ToString('o')",
        "        command = $CommandText",
        "        exit_code = $exitCode",
        "        operation_variant = $Variant",
        "        error = $errorText",
        "    }",
        "    $record | ConvertTo-Json -Compress | Add-Content -Encoding UTF8 -Path $GroundTruthPath",
    ]
    if stop_on_error:
        lines.append("    if ($exitCode -ne 0) { throw \"SCF operation $OpId failed: $errorText\" }")
    lines.extend(["}", ""])

    for op in plan:
        if op["event"] == "upload_file":
            if op.get("local_source_op_id"):
                lines.extend([
                    f"Copy-Item -Path {ps_quote(local_path_for_id(local_dir, op['local_source_op_id'], 'download'))} -Destination {ps_quote(upload_local_path(local_dir, op))} -Force",
                    "",
                ])
            else:
                lines.extend([
                    f"New-ScfLocalFile -Path {ps_quote(upload_local_path(local_dir, op))} -Size {int(op.get('file_size') or 128)}",
                    "",
                ])

        command = ps_for_op(op, drive, local_dir)
        if op.get("log_ground_truth") is False:
            lines.extend([
                f"# setup op_id={op['op_id']} event={op['event']}",
                command,
                "",
            ])
            continue
        lines.extend([
            f"Invoke-ScfOp -OpId {op['op_id']} -Event {ps_quote(op['event'])} -PathValue {ps_quote(op['path'])} -TargetPath {ps_quote(op.get('target_path'))} -Variant {ps_quote(op.get('operation_variant') or '')} -CommandText {ps_quote(command)} -Body {{",
            f"    {command}",
            "}",
            "",
        ])

    ensure_dir(Path(out_file).parent)
    Path(out_file).write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Render a PowerShell workload that logs SCF ground truth JSONL.")
    parser.add_argument("plan_jsonl")
    parser.add_argument("--out-dir", default="data/eval/generated/workloads/powershell")
    parser.add_argument("--drive", default="Z")
    parser.add_argument("--continue-on-error", action="store_true")
    args = parser.parse_args()

    plan = read_jsonl(args.plan_jsonl)
    run_id = plan[0]["run_id"] if plan else Path(args.plan_jsonl).stem
    out_file = Path(args.out_dir) / f"{run_id}.ps1"
    render(plan, out_file, args.drive, stop_on_error=not args.continue_on_error)
    print(out_file)


if __name__ == "__main__":
    main()
