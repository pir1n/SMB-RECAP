param(
    [int]$CountPerOperation = 1000,
    [string]$Server = "192.168.106.131",
    [string]$Share = "SMB_EVAL",
    [string]$User = "SMB1_Sakana",
    [string]$Password = "abcABC123!@#",
    [string]$Drive = "Z"
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    throw "This script must be run from an elevated Administrator PowerShell because pktmon requires elevation."
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Python venv not found: $Python"
}

New-Item -ItemType Directory -Force -Path `
    "data\eval\pcaps", `
    "data\eval\generated", `
    "outputs\eval\timelines", `
    "outputs\eval\metrics" | Out-Null

$driveRoot = "${Drive}:\"
$service = "\\$Server\$Share"

Write-Host "Mounting $driveRoot -> $service"
cmd /c "net use $Drive`: /delete /y" | Out-Null
cmd /c "net use $Drive`: $service /user:$User `"$Password`""

function Invoke-CommandChecked {
    param(
        [string]$Exe,
        [string[]]$Args
    )
    Write-Host ">> $Exe $($Args -join ' ')"
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($Args -join ' ')"
    }
}

function Generate-Workload {
    param(
        [string]$Client,
        [string]$RunId
    )
    Invoke-CommandChecked $Python @(
        "scripts\eval\generate_operation_scale.py",
        "--client", $Client,
        "--count-per-operation", "$CountPerOperation",
        "--run-id", $RunId,
        "--out-dir", "data\eval\generated",
        "--render",
        "--drive", $Drive
    )
}

function Start-SmbCapture {
    param([string]$RunId)
    Write-Host "Starting SMB capture for $RunId"
    pktmon stop | Out-Null
    pktmon filter remove | Out-Null
    pktmon filter add -p 445 | Out-Null
    Remove-Item -Force -ErrorAction SilentlyContinue "PktMon.etl"
    pktmon start --capture --pkt-size 0
}

function Stop-SmbCapture {
    param([string]$RunId)
    Write-Host "Stopping SMB capture for $RunId"
    pktmon stop
    $pcap = "data\eval\pcaps\$RunId.pcapng"
    Remove-Item -Force -ErrorAction SilentlyContinue $pcap
    pktmon pcapng PktMon.etl -o $pcap
    if (-not (Test-Path $pcap)) {
        throw "PCAPNG was not created: $pcap"
    }
}

function Run-Workload {
    param(
        [string]$Client,
        [string]$RunId
    )
    if ($Client -eq "cmd") {
        Invoke-CommandChecked "cmd.exe" @("/c", "data\eval\generated\workloads\cmd\$RunId.cmd")
        return
    }
    if ($Client -eq "powershell") {
        Invoke-CommandChecked "powershell.exe" @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "data\eval\generated\workloads\powershell\$RunId.ps1"
        )
        return
    }
    throw "Unsupported client: $Client"
}

function Build-TimelineAndScore {
    param(
        [string]$Client,
        [string]$RunId
    )
    $pcap = "data\eval\pcaps\$RunId.pcapng"
    $rules = "rules\$($Client)_rules.json"
    $timeline = "outputs\eval\timelines\$($RunId)_timeline.json"
    $gt = "data\eval\generated\ground_truth\$RunId.jsonl"
    $metrics = "outputs\eval\metrics\$RunId"

    if (-not (Test-Path $gt)) {
        throw "Ground truth was not created: $gt"
    }

    Invoke-CommandChecked $Python @(
        "-m", "smbmount", "scf",
        $pcap,
        $rules,
        $timeline
    )

    Invoke-CommandChecked $Python @(
        "scripts\eval\score_timeline.py",
        "--ground-truth", $gt,
        "--timeline", $timeline,
        "--out-dir", $metrics
    )
}

function Invoke-ClientRun {
    param(
        [string]$Client,
        [string]$RunId
    )

    Write-Host ""
    Write-Host "===== $Client / $RunId ====="
    Generate-Workload -Client $Client -RunId $RunId

    try {
        Start-SmbCapture -RunId $RunId
        Run-Workload -Client $Client -RunId $RunId
    }
    finally {
        Stop-SmbCapture -RunId $RunId
    }

    Build-TimelineAndScore -Client $Client -RunId $RunId
}

Invoke-ClientRun -Client "cmd" -RunId "cmd_operation_scale_1000"
Invoke-ClientRun -Client "powershell" -RunId "powershell_operation_scale_1000"

Write-Host ""
Write-Host "Done."
Write-Host "CMD metrics: outputs\eval\metrics\cmd_operation_scale_1000\metrics.json"
Write-Host "PowerShell metrics: outputs\eval\metrics\powershell_operation_scale_1000\metrics.json"
