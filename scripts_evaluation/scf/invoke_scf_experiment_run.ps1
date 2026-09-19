param(
  [Parameter(Mandatory=$true)][ValidateSet("cmd", "powershell", "smbclient")][string]$Client,
  [Parameter(Mandatory=$true)][int]$CountPerOperation,
  [Parameter(Mandatory=$true)][string]$RunId,
  [string]$Campaign = "exp_2026_07_supplement",
  [string]$ServerIp = "192.168.106.131",
  [string]$Interface = "8",
  [string]$Drive = "Z",
  [string]$Share = "SMB_EVAL",
  [string]$SmbAuthFile = "/tmp/smb_eval.auth",
  [string]$SmbLocalDir = "/tmp/smbmount_scf_eval",
  [double]$TimeBefore = 1.0,
  [double]$TimeAfter = 3.0,
  [int]$ProgressEvery = 100
)

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"

New-Item -ItemType Directory -Force `
  "outputs\$Campaign\pcaps", `
  "outputs\$Campaign\timelines", `
  "outputs\$Campaign\metrics", `
  "outputs\$Campaign\logs" | Out-Null

$generateArgs = @(
  "scripts\data_generators\scf\generate_operation_scale.py",
  "--client", $Client,
  "--count-per-operation", "$CountPerOperation",
  "--run-id", $RunId,
  "--render",
  "--progress-every", "$ProgressEvery"
)

if ($Client -in @("cmd", "powershell")) {
  $generateArgs += @("--drive", $Drive, "--fast-workload")
} else {
  $generateArgs += @(
    "--server", $ServerIp,
    "--share", $Share,
    "--auth-file", $SmbAuthFile,
    "--local-dir", $SmbLocalDir
  )
}

& ".\.venv\Scripts\python.exe" @generateArgs

$pcap = "outputs\$Campaign\pcaps\$RunId.pcapng"
$rawPcap = "outputs\$Campaign\pcaps\${RunId}.raw.pcapng"
$timeline = "outputs\$Campaign\timelines\${RunId}_timeline.json"
$metricDir = "outputs\$Campaign\metrics\$RunId"
$tsharkErr = "outputs\$Campaign\logs\$RunId.tshark.err.txt"
$runtimeJson = "outputs\$Campaign\logs\$RunId.runtime.json"
$workloadLog = "outputs\$Campaign\logs\$RunId.workload.log"

Remove-Item $pcap, $rawPcap, $timeline, $tsharkErr, $workloadLog -ErrorAction SilentlyContinue
Remove-Item $metricDir -Recurse -Force -ErrorAction SilentlyContinue

$argString = ('-i {0} -f "host {1} and tcp port 445" -w "{2}"' -f $Interface, $ServerIp, $rawPcap)
$tshark = Start-Process -FilePath "tshark" -PassThru -WindowStyle Hidden -RedirectStandardError $tsharkErr -ArgumentList $argString

Start-Sleep -Seconds 2
$workloadStart = Get-Date
try {
  if ($Client -eq "cmd") {
    & cmd.exe /d /c "data\eval\generated\workloads\cmd\$RunId.cmd"
    if ($LASTEXITCODE -ne 0) {
      throw "CMD workload failed with exit code $LASTEXITCODE"
    }
  } elseif ($Client -eq "powershell") {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "data\eval\generated\workloads\powershell\$RunId.ps1"
    if ($LASTEXITCODE -ne 0) {
      throw "PowerShell workload failed with exit code $LASTEXITCODE"
    }
  } elseif ($Client -eq "smbclient") {
    $repoPath = (Get-Location).Path
    $driveLetter = $repoPath.Substring(0, 1).ToLowerInvariant()
    $repoLinux = "/mnt/$driveLetter" + (($repoPath.Substring(2)) -replace "\\", "/")
    $bashCommand = "cd '$repoLinux' && bash 'data/eval/generated/workloads/smbclient/$RunId.sh'"
    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
      & bash -lc $bashCommand *> $workloadLog
      $bashExitCode = $LASTEXITCODE
    } finally {
      $ErrorActionPreference = $oldErrorActionPreference
    }
    if ($bashExitCode -ne 0) {
      throw "smbclient workload failed with exit code $bashExitCode. See $workloadLog"
    }
  }
} finally {
  $workloadEnd = Get-Date
  Stop-Process -Id $tshark.Id -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

if (-not (Test-Path $rawPcap)) {
  throw "tshark did not create $rawPcap. See $tsharkErr"
}

$oldErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
  $editcapOutput = (& editcap $rawPcap $pcap 2>&1) -join "`n"
  $editcapExitCode = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $oldErrorActionPreference
}
if (-not (Test-Path $pcap)) {
  throw "editcap did not create sanitized PCAP $pcap. Exit=$editcapExitCode Output: $editcapOutput"
}

$capinfos = (& capinfos -M -c -s $pcap) -join "`n"
if ($capinfos -match "Number of packets:\s+(\d+)") {
  $packetCount = [int]$Matches[1]
} else {
  $packetCount = $null
}
if ($packetCount -eq 0) {
  throw "capture has 0 packets: $pcap"
}

$scfStart = Get-Date
& ".\.venv\Scripts\python.exe" -m smbmount scf `
  $pcap `
  "rules\${Client}_rules.json" `
  $timeline `
  --no-print-table `
  --no-progress
if ($LASTEXITCODE -ne 0) {
  throw "SCF failed with exit code $LASTEXITCODE"
}
$scfEnd = Get-Date

& ".\.venv\Scripts\python.exe" "scripts\scf\score_timeline.py" `
  --ground-truth "data\eval\generated\ground_truth\$RunId.jsonl" `
  --timeline $timeline `
  --out-dir $metricDir `
  --time-before $TimeBefore `
  --time-after $TimeAfter
if ($LASTEXITCODE -ne 0) {
  throw "score_timeline failed with exit code $LASTEXITCODE"
}

$metricsPath = "$metricDir\metrics.json"
$metrics = Get-Content $metricsPath -Raw | ConvertFrom-Json

[ordered]@{
  run_id = $RunId
  client = $Client
  count_per_operation = $CountPerOperation
  workload_seconds = ($workloadEnd - $workloadStart).TotalSeconds
  scf_seconds = ($scfEnd - $scfStart).TotalSeconds
  packet_count = $packetCount
  pcap = $pcap
  raw_pcap = $rawPcap
  editcap_output = $editcapOutput
  timeline = $timeline
  metrics = $metricsPath
  workload_log = $workloadLog
  precision = $metrics.overall.precision
  recall = $metrics.overall.recall
  f1 = $metrics.overall.f1
  fp = $metrics.overall.fp
  fn = $metrics.overall.fn
  tp = $metrics.overall.tp
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $runtimeJson

Write-Host ("RESULT {0}: packets={1} workload={2:n2}s scf={3:n2}s precision={4:n4} recall={5:n4} f1={6:n4} fp={7} fn={8}" -f `
  $RunId, $packetCount, ($workloadEnd - $workloadStart).TotalSeconds, ($scfEnd - $scfStart).TotalSeconds, `
  $metrics.overall.precision, $metrics.overall.recall, $metrics.overall.f1, $metrics.overall.fp, $metrics.overall.fn)
