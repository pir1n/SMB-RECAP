param(
    [ValidateSet('cmd', 'powershell')]
    [string]$Client = 'cmd',
    [string]$Pcap,
    [string]$RunId,
    [int]$TimeoutSeconds = 3600
)

$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$WorkspaceRoot = Split-Path $ProjectRoot -Parent
$ScfRoot = Join-Path $WorkspaceRoot 'SCF'
$SmbPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$FkiePython = Join-Path $ScfRoot '.venv\Scripts\python.exe'

if (-not $RunId) {
    if (-not $Pcap) { throw 'Specify -RunId or -Pcap.' }
    $RunId = [IO.Path]::GetFileNameWithoutExtension($Pcap)
}
if (-not $Pcap) {
    $Pcap = Join-Path $ProjectRoot "data\eval\pcaps\$RunId.pcapng"
}
$Pcap = (Resolve-Path $Pcap).Path

if (-not (Test-Path $SmbPython)) { throw "Missing $SmbPython" }
if (-not (Test-Path $FkiePython)) { throw "Missing $FkiePython" }

$FkieRule = if ($Client -eq 'cmd') { 'cmd-rules.tsv' } else { 'ps-rules.tsv' }
$SmbRule = if ($Client -eq 'cmd') { 'cmd_rules.json' } else { 'powershell_rules.json' }
$OutRoot = Join-Path $ProjectRoot "outputs\baseline\comparison\$RunId"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$FkieOutput = Join-Path $OutRoot 'fkie.txt'
$SmbOutput = Join-Path $OutRoot 'smbmount.json'
$TimingOutput = Join-Path $OutRoot 'runtime.json'

function Invoke-TimedProcess($Python, $Arguments, $WorkingDirectory, $Stdout, $Stderr) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $Python -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill($true)
        $watch.Stop()
        return @{ status = 'timeout'; seconds = $watch.Elapsed.TotalSeconds; exit_code = $null }
    }
    $watch.Stop()
    return @{ status = $(if ($process.ExitCode -eq 0) { 'success' } else { 'error' }); seconds = $watch.Elapsed.TotalSeconds; exit_code = $process.ExitCode }
}

$FkieArgs = @('main.py', $Pcap, (Join-Path $ScfRoot "rules\$FkieRule"), '-o', $FkieOutput)
$FkieRuntime = Invoke-TimedProcess $FkiePython $FkieArgs (Join-Path $ScfRoot 'python') `
    (Join-Path $OutRoot 'fkie.stdout.log') (Join-Path $OutRoot 'fkie.stderr.log')

$SmbArgs = @('-m', 'smbmount', 'scf', $Pcap, (Join-Path $ProjectRoot "rules\$SmbRule"), $SmbOutput, '--no-progress')
$SmbRuntime = Invoke-TimedProcess $SmbPython $SmbArgs $ProjectRoot `
    (Join-Path $OutRoot 'smbmount.stdout.log') (Join-Path $OutRoot 'smbmount.stderr.log')

@{ run_id = $RunId; client = $Client; pcap = $Pcap; fkie = $FkieRuntime; smbmount = $SmbRuntime } |
    ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 $TimingOutput

if ($FkieRuntime.status -eq 'success' -and $SmbRuntime.status -eq 'success') {
    & $SmbPython (Join-Path $PSScriptRoot 'compare_fkie_outputs.py') `
        --fkie $FkieOutput --smbmount $SmbOutput --output (Join-Path $OutRoot 'comparison.json')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Results: $OutRoot"
