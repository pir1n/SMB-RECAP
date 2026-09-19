$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"

$SampleRoot = Split-Path -Parent $PSScriptRoot
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $SampleRoot)
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
  $Python = "python"
}

$OutDir = Join-Path $SampleRoot "reproduced_outputs"
New-Item -ItemType Directory -Force $OutDir | Out-Null

$Timeline = Join-Path $OutDir "powershell_submission_scale50_timeline.json"
$Metrics = Join-Path $OutDir "powershell_submission_scale50_metrics"

& $Python -m smb_recap scf `
  (Join-Path $SampleRoot "sample_pcaps\powershell_submission_scale50.pcapng") `
  (Join-Path $SampleRoot "rules\powershell_rules.json") `
  $Timeline `
  --no-print-table --no-progress

& $Python (Join-Path $ProjectRoot "scripts\eval\score_timeline.py") `
  --ground-truth (Join-Path $SampleRoot "ground_truth\powershell_submission_scale50.jsonl") `
  --timeline $Timeline `
  --out-dir $Metrics `
  --time-before 1 --time-after 3
