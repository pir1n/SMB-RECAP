# SCF Scale 50 Sample

This sample contains fresh controlled SCF runs with `count-per-operation=4`, which yields 52 measured operations per client.

## Files

```text
sample_pcaps/cmd_submission_scale50.pcapng
sample_pcaps/powershell_submission_scale50.pcapng
ground_truth/cmd_submission_scale50.jsonl
ground_truth/powershell_submission_scale50.jsonl
rules/cmd_rules.json
rules/powershell_rules.json
expected_outputs/*_timeline.json
expected_outputs/*_metrics/
commands/reproduce_cmd_scale50.ps1
commands/reproduce_powershell_scale50.ps1
```

## Expected Metrics

| Sample | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| CMD scale 50 | 0.9619 | 0.9439 | 0.9528 | 101 | 4 | 6 |
| PowerShell scale 50 | 0.9615 | 0.9346 | 0.9479 | 100 | 4 | 7 |

## Run

From the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\sample\cmd_powershell_scale50\commands\reproduce_cmd_scale50.ps1
.\sample\cmd_powershell_scale50\commands\reproduce_powershell_scale50.ps1
```

The reproduced outputs are written to:

```text
sample/cmd_powershell_scale50/reproduced_outputs/
```
