# SMB-RECAP

SMB-RECAP (SMB Reconstruction of Events and Content from Packet Captures) is a research prototype for reconstructing SMB activity from PCAP/PCAPNG network captures. The project has two main parts:

- Filesystem reconstruction from SMB traffic: parse SMB2 packets, rebuild directory/file metadata, recover observed content versions, export JSON, and optionally mount the reconstructed view with FUSE.
- Semantic Command Fingerprinting (SCF): normalize SMB command sequences into semantic features and infer high-level file operations such as create, delete, list, upload, download, read, append, rename, and move.

The repository also contains a reproducible evaluation harness with workload generation, ground truth JSONL, scoring, confusion matrices, FP/FN debug output, and small sample packages for submission.

## Repository Layout

```text
smb_recap/
  __main__.py                    Preferred CLI namespace: python -m smb_recap

smbmount/
  cli.py                         Backward-compatible implementation namespace
  parser/                        PCAP/SMB parsing and TCP stream handling
  reconstruct/                   File metadata, content, hierarchy, versioning
  output/
    fs_export.py                 JSON reconstruction export
    fuse_mount.py                Read-only FUSE view of reconstructed files
    snapshot_export.py           Snapshot view at a selected timestamp
  scf/                           Semantic SCF normalization and rule detector
  benchmark_parsepcap/           parse-pcap/FUSE benchmark helpers

rules/
  cmd_rules.json
  powershell_rules.json
  smbclient_rules.json
  scf_builtin_rules.json

scripts/
  eval/                          SCF workload, renderer, scoring, ablation
  eval_parsepcap/                parse-pcap/FUSE workload and benchmark scripts

sample/
  fuse_module_sample/            Small parse-pcap/FUSE reproducibility sample
  cmd_powershell_scale50/        SCF scale-50 reproducibility sample

paper/
  main.tex                       Self-contained Elsevier LaTeX manuscript
```

## Manuscript

The submission manuscript is maintained as a single self-contained LaTeX
source file. Internal Markdown drafts and generated PDFs are intentionally not
tracked.

```bash
tectonic paper/main.tex
```

## Environment

### Windows / PowerShell for SCF

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m smb_recap --help
```

Optional tools for live capture:

- Wireshark/tshark
- An SMB server/share
- A mapped drive for `cmd.exe` and PowerShell workloads, for example `Z:`

### Linux / WSL for FUSE

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

sudo apt install tshark fuse3
python -m smb_recap --help
```

For comparison with pcapFS, install pcapFS separately and verify:

```bash
pcapfs --help
```

If `requirements.txt` has encoding issues in Linux/WSL:

```bash
iconv -f UTF-16LE -t UTF-8 requirements.txt > /tmp/smb_recap_requirements.txt
pip install -r /tmp/smb_recap_requirements.txt
```

## Filesystem Reconstruction and FUSE

`parse-pcap` reads SMB traffic from a PCAP/PCAPNG capture and exports a structured reconstruction JSON. The output includes reconstructed file entries, metadata, path history, content versions, hashes, and events observed from the network trace.

Basic parse:

```bash
python -m smb_recap parse-pcap \
  <input.pcapng> \
  <output.json> \
  --timestamp-mode network
```

Useful options:

- `--timestamp-mode network|fs|hybrid`: choose packet timestamp, filesystem timestamp, or hybrid mode.
- `--reader streaming|legacy`: use streaming or legacy reader. Use `streaming` for larger captures.
- `--snapshot-at <unix_timestamp>`: export a filesystem snapshot at a selected time.
- `--snapshot-time-source network|fs`: choose timestamp source for snapshot membership.
- `--fuse-mount <mountpoint>`: mount the reconstructed filesystem as a read-only FUSE view.
- `--fuse-include-deleted`: include deleted files in the FUSE view.
- `--fuse-allow-other`: allow other users to access the mount, if enabled in system FUSE config.
- `--fuse-debug`: print FUSE debug logs.

### Run the FUSE Sample

The FUSE sample is in:

```text
sample/fuse_module_sample/
  pcaps/scale_0050_mixed.pcapng
  ground_truth/scale_0050_mixed.json
  expected_output.md
  measure_runtime.sh
```

Parse the sample PCAP:

```bash
mkdir -p outputs/fuse_module_sample/manual

python -m smb_recap parse-pcap \
  sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng \
  outputs/fuse_module_sample/manual/scale_0050_mixed.json \
  --timestamp-mode network \
  --reader streaming
```

Mount the reconstructed filesystem:

```bash
mkdir -p /tmp/smb_recap_recon

python -m smb_recap parse-pcap \
  sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng \
  outputs/fuse_module_sample/manual/scale_0050_mixed.json \
  --timestamp-mode network \
  --reader streaming \
  --fuse-mount /tmp/smb_recap_recon
```

In another terminal, inspect the mounted view:

```bash
find /tmp/smb_recap_recon -maxdepth 3 | head
ls -lah /tmp/smb_recap_recon
```

Stop the FUSE mount with `Ctrl+C` in the terminal running `parse-pcap`. If needed:

```bash
fusermount3 -u /tmp/smb_recap_recon
```

Expected sample details are documented in:

```text
sample/fuse_module_sample/expected_output.md
```

Expected strict path-content score for SMB-RECAP on this sample:

| Tool | TP/FP/FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| SMB-RECAP parse-pcap | 90/0/0 | 1.0000 | 1.0000 | 1.0000 |

### Optional pcapFS Comparison

Run pcapFS on the same sample:

```bash
mkdir -p /tmp/pcapfs_scale_0050

pcapfs \
  --timestamp-mode network \
  --show-metadata \
  -f \
  sample/fuse_module_sample/pcaps/scale_0050_mixed.pcapng \
  /tmp/pcapfs_scale_0050
```

In another terminal, score SMB-RECAP and pcapFS with the shared benchmark schema:

```bash
python -m smb_recap.benchmark_parsepcap.cli \
  --ground-truth sample/fuse_module_sample/ground_truth/scale_0050_mixed.json \
  --ours-json outputs/fuse_module_sample/manual/scale_0050_mixed.json \
  --pcapfs-root /tmp/pcapfs_scale_0050 \
  --scenario-dir bench_scale_0050_mixed \
  --out outputs/fuse_module_sample/manual/benchmark
```

Unmount pcapFS after scoring:

```bash
fusermount3 -u /tmp/pcapfs_scale_0050
```

Expected comparison for the sample:

| Tool | strict_path_content TP/FP/FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| SMB-RECAP parse-pcap | 90/0/0 | 1.0000 | 1.0000 | 1.0000 |
| pcapFS | 80/13/10 | 0.8602 | 0.8889 | 0.8743 |

### Repeated Runtime Script for FUSE Sample

Run both SMB-RECAP and pcapFS:

```bash
sample/fuse_module_sample/measure_runtime.sh --repeats 5
```

Run only SMB-RECAP:

```bash
sample/fuse_module_sample/measure_runtime.sh --tool smbmount --repeats 1
```

The benchmark selector remains `smbmount` for compatibility with archived CSV files; the tool name reported in the paper is SMB-RECAP.

Main outputs:

```text
outputs/fuse_module_sample/runtime_metrics.csv
outputs/fuse_module_sample/json/
outputs/fuse_module_sample/logs/
outputs/fuse_module_sample/benchmark/
```

## Semantic Command Fingerprinting

SCF converts SMB records into semantic features, then matches command sequences against rule JSON. The current rule files are:

```text
rules/cmd_rules.json
rules/powershell_rules.json
rules/smbclient_rules.json
```

Semantic features include:

- SMB command type: `CREATE`, `READ`, `WRITE`, `SET_INFO`, `QUERY_DIRECTORY`
- access intent: read, write, delete, metadata
- target type: file, directory, unknown
- create result/disposition family
- information class for rename/delete/list operations
- I/O length class

Dynamic values such as raw path, FileId, offset, raw length, and content bytes are not used as the main fingerprint so that rules generalize better across runs.

Build a timeline:

```powershell
.\.venv\Scripts\python.exe -m smb_recap scf `
  <input.pcapng> `
  rules\cmd_rules.json `
  outputs\eval\timelines\<RUN_ID>_timeline.json `
  --no-print-table
```

Useful options:

- `--no-print-table`: do not print the Rich table, recommended for large captures.
- `--print-table`: print the timeline table for manual inspection.
- `--no-progress`: suppress 10% progress logs.
- `--with-builtin-rules`: load built-in semantic rules in addition to the supplied rule file.

Dump normalized SCF features for rule debugging:

```powershell
.\.venv\Scripts\python.exe -m smb_recap scf-dump `
  <input.pcapng> `
  outputs\eval\tshark\<RUN_ID>_scf_dump.json
```

## Run the SCF Sample

The SCF reproducibility sample contains a small controlled scale-50 CMD and PowerShell run. It is in:

```text
sample/cmd_powershell_scale50/
  sample_pcaps/
  ground_truth/
  rules/
  expected_outputs/
  commands/
```

Run CMD scale-50 sample:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\sample\cmd_powershell_scale50\commands\reproduce_cmd_scale50.ps1
```

Run PowerShell scale-50 sample:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\sample\cmd_powershell_scale50\commands\reproduce_powershell_scale50.ps1
```

Manual CMD scale-50 commands:

```powershell
.\.venv\Scripts\python.exe -m smb_recap scf `
  sample\cmd_powershell_scale50\sample_pcaps\cmd_submission_scale50.pcapng `
  sample\cmd_powershell_scale50\rules\cmd_rules.json `
  sample\cmd_powershell_scale50\reproduced_outputs\cmd_submission_scale50_timeline.json `
  --no-print-table --no-progress

.\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
  --ground-truth sample\cmd_powershell_scale50\ground_truth\cmd_submission_scale50.jsonl `
  --timeline sample\cmd_powershell_scale50\reproduced_outputs\cmd_submission_scale50_timeline.json `
  --out-dir sample\cmd_powershell_scale50\reproduced_outputs\cmd_submission_scale50_metrics `
  --time-before 1 --time-after 3
```

Manual PowerShell scale-50 commands:

```powershell
.\.venv\Scripts\python.exe -m smb_recap scf `
  sample\cmd_powershell_scale50\sample_pcaps\powershell_submission_scale50.pcapng `
  sample\cmd_powershell_scale50\rules\powershell_rules.json `
  sample\cmd_powershell_scale50\reproduced_outputs\powershell_submission_scale50_timeline.json `
  --no-print-table --no-progress

.\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
  --ground-truth sample\cmd_powershell_scale50\ground_truth\powershell_submission_scale50.jsonl `
  --timeline sample\cmd_powershell_scale50\reproduced_outputs\powershell_submission_scale50_timeline.json `
  --out-dir sample\cmd_powershell_scale50\reproduced_outputs\powershell_submission_scale50_metrics `
  --time-before 1 --time-after 3
```

Expected SCF sample metrics:

| Sample | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| CMD scale 50 | 0.9619 | 0.9439 | 0.9528 | 101 | 4 | 6 |
| PowerShell scale 50 | 0.9615 | 0.9346 | 0.9479 | 100 | 4 | 7 |

## Generate New SCF Workloads

Use `scripts/eval/generate_operation_scale.py`.

CMD:

```powershell
$RUN_ID = "cmd_sample_live"

.\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
  --client cmd `
  --count-per-operation 3 `
  --run-id $RUN_ID `
  --render `
  --drive Z `
  --fast-workload `
  --progress-every 100
```

PowerShell:

```powershell
$RUN_ID = "powershell_sample_live"

.\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
  --client powershell `
  --count-per-operation 3 `
  --run-id $RUN_ID `
  --render `
  --drive Z `
  --fast-workload `
  --progress-every 100
```

smbclient:

```bash
RUN_ID="smbclient_sample_live"

python scripts/eval/generate_operation_scale.py \
  --client smbclient \
  --count-per-operation 3 \
  --run-id "$RUN_ID" \
  --render \
  --server <SERVER_IP> \
  --share <SHARE_NAME> \
  --auth-file /tmp/smb_eval.auth \
  --local-dir /tmp/smb_recap_scf_eval \
  --progress-every 100
```

Generated files:

```text
data/eval/generated/plans/
data/eval/generated/ground_truth/
data/eval/generated/ground_truth_expected/
data/eval/generated/manifests/
data/eval/generated/workloads/
```

## Capture Live SMB Traffic with tshark

List interfaces:

```powershell
tshark -D
```

Capture SMB traffic:

```powershell
tshark -i <INTERFACE_ID> -f "host <SERVER_IP> and tcp port 445" -w data\eval\pcaps\$RUN_ID.pcapng
```

Run workload in another terminal.

CMD:

```powershell
cmd /c data\eval\generated\workloads\cmd\$RUN_ID.cmd
```

PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File data\eval\generated\workloads\powershell\$RUN_ID.ps1
```

smbclient:

```bash
bash "data/eval/generated/workloads/smbclient/${RUN_ID}.sh"
```

Stop `tshark` with `Ctrl+C`, then build and score the timeline.

## Score SCF Timeline

```powershell
.\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
  --ground-truth data\eval\generated\ground_truth\$RUN_ID.jsonl `
  --timeline outputs\eval\timelines\${RUN_ID}_timeline.json `
  --out-dir outputs\eval\metrics\$RUN_ID `
  --time-before 1.0 `
  --time-after 3.0
```

`--time-before` and `--time-after` define the match window:

```text
ground_truth.start_time - time_before
to
ground_truth.end_time + time_after
```

Metrics output:

```text
outputs/eval/metrics/<RUN_ID>/metrics.json
outputs/eval/metrics/<RUN_ID>/confusion_matrix.csv
outputs/eval/metrics/<RUN_ID>/confusion_matrix.json
outputs/eval/metrics/<RUN_ID>/matches.json
outputs/eval/metrics/<RUN_ID>/fp_debug.json
outputs/eval/metrics/<RUN_ID>/fn_debug.json
outputs/eval/metrics/<RUN_ID>/fp_fn_debug.json
```

## Notes

- `cmd` and PowerShell workloads are intended to run through a mapped SMB drive such as `Z:`.
- `smbclient` workloads are intended for Linux/WSL with an auth file.
- Use `--fast-workload --progress-every 100` for large CMD/PowerShell workloads.
- Use `--no-print-table` when building large SCF timelines.
- The pcapFS comparison is only for reconstructed content/version output. pcapFS does not emit a semantic event timeline comparable to SCF.
- Large PCAPs, benchmark outputs, and generated workloads should not be committed unless they are intentionally curated samples.
