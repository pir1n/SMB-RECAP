# Additional Experiment Guide

Tai lieu nay mo ta cac thuc nghiem bo sung cho SMBmount/SCF theo yeu cau phan bien: repeated-run benchmark, scale benchmark, robustness test, SCF ablation, error taxonomy, realistic case study va reproducibility package.

Mac dinh chay tai root repo:

```powershell
cd C:\Users\m4scul1n3\Desktop\School\DoAnChuyenNganh\Gitingest\SMBmount_v1_merge
$env:PYTHONIOENCODING = "utf-8"
```

Neu dung Linux/WSL cho `smbclient`, thay path Windows bang path Linux tuong ung va dung `python3`.

## 1. Chuan Bi Moi Truong

### Windows CMD/PowerShell client

Ket noi SMB share:

```powershell
net use Z: \\192.168.106.131\SMB_EVAL /user:SMB1_Sakana "abcABC123!@#"
```

Kiem tra:

```powershell
dir Z:\
```

Kiem tra tool:

```powershell
.\.venv\Scripts\python.exe -m smbmount --help
tshark -v
editcap -v
capinfos -h
```

### Linux/WSL smbclient client

Tao auth file:

```bash
cat > /tmp/smb_eval.auth <<'EOF'
username=SMB1_Sakana
password=abcABC123!@#
EOF
chmod 600 /tmp/smb_eval.auth
```

Kiem tra:

```bash
smbclient //192.168.106.131/SMB_EVAL -A /tmp/smb_eval.auth -m SMB3 -c 'ls'
```

### Thu muc output rieng

Khong ghi de ket qua cu. Moi dot thuc nghiem nen tao mot campaign id:

```powershell
$CAMPAIGN = "exp_2026_07_supplement"
New-Item -ItemType Directory -Force `
  "outputs\$CAMPAIGN", `
  "outputs\$CAMPAIGN\pcaps", `
  "outputs\$CAMPAIGN\timelines", `
  "outputs\$CAMPAIGN\metrics", `
  "outputs\$CAMPAIGN\logs", `
  "outputs\$CAMPAIGN\figures" | Out-Null
```

## 2. Repeated-Run Benchmark

Muc tieu: moi kich ban chay it nhat 5 lan, bao cao mean va standard deviation cua runtime, precision, recall, F1.

### 2.1. SCF repeated-run cho CMD/PowerShell

Vi `generate_operation_scale.py` tao workload deterministic theo `run_id`, moi lan lap nen dung run id rieng de tranh cache/path cu.

Vi du chay 5 lan, moi operation co 40 lan lap. Tong measured operation xap xi `13 * 40 = 520`.

```powershell
$CLIENTS = @("cmd", "powershell")
$REPEATS = 5
$COUNT_PER_OPERATION = 40
$SERVER_IP = "192.168.106.131"
$INTERFACE = "<TSHARK_INTERFACE_ID>"
$CAMPAIGN = "exp_2026_07_supplement"

foreach ($client in $CLIENTS) {
  foreach ($r in 1..$REPEATS) {
    $RUN_ID = "${client}_repeat${r}_scale520_tshark"

    .\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
      --client $client `
      --count-per-operation $COUNT_PER_OPERATION `
      --run-id $RUN_ID `
      --render `
      --drive Z `
      --fast-workload `
      --progress-every 100

    $pcap = "outputs\$CAMPAIGN\pcaps\$RUN_ID.pcapng"
    $tshark = Start-Process -FilePath "tshark" -PassThru -WindowStyle Hidden -ArgumentList @(
      "-i", $INTERFACE,
      "-f", "host $SERVER_IP and tcp port 445",
      "-w", $pcap
    )

    Start-Sleep -Seconds 2
    $start = Get-Date

    if ($client -eq "cmd") {
      cmd.exe /c "data\eval\generated\workloads\cmd\$RUN_ID.cmd"
    } else {
      powershell -NoProfile -ExecutionPolicy Bypass -File "data\eval\generated\workloads\powershell\$RUN_ID.ps1"
    }

    $end = Get-Date
    Stop-Process -Id $tshark.Id

    $timeline = "outputs\$CAMPAIGN\timelines\${RUN_ID}_timeline.json"
    $metricDir = "outputs\$CAMPAIGN\metrics\$RUN_ID"

    .\.venv\Scripts\python.exe -m smbmount scf `
      $pcap `
      "rules\${client}_rules.json" `
      $timeline `
      --no-print-table `
      --no-progress

    .\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
      --ground-truth "data\eval\generated\ground_truth\$RUN_ID.jsonl" `
      --timeline $timeline `
      --out-dir $metricDir `
      --time-before 1 `
      --time-after 3

    [ordered]@{
      run_id = $RUN_ID
      client = $client
      workload_seconds = ($end - $start).TotalSeconds
      pcap = $pcap
      timeline = $timeline
      metrics = "$metricDir\metrics.json"
    } | ConvertTo-Json | Set-Content -Encoding UTF8 "outputs\$CAMPAIGN\logs\$RUN_ID.runtime.json"
  }
}
```

### 2.2. Tong hop mean/std cho SCF

Tao file tam `outputs/<CAMPAIGN>/summarize_scf_repeats.py`:

```powershell
@'
import json, math, statistics, sys
from pathlib import Path

root = Path(sys.argv[1])
rows = []
for metrics_path in root.glob("metrics/*/metrics.json"):
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    overall = metrics["overall"]
    run_id = metrics_path.parent.name
    runtime_path = root / "logs" / f"{run_id}.runtime.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8")) if runtime_path.exists() else {}
    client = run_id.split("_repeat", 1)[0]
    rows.append({
        "client": client,
        "run_id": run_id,
        "workload_seconds": runtime.get("workload_seconds"),
        "precision": overall["precision"],
        "recall": overall["recall"],
        "f1": overall["f1"],
    })

def mean(values):
    values = [v for v in values if v is not None]
    return statistics.mean(values) if values else None

def stdev(values):
    values = [v for v in values if v is not None]
    return statistics.stdev(values) if len(values) > 1 else 0.0

summary = {}
for client in sorted({r["client"] for r in rows}):
    group = [r for r in rows if r["client"] == client]
    summary[client] = {
        "runs": len(group),
        "workload_seconds_mean": mean([r["workload_seconds"] for r in group]),
        "workload_seconds_std": stdev([r["workload_seconds"] for r in group]),
        "precision_mean": mean([r["precision"] for r in group]),
        "precision_std": stdev([r["precision"] for r in group]),
        "recall_mean": mean([r["recall"] for r in group]),
        "recall_std": stdev([r["recall"] for r in group]),
        "f1_mean": mean([r["f1"] for r in group]),
        "f1_std": stdev([r["f1"] for r in group]),
    }

(root / "repeated_run_summary.json").write_text(json.dumps({
    "runs": rows,
    "summary": summary,
}, indent=2), encoding="utf-8")

print(json.dumps(summary, indent=2))
'@ | Set-Content -Encoding UTF8 "outputs\$CAMPAIGN\summarize_scf_repeats.py"

.\.venv\Scripts\python.exe "outputs\$CAMPAIGN\summarize_scf_repeats.py" "outputs\$CAMPAIGN"
```

Ket qua can dua vao bao cao:

- `outputs/<CAMPAIGN>/repeated_run_summary.json`
- bang mean/std theo client
- note ve may test, CPU/RAM, network, SMB server, client app.

### 2.3. Repeated-run cho parse-pcap/FUSE reconstruction

Neu can benchmark phan reconstruct/FUSE so voi pcapFS, dung script co san:

```bash
cd /path/to/SMBmount_v1_merge
export REPEATS=5
export PCAP_DIR=data/pcaps/benchmark_parse-pcap
export OUT_DIR=outputs/exp_2026_07_supplement/runtime_benchmark
bash scripts/measure_runtime.sh
```

Script sinh:

- `outputs/<CAMPAIGN>/runtime_benchmark/runtime.csv`
- JSON output moi run trong `outputs/<CAMPAIGN>/runtime_benchmark/json/`
- log trong `outputs/<CAMPAIGN>/runtime_benchmark/logs/`

Neu khong co `pcapFS`, chi chay SMBmount parse-pcap thu cong:

```bash
for case in multi_file_versioning_001 scale_020_mixed scale_100_mixed; do
  for run in 1 2 3 4 5; do
    /usr/bin/time -f "$case,$run,%e" \
      python -m smbmount parse-pcap \
      "data/pcaps/benchmark_parse-pcap/${case}.pcapng" \
      "outputs/exp_2026_07_supplement/runtime_benchmark/json/${case}_run${run}.json" \
      --timestamp-mode network
  done
done
```

## 3. Scale Benchmark

Muc tieu: bo sung muc lon hon, vi du 500, 1,000, 5,000 operations hoac files. Ve runtime va F1 theo scale.

### 3.1. SCF scale theo tong operation

`generate_operation_scale.py` dung `--count-per-operation`. Hien co 13 operation, do do:

| Tong measured operation mong muon | count-per-operation gan dung |
|---:|---:|
| 500 | 40 |
| 1,000 | 77 |
| 5,000 | 385 |

Chay tuong tu repeated-run, nhung thay `COUNT_PER_OPERATION`:

```powershell
$SCALES = @(
  @{name="500"; count=40},
  @{name="1000"; count=77},
  @{name="5000"; count=385}
)

foreach ($scale in $SCALES) {
  foreach ($client in @("cmd", "powershell")) {
    $RUN_ID = "${client}_scale$($scale.name)_tshark"

    .\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
      --client $client `
      --count-per-operation $scale.count `
      --run-id $RUN_ID `
      --render `
      --drive Z `
      --fast-workload `
      --progress-every 250

    # Capture/workload/SCF/score lam giong muc repeated-run.
  }
}
```

Voi `smbclient`:

```bash
RUN_ID="smbclient_scale1000_tshark"
python3 scripts/eval/generate_operation_scale.py \
  --client smbclient \
  --count-per-operation 77 \
  --run-id "$RUN_ID" \
  --render \
  --server 192.168.106.131 \
  --share SMB_EVAL \
  --auth-file /tmp/smb_eval.auth \
  --local-dir /tmp/smbmount_scf_eval \
  --progress-every 250

tshark -i <INTERFACE_ID> -f "host 192.168.106.131 and tcp port 445" \
  -w "outputs/${CAMPAIGN}/pcaps/${RUN_ID}.pcapng" &
TSHARK_PID=$!
sleep 2
bash "data/eval/generated/workloads/smbclient/${RUN_ID}.sh"
kill "$TSHARK_PID"

python3 -m smbmount scf \
  "outputs/${CAMPAIGN}/pcaps/${RUN_ID}.pcapng" \
  rules/smbclient_rules.json \
  "outputs/${CAMPAIGN}/timelines/${RUN_ID}_timeline.json" \
  --no-print-table --no-progress

python3 scripts/eval/score_timeline.py \
  --ground-truth "data/eval/generated/ground_truth/${RUN_ID}.jsonl" \
  --timeline "outputs/${CAMPAIGN}/timelines/${RUN_ID}_timeline.json" \
  --out-dir "outputs/${CAMPAIGN}/metrics/${RUN_ID}"
```

### 3.2. Reconstruction/FUSE scale theo files

Dung `scripts/generate_scale_workload.py` cho cac muc 500, 1,000, 5,000 files.

Quy trinh Linux/WSL vi script sinh workload thao tac tren mount root:

```bash
CAMPAIGN=exp_2026_07_supplement
MOUNT_ROOT=/mnt/smb_eval
SERVER_IP=192.168.106.131
IFACE=<TSHARK_INTERFACE_ID>

for FILES in 500 1000 5000; do
  CASE="scale_${FILES}_mixed"
  SCENARIO_DIR="bench_scale_${FILES}_mixed"

  mkdir -p "outputs/${CAMPAIGN}/pcaps" "data/gt_parse-pcap"

  tshark -i "$IFACE" -f "host ${SERVER_IP} and tcp port 445" \
    -w "outputs/${CAMPAIGN}/pcaps/${CASE}.pcapng" &
  TSHARK_PID=$!
  sleep 2

  python3 scripts/generate_scale_workload.py \
    --mount-root "$MOUNT_ROOT" \
    --ground-truth "data/gt_parse-pcap/${CASE}.json" \
    --scenario-id "$CASE" \
    --scenario-dir "$SCENARIO_DIR" \
    --files "$FILES" \
    --delay 0.01

  kill "$TSHARK_PID"

  /usr/bin/time -f "%e" \
    python3 -m smbmount parse-pcap \
    "outputs/${CAMPAIGN}/pcaps/${CASE}.pcapng" \
    "outputs/${CAMPAIGN}/${CASE}.json" \
    --timestamp-mode network \
    2> "outputs/${CAMPAIGN}/logs/${CASE}.runtime.txt"
done
```

### 3.3. Ve bieu do runtime va F1

Tao CSV `outputs/<CAMPAIGN>/scale_summary.csv` co cot:

```text
client,scale,run_id,pcap_mb,packet_count,runtime_seconds,precision,recall,f1
```

Lay packet count/pcap size:

```powershell
capinfos -c -s "outputs\$CAMPAIGN\pcaps\<RUN_ID>.pcapng"
```

Tao bieu do bang Python:

```powershell
@'
import csv
from pathlib import Path
import matplotlib.pyplot as plt

csv_path = Path("outputs/exp_2026_07_supplement/scale_summary.csv")
rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))

for metric in ["runtime_seconds", "f1"]:
    plt.figure()
    for client in sorted({r["client"] for r in rows}):
        group = sorted([r for r in rows if r["client"] == client], key=lambda r: int(r["scale"]))
        plt.plot([int(r["scale"]) for r in group], [float(r[metric]) for r in group], marker="o", label=client)
    plt.xlabel("Scale")
    plt.ylabel(metric)
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"outputs/exp_2026_07_supplement/figures/{metric}_by_scale.png", dpi=180)
'@ | Set-Content -Encoding UTF8 "outputs\$CAMPAIGN\plot_scale.py"

.\.venv\Scripts\python.exe "outputs\$CAMPAIGN\plot_scale.py"
```

## 4. Robustness Test

Muc tieu: tao capture khong hoan hao: packet loss 1%, 5%, 10% hoac truncated capture; danh gia complete, partial, hollow.

### 4.1. Dinh nghia complete/partial/hollow

Ap dung cho reconstruction output `parse-pcap`:

- `complete`: file co du tat ca version mong doi, size va md5 dung voi ground truth.
- `partial`: file/path duoc phat hien nhung thieu mot phan version hoac md5/size sai.
- `hollow`: chi co metadata/path/context, khong co content blob hoac version content.

Trong bao cao nen tach:

- content completeness theo file;
- version completeness theo file;
- event completeness theo operation.

### 4.2. Tao packet loss PCAP

Neu `editcap` duoc cai dat, cach on dinh nhat la tao danh sach frame can xoa roi goi `editcap` de remove frame.

Tao helper Python `outputs/<CAMPAIGN>/make_loss_frame_list.py`:

```powershell
@'
import random, sys
from pathlib import Path

packet_count = int(sys.argv[1])
loss_rate = float(sys.argv[2])
seed = int(sys.argv[3])
out = Path(sys.argv[4])

rng = random.Random(seed)
drop = [str(i) for i in range(1, packet_count + 1) if rng.random() < loss_rate]
out.write_text(" ".join(drop), encoding="ascii")
print(f"drop_count={len(drop)}")
'@ | Set-Content -Encoding UTF8 "outputs\$CAMPAIGN\make_loss_frame_list.py"
```

Lay packet count:

```powershell
$INPUT = "outputs\$CAMPAIGN\pcaps\scale_1000_mixed.pcapng"
$COUNT = (capinfos -c $INPUT | Select-String "Number of packets").ToString().Split(":")[-1].Trim()
```

Tao cac ban packet loss:

```powershell
foreach ($loss in @("0.01", "0.05", "0.10")) {
  $tag = $loss.Replace(".", "p")
  $dropList = "outputs\$CAMPAIGN\pcaps\drop_$tag.txt"
  .\.venv\Scripts\python.exe "outputs\$CAMPAIGN\make_loss_frame_list.py" $COUNT $loss 1337 $dropList

  $frames = Get-Content $dropList -Raw
  editcap $INPUT "outputs\$CAMPAIGN\pcaps\scale_1000_mixed_loss_$tag.pcapng" $frames
}
```

Neu danh sach frame qua dai va PowerShell vuot gioi han command-line, chia drop list thanh nhieu lan:

```powershell
# Goi editcap lap nhieu batch 1000 frame: input tam -> output tam.
# Nen dung cho PCAP rat lon.
```

Trong truong hop do, viet script nho de cat batch 1000 frame va goi `editcap` nhieu lan, moi lan output vao file tam tiep theo.

### 4.3. Tao truncated capture

Giu N packet dau:

```powershell
tshark -r $INPUT -c 10000 -w "outputs\$CAMPAIGN\pcaps\scale_1000_mixed_trunc_10k.pcapng"
tshark -r $INPUT -c 50000 -w "outputs\$CAMPAIGN\pcaps\scale_1000_mixed_trunc_50k.pcapng"
```

Hoac cat theo thoi gian:

```powershell
editcap -A "2026-07-05 10:00:00" -B "2026-07-05 10:03:00" `
  $INPUT "outputs\$CAMPAIGN\pcaps\scale_1000_mixed_trunc_time.pcapng"
```

### 4.4. Danh gia robustness

Chay parser tren tung PCAP loi:

```powershell
foreach ($pcap in Get-ChildItem "outputs\$CAMPAIGN\pcaps\*_loss_*.pcapng","outputs\$CAMPAIGN\pcaps\*_trunc_*.pcapng") {
  $case = [IO.Path]::GetFileNameWithoutExtension($pcap.Name)
  .\.venv\Scripts\python.exe -m smbmount parse-pcap `
    $pcap.FullName `
    "outputs\$CAMPAIGN\robustness\$case.json" `
    --timestamp-mode network
}
```

So sanh voi ground truth:

```powershell
.\.venv\Scripts\python.exe -m smbmount.benchmark_parsepcap.cli `
  --ground-truth data\gt_parse-pcap\scale_1000_mixed.json `
  --ours-json outputs\$CAMPAIGN\robustness\scale_1000_mixed_loss_0p05.json `
  --pcapfs-root <PCAPFS_MOUNT_OR_EMPTY_REFERENCE> `
  --out outputs\$CAMPAIGN\robustness\scale_1000_mixed_loss_0p05_metrics
```

Neu khong dung pcapFS trong robustness, viet bang rieng:

| case | packet loss/truncate | complete files | partial files | hollow files | version precision | version recall | version F1 |
|---|---:|---:|---:|---:|---:|---:|---:|

Can luu:

- PCAP loi;
- output parse JSON;
- metrics JSON;
- danh sach file bi partial/hollow.

## 5. SCF Ablation Study

Muc tieu: so sanh semantic SCF hien tai voi cac bien the:

- `full`: rule hien tai theo tung application.
- `app_agnostic`: khong tach rule theo application.
- `no_context`: bo context feature.
- `no_max_gap`: khong dung max_gap.
- `no_excluded_noise`: khong dung excluded/noise pattern.

### 5.1. Tao thu muc ablation

```powershell
New-Item -ItemType Directory -Force "outputs\$CAMPAIGN\ablation\rules" | Out-Null
```

### 5.2. Full baseline

Baseline dung rule theo app:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf `
  data\eval\pcaps\powershell_operation_scale_100_tshark.pcapng `
  rules\powershell_rules.json `
  outputs\$CAMPAIGN\ablation\powershell_full_timeline.json `
  --no-print-table --no-progress
```

### 5.3. App-agnostic variant

Gop rule 3 app vao mot file. Neu JSON co key `rules`, tao file merged bang Python:

```powershell
@'
import json
from pathlib import Path

sources = [
    Path("rules/cmd_rules.json"),
    Path("rules/powershell_rules.json"),
    Path("rules/smbclient_rules.json"),
]
merged = {
    "format": "smbmount-semantic-scf-v2",
    "source": "ablation_app_agnostic",
    "rules": [],
}
for src in sources:
    data = json.loads(src.read_text(encoding="utf-8"))
    app = src.stem.replace("_rules", "")
    for rule in data.get("rules", []):
        item = dict(rule)
        item["rule_id"] = f"{app}:{item.get('rule_id')}"
        item["source_application"] = app
        merged["rules"].append(item)
Path("outputs/exp_2026_07_supplement/ablation/rules/app_agnostic_rules.json").write_text(
    json.dumps(merged, indent=2, ensure_ascii=False),
    encoding="utf-8",
)
'@ | Set-Content -Encoding UTF8 "outputs\$CAMPAIGN\ablation\make_app_agnostic_rules.py"

.\.venv\Scripts\python.exe "outputs\$CAMPAIGN\ablation\make_app_agnostic_rules.py"
```

Chay moi client voi file rule gop:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf `
  data\eval\pcaps\powershell_operation_scale_100_tshark.pcapng `
  outputs\$CAMPAIGN\ablation\rules\app_agnostic_rules.json `
  outputs\$CAMPAIGN\ablation\powershell_app_agnostic_timeline.json `
  --no-print-table --no-progress
```

### 5.4. No-context / no-max-gap / no-excluded-noise

Tao script ablation rule JSON:

```powershell
@'
import json, sys
from pathlib import Path

src = Path(sys.argv[1])
variant = sys.argv[2]
dst = Path(sys.argv[3])
data = json.loads(src.read_text(encoding="utf-8"))

for rule in data.get("rules", []):
    rule["rule_id"] = f"{rule.get('rule_id')}__{variant}"

    if variant == "no_context":
        for key in [
            "context",
            "context_features",
            "required_context",
            "path_context",
            "target_context",
        ]:
            rule.pop(key, None)

    elif variant == "no_max_gap":
        rule.pop("max_gap", None)
        rule.pop("max_frame_gap", None)
        rule.pop("max_time_gap", None)

    elif variant == "no_excluded_noise":
        for key in [
            "excluded",
            "excluded_patterns",
            "exclude_patterns",
            "noise",
            "noise_patterns",
            "support_commands",
        ]:
            rule.pop(key, None)
    else:
        raise SystemExit(f"unknown variant: {variant}")

dst.parent.mkdir(parents=True, exist_ok=True)
dst.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
'@ | Set-Content -Encoding UTF8 "outputs\$CAMPAIGN\ablation\make_rule_variant.py"
```

Sinh variants:

```powershell
foreach ($client in @("cmd", "powershell", "smbclient")) {
  foreach ($variant in @("no_context", "no_max_gap", "no_excluded_noise")) {
    .\.venv\Scripts\python.exe "outputs\$CAMPAIGN\ablation\make_rule_variant.py" `
      "rules\${client}_rules.json" `
      $variant `
      "outputs\$CAMPAIGN\ablation\rules\${client}_${variant}.json"
  }
}
```

Chay SCF/score cho tung variant:

```powershell
$client = "powershell"
$RUN_ID = "powershell_operation_scale_100_tshark"
foreach ($variant in @("full", "app_agnostic", "no_context", "no_max_gap", "no_excluded_noise")) {
  if ($variant -eq "full") {
    $rule = "rules\${client}_rules.json"
  } elseif ($variant -eq "app_agnostic") {
    $rule = "outputs\$CAMPAIGN\ablation\rules\app_agnostic_rules.json"
  } else {
    $rule = "outputs\$CAMPAIGN\ablation\rules\${client}_${variant}.json"
  }

  $timeline = "outputs\$CAMPAIGN\ablation\${RUN_ID}_${variant}_timeline.json"
  $metricDir = "outputs\$CAMPAIGN\ablation\metrics\${RUN_ID}_${variant}"

  .\.venv\Scripts\python.exe -m smbmount scf `
    "data\eval\pcaps\$RUN_ID.pcapng" `
    $rule `
    $timeline `
    --no-print-table --no-progress

  .\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
    --ground-truth "data\eval\generated\ground_truth\$RUN_ID.jsonl" `
    --timeline $timeline `
    --out-dir $metricDir
}
```

Bang bao cao:

| client | variant | precision | recall | F1 | FP | FN | nhan xet |
|---|---|---:|---:|---:|---:|---:|---|

## 6. Error Taxonomy Cho FP/FN

Muc tieu: voi loi PowerShell va smbclient, phan loai nguyen nhan:

- `path_mismatch`
- `time_window_mismatch`
- `rule_ambiguity`
- `support_command_noise`
- `client_cache`
- `interleaving`
- `missing_packet`

### 6.1. Lay file debug

Sau scoring, moi run co:

```text
outputs/<CAMPAIGN>/metrics/<RUN_ID>/fp_fn_debug.json
outputs/<CAMPAIGN>/metrics/<RUN_ID>/fp_debug.json
outputs/<CAMPAIGN>/metrics/<RUN_ID>/fn_debug.json
```

### 6.2. Quy tac phan loai de audit thu cong

Dung `fp_fn_debug.json` va `timeline.json`, mo tung error:

- `path_mismatch`: event/time dung nhung `path` hoac `target_path` khac ground truth.
- `time_window_mismatch`: event/path dung nhung timestamp nam ngoai `[start_time - time_before, end_time + time_after]`.
- `rule_ambiguity`: SMB sequence co the match nhieu operation, vi du read/download, upload/write/append.
- `support_command_noise`: command setup phu sinh CREATE/QUERY/READ/WRITE va bi detect thanh user operation.
- `client_cache`: client khong gui SMB operation vi cache local, hoac gui READ/QUERY khac ky vong.
- `interleaving`: operation chong lan trong window, frame cua operation A/B xen nhau.
- `missing_packet`: PCAP thieu request/response can thiet, thuong gap trong robustness loss/truncate.

### 6.3. Tao taxonomy JSON

Tao file:

```text
outputs/<CAMPAIGN>/error_taxonomy/<RUN_ID>_taxonomy.json
```

Format:

```json
[
  {
    "error_id": "powershell_001",
    "run_id": "powershell_operation_scale_100_tshark",
    "error_type": "FP",
    "predicted_event": "directory_listing",
    "expected_event": null,
    "taxonomy": "support_command_noise",
    "evidence": {
      "frames": [123, 124, 125],
      "rule_id": "powershell_directory_listing",
      "path": "rabc123/ld000001"
    },
    "note": "PowerShell emitted extra GetChildItem-like query during setup."
  }
]
```

### 6.4. Bang tong hop

Tao CSV:

```text
run_id,client,error_type,taxonomy,count
```

Bang dua vao bao cao:

| client | taxonomy | FP | FN | MISCLASS | example frame/rule |
|---|---|---:|---:|---:|---|

## 7. Realistic Case Study

Muc tieu: tao mot kich ban dieu tra so hoan chinh: create file, modify, rename, copy/upload, delete, download. Xuat evidence bundle gom timeline, frame list, SCF hash, file version, md5, path history.

### 7.1. Cach nhanh bang operation-scale count=1

Tao workload co day du operation:

```powershell
$RUN_ID = "case_study_cmd_001"
$CAMPAIGN = "exp_2026_07_supplement"

.\.venv\Scripts\python.exe scripts\eval\generate_operation_scale.py `
  --client cmd `
  --count-per-operation 1 `
  --run-id $RUN_ID `
  --render `
  --drive Z `
  --fast-workload `
  --progress-every 1
```

Capture va chay:

```powershell
$pcap = "outputs\$CAMPAIGN\case_study\$RUN_ID.pcapng"
New-Item -ItemType Directory -Force "outputs\$CAMPAIGN\case_study" | Out-Null

$tshark = Start-Process -FilePath "tshark" -PassThru -WindowStyle Hidden -ArgumentList @(
  "-i", "<TSHARK_INTERFACE_ID>",
  "-f", "host 192.168.106.131 and tcp port 445",
  "-w", $pcap
)
Start-Sleep -Seconds 2
cmd.exe /c "data\eval\generated\workloads\cmd\$RUN_ID.cmd"
Stop-Process -Id $tshark.Id
```

Sinh evidence:

```powershell
.\.venv\Scripts\python.exe -m smbmount scf `
  $pcap `
  rules\cmd_rules.json `
  "outputs\$CAMPAIGN\case_study\${RUN_ID}_timeline.json" `
  --no-print-table

.\.venv\Scripts\python.exe -m smbmount scf-dump `
  $pcap `
  "outputs\$CAMPAIGN\case_study\${RUN_ID}_scf_dump.json"

.\.venv\Scripts\python.exe -m smbmount parse-pcap `
  $pcap `
  "outputs\$CAMPAIGN\case_study\${RUN_ID}_reconstruction.json" `
  --timestamp-mode network

.\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
  --ground-truth "data\eval\generated\ground_truth\$RUN_ID.jsonl" `
  --timeline "outputs\$CAMPAIGN\case_study\${RUN_ID}_timeline.json" `
  --out-dir "outputs\$CAMPAIGN\case_study\${RUN_ID}_metrics"
```

### 7.2. Evidence bundle can nop

Tao folder:

```powershell
$BUNDLE = "outputs\$CAMPAIGN\case_study\evidence_bundle_$RUN_ID"
New-Item -ItemType Directory -Force $BUNDLE | Out-Null

Copy-Item $pcap $BUNDLE
Copy-Item "data\eval\generated\ground_truth\$RUN_ID.jsonl" $BUNDLE
Copy-Item "outputs\$CAMPAIGN\case_study\${RUN_ID}_timeline.json" $BUNDLE
Copy-Item "outputs\$CAMPAIGN\case_study\${RUN_ID}_scf_dump.json" $BUNDLE
Copy-Item "outputs\$CAMPAIGN\case_study\${RUN_ID}_reconstruction.json" $BUNDLE
Copy-Item "outputs\$CAMPAIGN\case_study\${RUN_ID}_metrics\metrics.json" $BUNDLE
Copy-Item "outputs\$CAMPAIGN\case_study\${RUN_ID}_metrics\fp_fn_debug.json" $BUNDLE
```

Tao `README_case_study.md` trong bundle, gom cac y:

- muc tieu dieu tra;
- PCAP file va capture filter;
- timeline cac hanh dong;
- frame list cho moi event;
- SCF hash/fingerprint lay tu `scf_dump.json`;
- file versions, md5, size lay tu `reconstruction.json`;
- path history cua file rename/move;
- ket luan: file nao bi tao/sua/rename/download/delete.

## 8. Reproducibility Package

Muc tieu: nguoi khac co the tai package, chay lai lenh, va thu duoc expected output.

### 8.1. Cau truc package

Tao:

```powershell
$PKG = "outputs\$CAMPAIGN\repro_package"
New-Item -ItemType Directory -Force `
  "$PKG\sample_pcaps", `
  "$PKG\ground_truth", `
  "$PKG\rules", `
  "$PKG\expected_outputs", `
  "$PKG\commands" | Out-Null
```

Copy file toi thieu:

```powershell
Copy-Item README.md $PKG
Copy-Item requirements.txt $PKG
Copy-Item rules\cmd_rules.json "$PKG\rules"
Copy-Item rules\powershell_rules.json "$PKG\rules"
Copy-Item rules\smbclient_rules.json "$PKG\rules"

Copy-Item data\pcaps\benchmark_parse-pcap\multi_file_versioning_001.pcapng "$PKG\sample_pcaps"
Copy-Item data\gt_parse-pcap\multi_file_versioning_001_gt.json "$PKG\ground_truth"
Copy-Item outputs\multi_file_versioning_001_fixed.json "$PKG\expected_outputs" -ErrorAction SilentlyContinue
```

### 8.2. Lenh tai lap toi thieu

Tao `commands/reproduce_parse_pcap.ps1`:

```powershell
@'
$env:PYTHONIOENCODING = "utf-8"
python -m venv .venv
.\.venv\Scripts\pip.exe install -r requirements.txt
.\.venv\Scripts\python.exe -m smbmount parse-pcap `
  sample_pcaps\multi_file_versioning_001.pcapng `
  expected_outputs\reproduced_parse.json `
  --timestamp-mode network
'@ | Set-Content -Encoding UTF8 "$PKG\commands\reproduce_parse_pcap.ps1"
```

Tao `commands/reproduce_scf.ps1` neu co sample SCF PCAP + ground truth JSONL:

```powershell
@'
$env:PYTHONIOENCODING = "utf-8"
.\.venv\Scripts\python.exe -m smbmount scf `
  sample_pcaps\cmd_operation_scale_sample.pcapng `
  rules\cmd_rules.json `
  expected_outputs\cmd_operation_scale_sample_timeline.json `
  --no-print-table --no-progress

.\.venv\Scripts\python.exe scripts\eval\score_timeline.py `
  --ground-truth ground_truth\cmd_operation_scale_sample.jsonl `
  --timeline expected_outputs\cmd_operation_scale_sample_timeline.json `
  --out-dir expected_outputs\cmd_operation_scale_sample_metrics
'@ | Set-Content -Encoding UTF8 "$PKG\commands\reproduce_scf.ps1"
```

### 8.3. Metadata package

Tao `repro_manifest.json`:

```powershell
@{
  repo_branch = "SMBmount_v1"
  generated_at = (Get-Date).ToUniversalTime().ToString("o")
  python = (& .\.venv\Scripts\python.exe --version)
  tshark = (& tshark -v | Select-Object -First 1)
  sample_pcaps = @("multi_file_versioning_001.pcapng")
  expected_outputs = @("reproduced_parse.json")
  notes = "Run commands from package root. Use PYTHONIOENCODING=utf-8 on Windows."
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 "$PKG\repro_manifest.json"
```

Nen nen package:

```powershell
Compress-Archive -Path "$PKG\*" -DestinationPath "outputs\$CAMPAIGN\repro_package.zip" -Force
```

## 9. Bao Cao Ket Qua

Trong bao cao, nen tach thanh cac bang/hinh:

1. Repeated-run SCF:
   - mean/std runtime, precision, recall, F1 theo client.
2. Scale SCF:
   - runtime theo scale;
   - F1 theo scale;
   - FP/FN theo scale.
3. Robustness:
   - complete/partial/hollow theo packet loss/truncation.
4. Ablation:
   - full vs app_agnostic vs no_context vs no_max_gap vs no_excluded_noise.
5. Error taxonomy:
   - so luong FP/FN theo taxonomy va vi du frame.
6. Realistic case study:
   - timeline dieu tra, frame evidence, SCF hash, md5, path history.
7. Reproducibility:
   - link package, cau truc package, lenh tai lap, expected output.

Moi bang nen ghi ro:

- PCAP source;
- client app;
- SMB server;
- capture filter;
- rule file;
- scoring window `time_before`, `time_after`;
- hardware/moi truong chay;
- commit/branch: `SMBmount_v1`.
