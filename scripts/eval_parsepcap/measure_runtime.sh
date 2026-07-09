#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

CASE_ID="scale_0050_mixed"
FILES="50"
PCAP="$SCRIPT_DIR/pcaps/scale_0050_mixed.pcapng"
GROUND_TRUTH="$SCRIPT_DIR/ground_truth/scale_0050_mixed.json"
SCENARIO_DIR="bench_scale_0050_mixed"
CASE_FILE=""

REPEATS="${REPEATS:-5}"
OUT_DIR="$ROOT_DIR/outputs/fuse_module_sample"
PCAPFS_MOUNT="/tmp/pcapfs_fuse_module_sample"
TIMESTAMP_MODE="network"
READER="streaming"
BENCH_MODULE="smbmount.benchmark_parsepcap.cli"
TOOL_MODE="both"

if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python"
  fi
fi

usage() {
  cat <<'EOF'
Usage:
  sample/fuse_module_sample/measure_runtime.sh [options]

Default:
  Runs scale_0050_mixed sample in sample/fuse_module_sample.

Options:
  --case-id ID              Case id used in output filenames.
  --files N                 Number of files in the case.
  --pcap PATH               PCAP/PCAPNG input.
  --ground-truth PATH       Ground truth JSON input.
  --scenario-dir NAME       Scenario root directory inside the SMB share.
  --case-file PATH          TSV with: case_id<TAB>files<TAB>pcap<TAB>ground_truth<TAB>scenario_dir.
  --repeats N               Number of repeated runs. Default: 5.
  --out-dir PATH            Output directory. Default: outputs/fuse_module_sample.
  --pcapfs-mount PATH       Temporary pcapFS mountpoint.
  --timestamp-mode MODE     network, fs, or hybrid. Default: network.
  --reader MODE             streaming or legacy. Default: streaming.
  --tool MODE               smbmount, pcapfs, or both. Default: both.
  --python-bin PATH         Python executable.
  --bench-module MODULE     Benchmark module. Default: smbmount.benchmark_parsepcap.cli.
  -h, --help                Show this help.

Environment overrides:
  PYTHON_BIN, REPEATS
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case-id) CASE_ID="$2"; shift 2 ;;
    --files) FILES="$2"; shift 2 ;;
    --pcap) PCAP="$2"; shift 2 ;;
    --ground-truth) GROUND_TRUTH="$2"; shift 2 ;;
    --scenario-dir) SCENARIO_DIR="$2"; shift 2 ;;
    --case-file) CASE_FILE="$2"; shift 2 ;;
    --repeats) REPEATS="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --pcapfs-mount) PCAPFS_MOUNT="$2"; shift 2 ;;
    --timestamp-mode) TIMESTAMP_MODE="$2"; shift 2 ;;
    --reader) READER="$2"; shift 2 ;;
    --tool) TOOL_MODE="$2"; shift 2 ;;
    --python-bin) PYTHON_BIN="$2"; shift 2 ;;
    --bench-module) BENCH_MODULE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

JSON_DIR="$OUT_DIR/json"
LOG_DIR="$OUT_DIR/logs"
BENCH_DIR="$OUT_DIR/benchmark"
CSV="$OUT_DIR/runtime_metrics.csv"
CURRENT_PCAPFS_PID=""

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[ERROR] Missing command: $1" >&2
    exit 1
  fi
}

abspath() {
  "$PYTHON_BIN" - "$1" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
}

now_ns() {
  "$PYTHON_BIN" -c 'import time; print(time.time_ns())'
}

elapsed_sec() {
  "$PYTHON_BIN" - "$1" "$2" <<'PY'
import sys
start = int(sys.argv[1])
end = int(sys.argv[2])
print(f"{(end - start) / 1_000_000_000:.6f}")
PY
}

cleanup_pcapfs_mount() {
  local mount_dir="$1"

  if mountpoint -q "$mount_dir" 2>/dev/null; then
    fusermount3 -u "$mount_dir" 2>/dev/null \
      || fusermount -u "$mount_dir" 2>/dev/null \
      || sudo umount -l "$mount_dir" 2>/dev/null \
      || true
  fi

  pkill -f "pcapfs.*$mount_dir" 2>/dev/null || true
  sleep 0.3
}

cleanup_on_exit() {
  if [[ "$TOOL_MODE" == "smbmount" ]]; then
    return
  fi

  if [[ -n "${CURRENT_PCAPFS_PID:-}" ]]; then
    kill "$CURRENT_PCAPFS_PID" 2>/dev/null || true
    wait "$CURRENT_PCAPFS_PID" 2>/dev/null || true
    CURRENT_PCAPFS_PID=""
  fi

  cleanup_pcapfs_mount "$PCAPFS_MOUNT"
}

wait_for_mount_ready() {
  local mount_dir="$1"
  local pid="$2"
  local waited=0
  local timeout="${PCAPFS_TIMEOUT:-120}"

  while true; do
    if mountpoint -q "$mount_dir" 2>/dev/null; then
      return 0
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi

    sleep 1
    waited=$((waited + 1))

    if (( waited >= timeout )); then
      echo "[ERROR] Timeout waiting for pcapFS mount after ${timeout}s" >&2
      return 1
    fi

    if (( waited % 30 == 0 )); then
      echo "      waiting for pcapFS mount... ${waited}s"
    fi
  done
}

append_metric_row() {
  local tool="$1"
  local case_id="$2"
  local files="$3"
  local run_id="$4"
  local runtime_s="$5"
  local metrics_json="$6"
  local status="$7"
  local extra="$8"

  "$PYTHON_BIN" - "$tool" "$case_id" "$files" "$run_id" "$runtime_s" "$metrics_json" "$status" "$extra" "$CSV" <<'PY'
import csv
import json
import sys

tool, case_id, files, run_id, runtime_s, metrics_json, status, extra, csv_path = sys.argv[1:]

precision = ""
recall = ""
f1 = ""

if status == "ok":
    try:
        with open(metrics_json, "r", encoding="utf-8") as f:
            metrics = json.load(f)
        score = metrics.get("strict_path_content") or {}
        precision = score.get("precision", "")
        recall = score.get("recall", "")
        f1 = score.get("f1", "")
    except Exception as exc:
        status = "metric_fail"
        extra = str(exc)

row = {
    "tool": tool,
    "case": case_id,
    "files": files,
    "run": run_id,
    "runtime_s": runtime_s,
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "status": status,
    "extra": extra,
}

with open(csv_path, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "tool", "case", "files", "run", "runtime_s",
            "precision", "recall", "f1", "status", "extra"
        ],
    )
    writer.writerow(row)
PY
}

score_smbmount_only() {
  local ground_truth="$1"
  local out_json="$2"
  local out_dir="$3"

  mkdir -p "$out_dir"

  "$PYTHON_BIN" - "$ground_truth" "$out_json" "$out_dir" <<'PY'
import json
import sys
from pathlib import Path

from smbmount.benchmark_parsepcap.metrics import score_versions
from smbmount.benchmark_parsepcap.normalize_ours import normalize_ours

ground_truth_path, ours_json_path, out_dir = sys.argv[1:]
out = Path(out_dir)

with open(ground_truth_path, "r", encoding="utf-8") as f:
    ground_truth = json.load(f)

ours_norm = normalize_ours(ours_json_path)
metrics = score_versions(ground_truth, ours_norm)

with (out / "ours_normalized.json").open("w", encoding="utf-8") as f:
    json.dump(ours_norm, f, indent=2, ensure_ascii=False)

with (out / "ours_metrics.json").open("w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2, ensure_ascii=False)
PY
}

run_one_repeat() {
  local case_id="$1"
  local files="$2"
  local pcap="$3"
  local ground_truth="$4"
  local scenario_dir="$5"
  local run_id="$6"

  local out_json="$JSON_DIR/${case_id}_run${run_id}.json"
  local smb_log="$LOG_DIR/${case_id}_smbmount_run${run_id}.log"
  local pcapfs_log="$LOG_DIR/${case_id}_pcapfs_run${run_id}.log"
  local bench_out="$BENCH_DIR/${case_id}_run${run_id}"

  local smb_start
  local smb_end
  local smb_runtime
  local pcapfs_start
  local pcapfs_end
  local pcapfs_runtime
  local pcapfs_exit_file="$LOG_DIR/${case_id}_pcapfs_run${run_id}.exit"

  rm -rf "$bench_out"
  rm -f "$out_json"
  rm -f "$pcapfs_exit_file"

  echo "    [smbmount] parse run $run_id"
  smb_start="$(now_ns)"

  if "$PYTHON_BIN" -m smbmount parse-pcap \
      "$pcap" \
      "$out_json" \
      --timestamp-mode "$TIMESTAMP_MODE" \
      --reader "$READER" \
      >"$smb_log" 2>&1; then

    smb_end="$(now_ns)"
    smb_runtime="$(elapsed_sec "$smb_start" "$smb_end")"
  else
    smb_end="$(now_ns)"
    smb_runtime="$(elapsed_sec "$smb_start" "$smb_end")"

    append_metric_row \
      "smbmount" "$case_id" "$files" "$run_id" "$smb_runtime" \
      "" "fail" "$smb_log"

    return
  fi

  if [[ "$TOOL_MODE" == "smbmount" ]]; then
    if score_smbmount_only "$ground_truth" "$out_json" "$bench_out"; then
      append_metric_row \
        "smbmount" "$case_id" "$files" "$run_id" "$smb_runtime" \
        "$bench_out/ours_metrics.json" "ok" "$out_json"
    else
      append_metric_row \
        "smbmount" "$case_id" "$files" "$run_id" "$smb_runtime" \
        "" "benchmark_fail" "$bench_out"
    fi

    return
  fi

  echo "    [pcapFS] mount + normalize/hash + score run $run_id"

  cleanup_pcapfs_mount "$PCAPFS_MOUNT"
  rm -rf "$PCAPFS_MOUNT"
  mkdir -p "$PCAPFS_MOUNT"

  pcapfs_start="$(now_ns)"

  (
    set +e
    pcapfs \
      --timestamp-mode "$TIMESTAMP_MODE" \
      --show-metadata \
      -f \
      "$pcap" \
      "$PCAPFS_MOUNT"
    echo "$?" > "$pcapfs_exit_file"
  ) >"$pcapfs_log" 2>&1 &

  local pcapfs_pid=$!
  CURRENT_PCAPFS_PID="$pcapfs_pid"

  if ! wait_for_mount_ready "$PCAPFS_MOUNT" "$pcapfs_pid"; then
    pcapfs_end="$(now_ns)"
    pcapfs_runtime="$(elapsed_sec "$pcapfs_start" "$pcapfs_end")"
    local pcapfs_exit="unknown"

    if [[ -f "$pcapfs_exit_file" ]]; then
      pcapfs_exit="$(cat "$pcapfs_exit_file")"
    fi

    append_metric_row \
      "smbmount" "$case_id" "$files" "$run_id" "$smb_runtime" \
      "" "benchmark_skipped" "pcapFS mount failed exit=$pcapfs_exit"

    append_metric_row \
      "pcapFS" "$case_id" "$files" "$run_id" "$pcapfs_runtime" \
      "" "mount_failed" "$pcapfs_log exit=$pcapfs_exit"

    cleanup_pcapfs_mount "$PCAPFS_MOUNT"
    kill "$pcapfs_pid" 2>/dev/null || true
    wait "$pcapfs_pid" 2>/dev/null || true
    CURRENT_PCAPFS_PID=""
    return
  fi

  if "$PYTHON_BIN" -m "$BENCH_MODULE" \
      --ground-truth "$ground_truth" \
      --ours-json "$out_json" \
      --pcapfs-root "$PCAPFS_MOUNT" \
      --scenario-dir "$scenario_dir" \
      --out "$bench_out" \
      >>"$pcapfs_log" 2>&1; then

    pcapfs_end="$(now_ns)"
    pcapfs_runtime="$(elapsed_sec "$pcapfs_start" "$pcapfs_end")"

    append_metric_row \
      "smbmount" "$case_id" "$files" "$run_id" "$smb_runtime" \
      "$bench_out/ours_metrics.json" "ok" "$out_json"

    append_metric_row \
      "pcapFS" "$case_id" "$files" "$run_id" "$pcapfs_runtime" \
      "$bench_out/pcapfs_metrics.json" "ok" "$PCAPFS_MOUNT"
  else
    pcapfs_end="$(now_ns)"
    pcapfs_runtime="$(elapsed_sec "$pcapfs_start" "$pcapfs_end")"

    append_metric_row \
      "smbmount" "$case_id" "$files" "$run_id" "$smb_runtime" \
      "" "benchmark_fail" "$bench_out"

    append_metric_row \
      "pcapFS" "$case_id" "$files" "$run_id" "$pcapfs_runtime" \
      "" "benchmark_fail" "$pcapfs_log"
  fi

  cleanup_pcapfs_mount "$PCAPFS_MOUNT"
  kill "$pcapfs_pid" 2>/dev/null || true
  wait "$pcapfs_pid" 2>/dev/null || true
  CURRENT_PCAPFS_PID=""
}

run_case() {
  local case_id="$1"
  local files="$2"
  local pcap="$3"
  local ground_truth="$4"
  local scenario_dir="$5"

  pcap="$(abspath "$pcap")"
  ground_truth="$(abspath "$ground_truth")"

  if [[ ! -f "$pcap" ]]; then
    echo "[SKIP] Missing PCAP: $pcap"
    return
  fi

  if [[ ! -f "$ground_truth" ]]; then
    echo "[SKIP] Missing ground truth: $ground_truth"
    return
  fi

  echo
  echo "[CASE] $case_id"
  echo "  Files: $files"
  echo "  PCAP: $pcap"
  echo "  Ground truth: $ground_truth"
  echo "  Scenario dir: $scenario_dir"
  echo "  Repeats: $REPEATS"

  for run_id in $(seq 1 "$REPEATS"); do
    run_one_repeat \
      "$case_id" \
      "$files" \
      "$pcap" \
      "$ground_truth" \
      "$scenario_dir" \
      "$run_id"
  done
}

print_summary() {
  "$PYTHON_BIN" - "$CSV" <<'PY'
import csv
import statistics
import sys
from collections import defaultdict

path = sys.argv[1]
rows = []

with open(path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row["status"] != "ok":
            continue
        for key in ("runtime_s", "precision", "recall", "f1"):
            row[key] = float(row[key])
        row["files"] = int(row["files"])
        rows.append(row)

groups = defaultdict(list)
for row in rows:
    groups[(row["tool"], row["case"], row["files"])].append(row)

def mean_std(values):
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return statistics.mean(values), 0.0
    return statistics.mean(values), statistics.stdev(values)

print()
print("Repeated benchmark summary")
print("=" * 130)
print(
    f"{'tool':<10} {'case':<22} {'files':>7} {'runs':>5} "
    f"{'runtime_mean':>14} {'runtime_std':>12} "
    f"{'precision_mean':>15} {'precision_std':>13} "
    f"{'recall_mean':>12} {'recall_std':>10} "
    f"{'f1_mean':>10} {'f1_std':>10}"
)
print("-" * 130)

for (tool, case, files), items in sorted(groups.items(), key=lambda x: (x[0][1], x[0][0])):
    runtime_mean, runtime_std = mean_std([x["runtime_s"] for x in items])
    precision_mean, precision_std = mean_std([x["precision"] for x in items])
    recall_mean, recall_std = mean_std([x["recall"] for x in items])
    f1_mean, f1_std = mean_std([x["f1"] for x in items])

    print(
        f"{tool:<10} {case:<22} {files:>7} {len(items):>5} "
        f"{runtime_mean:>14.4f} {runtime_std:>12.4f} "
        f"{precision_mean:>15.4f} {precision_std:>13.4f} "
        f"{recall_mean:>12.4f} {recall_std:>10.4f} "
        f"{f1_mean:>10.4f} {f1_std:>10.4f}"
    )

failed = []
with open(path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row["status"] != "ok":
            failed.append(row)

print()
print("Failed / skipped runs")
print("-" * 130)
if not failed:
    print("None")
else:
    for row in failed:
        print(row)
PY
}

if [[ "$TOOL_MODE" != "smbmount" ]]; then
  require_cmd mountpoint
  require_cmd pcapfs
fi

case "$TOOL_MODE" in
  smbmount|pcapfs|both) ;;
  *) echo "[ERROR] --tool must be smbmount, pcapfs, or both" >&2; exit 2 ;;
esac
mkdir -p "$OUT_DIR" "$JSON_DIR" "$LOG_DIR" "$BENCH_DIR"

LOCK_FILE="$OUT_DIR/.measure_runtime.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[ERROR] Another measure_runtime.sh is already running for OUT_DIR=$OUT_DIR" >&2
  exit 1
fi

trap cleanup_on_exit EXIT INT TERM

echo "tool,case,files,run,runtime_s,precision,recall,f1,status,extra" > "$CSV"

cd "$ROOT_DIR"

if [[ -n "$CASE_FILE" ]]; then
  while IFS=$'\t' read -r case_id files pcap ground_truth scenario_dir; do
    [[ -z "${case_id:-}" || "${case_id:0:1}" == "#" ]] && continue
    run_case "$case_id" "$files" "$pcap" "$ground_truth" "$scenario_dir"
  done < "$CASE_FILE"
else
  run_case "$CASE_ID" "$FILES" "$PCAP" "$GROUND_TRUTH" "$SCENARIO_DIR"
fi

echo
echo "[OK] CSV: $CSV"
print_summary
