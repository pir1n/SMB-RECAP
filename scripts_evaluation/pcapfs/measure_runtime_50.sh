#!/usr/bin/env bash
set -euo pipefail

REPEATS="${REPEATS:-5}"

PCAP_DIR="${PCAP_DIR:-data/pcaps/benchmark_parse-pcap}"
GT_DIR="${GT_DIR:-data/gt_parse-pcap}"

OUT_DIR="${OUT_DIR:-outputs/repeated_benchmark}"
JSON_DIR="$OUT_DIR/json"
LOG_DIR="$OUT_DIR/logs"
BENCH_DIR="$OUT_DIR/benchmark"

PCAPFS_MOUNT="${PCAPFS_MOUNT:-/tmp/pcapfs_mount}"

# Nếu package của bạn là smbmount.benchmark.cli thì đổi env BENCH_MODULE.
BENCH_MODULE="${BENCH_MODULE:-smbmount.pcapfs.benchmark.cli}"

if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    PYTHON_BIN="$PWD/.venv/bin/python"
  else
    PYTHON_BIN="python"
  fi
fi

mkdir -p "$OUT_DIR" "$JSON_DIR" "$LOG_DIR" "$BENCH_DIR"

LOCK_FILE="$OUT_DIR/.measure_runtime.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[ERROR] Another measure_runtime.sh is already running for OUT_DIR=$OUT_DIR" >&2
  echo "        Stop it first, or use a different OUT_DIR." >&2
  exit 1
fi

CSV="$OUT_DIR/runtime_metrics.csv"
echo "tool,case,files,run,runtime_s,precision,recall,f1,status,extra" > "$CSV"

CURRENT_PCAPFS_PID=""

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
  if [[ -n "${CURRENT_PCAPFS_PID:-}" ]]; then
    kill "$CURRENT_PCAPFS_PID" 2>/dev/null || true
    wait "$CURRENT_PCAPFS_PID" 2>/dev/null || true
    CURRENT_PCAPFS_PID=""
  fi

  cleanup_pcapfs_mount "$PCAPFS_MOUNT"
}

trap cleanup_on_exit EXIT INT TERM

wait_for_mount_ready() {
  local mount_dir="$1"
  local pid="$2"

  local waited=0

  while true; do
    if mountpoint -q "$mount_dir" 2>/dev/null; then
      return 0
    fi

    # Nếu pcapFS chết trước khi mount được thì fail thật,
    # không phải timeout.
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi

    sleep 1
    waited=$((waited + 1))

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

run_one_repeat() {
  local case_id="$1"
  local files="$2"
  local pcap_file="$3"
  local gt_file="$4"
  local scenario_dir="$5"
  local run_id="$6"

  local pcap="$PCAP_DIR/$pcap_file"
  local gt="$GT_DIR/$gt_file"

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

  rm -rf "$bench_out"
  rm -f "$out_json"

  echo "    [smbmount] parse run $run_id"

  smb_start="$(now_ns)"

  if "$PYTHON_BIN" -m smbmount parse-pcap \
      "$pcap" \
      "$out_json" \
      --timestamp-mode network \
      >"$smb_log" 2>&1; then

    smb_end="$(now_ns)"
    smb_runtime="$(elapsed_sec "$smb_start" "$smb_end")"
    smb_status="ok"
    smb_extra="$out_json"
  else
    smb_end="$(now_ns)"
    smb_runtime="$(elapsed_sec "$smb_start" "$smb_end")"
    smb_status="fail"
    smb_extra="$smb_log"

    append_metric_row \
      "smbmount" "$case_id" "$files" "$run_id" "$smb_runtime" \
      "" "$smb_status" "$smb_extra"

    return
  fi

  echo "    [pcapFS] mount + normalize/hash + score run $run_id"

  cleanup_pcapfs_mount "$PCAPFS_MOUNT"
  rm -rf "$PCAPFS_MOUNT"
  mkdir -p "$PCAPFS_MOUNT"

  pcapfs_start="$(now_ns)"

  pcapfs \
    --timestamp-mode network \
    --show-metadata \
    -f \
    "$pcap" \
    "$PCAPFS_MOUNT" \
    >"$pcapfs_log" 2>&1 &

  local pcapfs_pid=$!
  CURRENT_PCAPFS_PID="$pcapfs_pid"

  if ! wait_for_mount_ready "$PCAPFS_MOUNT" "$pcapfs_pid"; then
    pcapfs_end="$(now_ns)"
    pcapfs_runtime="$(elapsed_sec "$pcapfs_start" "$pcapfs_end")"
    local pcapfs_exit="unknown"

    if ! kill -0 "$pcapfs_pid" 2>/dev/null; then
      if wait "$pcapfs_pid" 2>/dev/null; then
        pcapfs_exit="0"
      else
        pcapfs_exit="$?"
      fi
    fi

    {
      echo
      echo "[measure_runtime] pcapFS exited before mount became ready"
      echo "[measure_runtime] exit_code=$pcapfs_exit"
      echo "[measure_runtime] mountpoint=$PCAPFS_MOUNT"
      echo "[measure_runtime] pcap=$pcap"
    } >>"$pcapfs_log"

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
      --ground-truth "$gt" \
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
  local pcap_file="$3"
  local gt_file="$4"
  local scenario_dir="$5"

  local pcap="$PCAP_DIR/$pcap_file"
  local gt="$GT_DIR/$gt_file"

  if [[ ! -f "$pcap" ]]; then
    echo "[SKIP] Missing PCAP: $pcap"
    return
  fi

  if [[ ! -f "$gt" ]]; then
    echo "[SKIP] Missing ground truth: $gt"
    return
  fi

  echo
  echo "[CASE] $case_id"
  echo "  Files: $files"
  echo "  PCAP: $pcap"
  echo "  GT: $gt"
  echo "  Scenario dir: $scenario_dir"

  for run_id in $(seq 1 "$REPEATS"); do
    run_one_repeat \
      "$case_id" \
      "$files" \
      "$pcap_file" \
      "$gt_file" \
      "$scenario_dir" \
      "$run_id"
  done
}

run_case \
  "scale_0050_mixed" \
  "50" \
  "scale_0050_mixed.pcapng" \
  "scale_0050_mixed.json" \
  "bench_scale_0050_mixed"

echo
echo "[OK] CSV: $CSV"

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
        return "", ""
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
