#!/usr/bin/env bash
set -euo pipefail

# Loss benchmark workflow:
# 1) python scripts/make_loss_pcaps_editcap.py --input data/pcaps/benchmark_parse-pcap/scale_1000_mixed.pcapng --out-dir data/pcaps/benchmark_parse-pcap --seed 1337
# 2) OUT_DIR=outputs/loss_benchmark REPEATS=5 bash scripts/run_loss_benchmark.sh
# 3) python scripts/plot_loss_benchmark.py --runtime-csv outputs/loss_benchmark/runtime_metrics.csv --robustness-csv outputs/loss_benchmark/robustness/robustness_summary.csv --out-dir outputs/loss_benchmark/plots

REPEATS="${REPEATS:-5}"

PCAP_DIR="${PCAP_DIR:-data/pcaps/benchmark_parse-pcap}"
GT_FILE="${GT_FILE:-data/gt_parse-pcap/scale_1000_mixed.json}"
SCENARIO_DIR="${SCENARIO_DIR:-bench_scale_1000_mixed}"

OUT_DIR="${OUT_DIR:-outputs/loss_benchmark}"
JSON_DIR="$OUT_DIR/json"
LOG_DIR="$OUT_DIR/logs"
BENCH_DIR="$OUT_DIR/benchmark"
ROBUST_DIR="$OUT_DIR/robustness"

PCAPFS_MOUNT="${PCAPFS_MOUNT:-/tmp/pcapfs_mount}"
PCAPFS_MOUNT_TIMEOUT_SECONDS="${PCAPFS_MOUNT_TIMEOUT_SECONDS:-0}"
BENCH_MODULE="${BENCH_MODULE:-smbmount.benchmark_parsepcap.cli}"

if [[ -z "${PYTHON_BIN:-}" ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    PYTHON_BIN="$PWD/.venv/bin/python"
  else
    PYTHON_BIN="python"
  fi
fi

mkdir -p "$OUT_DIR" "$JSON_DIR" "$LOG_DIR" "$BENCH_DIR" "$ROBUST_DIR"

LOCK_FILE="$OUT_DIR/.run_loss_benchmark.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[ERROR] Another run_loss_benchmark.sh is already running for OUT_DIR=$OUT_DIR" >&2
  exit 1
fi

CSV="$OUT_DIR/runtime_metrics.csv"
ROBUST_CSV="$ROBUST_DIR/robustness_summary.csv"

echo "tool,case,files,run,runtime_s,precision,recall,f1,status,extra" > "$CSV"
rm -f "$ROBUST_CSV"

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

    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi

    sleep 1
    waited=$((waited + 1))

    if (( waited % 30 == 0 )); then
      echo "      waiting for pcapFS mount... ${waited}s"
    fi

    if (
      ((${PCAPFS_MOUNT_TIMEOUT_SECONDS:-0} > 0)) \
      && ((waited >= PCAPFS_MOUNT_TIMEOUT_SECONDS))
    ); then
      echo "      pcapFS mount timeout after ${waited}s"
      return 2
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
        fieldnames=["tool", "case", "files", "run", "runtime_s", "precision", "recall", "f1", "status", "extra"],
    )
    writer.writerow(row)
PY
}

run_robustness() {
  local case_id="$1"
  local run_id="$2"
  local out_json="$3"

  "$PYTHON_BIN" scripts/robustness_report.py \
    --ground-truth "$GT_FILE" \
    --prediction-json "$out_json" \
    --case "$case_id" \
    --condition "${case_id}/run${run_id}" \
    --out-csv "$ROBUST_CSV" \
    --details-json "$ROBUST_DIR/${case_id}_run${run_id}.json" \
    >"$LOG_DIR/${case_id}_robustness_run${run_id}.log" 2>&1
}

run_one_repeat() {
  local case_id="$1"
  local pcap_file="$2"
  local run_id="$3"

  local pcap="$PCAP_DIR/$pcap_file"
  local out_json="$JSON_DIR/${case_id}_run${run_id}.json"
  local smb_log="$LOG_DIR/${case_id}_smbmount_run${run_id}.log"
  local pcapfs_log="$LOG_DIR/${case_id}_pcapfs_run${run_id}.log"
  local bench_out="$BENCH_DIR/${case_id}_run${run_id}"

  local smb_start smb_end smb_runtime
  local pcapfs_start pcapfs_end pcapfs_runtime

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
  else
    smb_end="$(now_ns)"
    smb_runtime="$(elapsed_sec "$smb_start" "$smb_end")"
    append_metric_row "smbmount" "$case_id" "1000" "$run_id" "$smb_runtime" "" "fail" "$smb_log"
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

  local mount_wait_status=0
  wait_for_mount_ready "$PCAPFS_MOUNT" "$pcapfs_pid" || mount_wait_status=$?

  if (( mount_wait_status != 0 )); then
    pcapfs_end="$(now_ns)"
    pcapfs_runtime="$(elapsed_sec "$pcapfs_start" "$pcapfs_end")"
    echo "[run_loss_benchmark] pcapFS mount failed wait_status=$mount_wait_status" >>"$pcapfs_log"
    append_metric_row "smbmount" "$case_id" "1000" "$run_id" "$smb_runtime" "" "benchmark_skipped" "pcapFS mount failed"
    append_metric_row "pcapFS" "$case_id" "1000" "$run_id" "$pcapfs_runtime" "" "mount_failed" "$pcapfs_log"
    cleanup_pcapfs_mount "$PCAPFS_MOUNT"
    kill "$pcapfs_pid" 2>/dev/null || true
    wait "$pcapfs_pid" 2>/dev/null || true
    CURRENT_PCAPFS_PID=""
    run_robustness "$case_id" "$run_id" "$out_json"
    return
  fi

  if "$PYTHON_BIN" -m "$BENCH_MODULE" \
      --ground-truth "$GT_FILE" \
      --ours-json "$out_json" \
      --pcapfs-root "$PCAPFS_MOUNT" \
      --scenario-dir "$SCENARIO_DIR" \
      --out "$bench_out" \
      >>"$pcapfs_log" 2>&1; then
    pcapfs_end="$(now_ns)"
    pcapfs_runtime="$(elapsed_sec "$pcapfs_start" "$pcapfs_end")"
    append_metric_row "smbmount" "$case_id" "1000" "$run_id" "$smb_runtime" "$bench_out/ours_metrics.json" "ok" "$out_json"
    append_metric_row "pcapFS" "$case_id" "1000" "$run_id" "$pcapfs_runtime" "$bench_out/pcapfs_metrics.json" "ok" "$PCAPFS_MOUNT"
  else
    pcapfs_end="$(now_ns)"
    pcapfs_runtime="$(elapsed_sec "$pcapfs_start" "$pcapfs_end")"
    append_metric_row "smbmount" "$case_id" "1000" "$run_id" "$smb_runtime" "" "benchmark_fail" "$bench_out"
    append_metric_row "pcapFS" "$case_id" "1000" "$run_id" "$pcapfs_runtime" "" "benchmark_fail" "$pcapfs_log"
  fi

  cleanup_pcapfs_mount "$PCAPFS_MOUNT"
  kill "$pcapfs_pid" 2>/dev/null || true
  wait "$pcapfs_pid" 2>/dev/null || true
  CURRENT_PCAPFS_PID=""

  run_robustness "$case_id" "$run_id" "$out_json"
}

run_case() {
  local case_id="$1"
  local pcap_file="$2"
  local pcap="$PCAP_DIR/$pcap_file"

  if [[ ! -f "$pcap" ]]; then
    echo "[SKIP] Missing PCAP: $pcap"
    return
  fi

  echo
  echo "[CASE] $case_id"
  echo "  PCAP: $pcap"
  echo "  GT: $GT_FILE"
  echo "  Scenario dir: $SCENARIO_DIR"

  for run_id in $(seq 1 "$REPEATS"); do
    run_one_repeat "$case_id" "$pcap_file" "$run_id"
  done
}

run_case "scale_1000_mixed_loss_01" "scale_1000_mixed_loss_01.pcapng"
run_case "scale_1000_mixed_loss_05" "scale_1000_mixed_loss_05.pcapng"
run_case "scale_1000_mixed_loss_10" "scale_1000_mixed_loss_10.pcapng"

echo
echo "[OK] Runtime CSV: $CSV"
echo "[OK] Robustness CSV: $ROBUST_CSV"
