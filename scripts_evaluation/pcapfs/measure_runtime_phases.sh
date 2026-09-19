#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PCAP_DIR="${PCAP_DIR:-$ROOT_DIR/data/pcaps/benchmark_parse-pcap}"
GT_DIR="${GT_DIR:-$ROOT_DIR/data/gt_parse-pcap}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/outputs/phase_runtime_benchmark}"
MOUNT_ROOT="${MOUNT_ROOT:-/tmp/smbmount_phase_runtime}"
REPEATS="${REPEATS:-5}"
TIMESTAMP_MODE="${TIMESTAMP_MODE:-network}"
READER="${READER:-streaming}"
TOOL_MODE="${TOOL_MODE:-both}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-0}"
PROGRESS_INTERVAL_SECONDS="${PROGRESS_INTERVAL_SECONDS:-30}"
CASE_FILE="${CASE_FILE:-}"
PCAPFS_COMMAND_TEMPLATE="${PCAPFS_COMMAND_TEMPLATE:-}"
SMBMOUNT_COMMAND_TEMPLATE="${SMBMOUNT_COMMAND_TEMPLATE:-}"

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
  scripts/eval_parsepcap/measure_runtime_phases.sh [options]

Purpose:
  Measure comparable runtime phases for SMBmount and pcapFS:
    start_to_mount_ready, export, hash, scoring, post_mount, end_to_end.
  SMBmount additionally records internal parse/reconstruct/mount_prepare timing.

Default cases:
  scale_0500_mixed, scale_1000_mixed, scale_5000_mixed

Options:
  --case-file PATH          TSV: case_id<TAB>files<TAB>pcap<TAB>ground_truth<TAB>scenario_dir.
  --repeats N               Repetitions per case. Default: 5.
  --out-dir PATH            Output directory. Default: outputs/phase_runtime_benchmark.
  --mount-root PATH         Temporary mount root. Default: /tmp/smbmount_phase_runtime.
  --timeout SECONDS         Per tool mount-ready timeout. Use 0 for no timeout. Default: 0.
  --timestamp-mode MODE     network, fs, or hybrid. Default: network.
  --reader MODE             streaming or legacy for SMBmount. Default: streaming.
  --tool MODE               smbmount, pcapfs, or both. Default: both.
  --progress-interval N     Print live elapsed seconds every N seconds. Default: 30.
  --python-bin PATH         Python executable.
  --smbmount-command CMD    Override SMBmount command template. Use {pcap}, {mountpoint}.
  --pcapfs-command CMD      Override pcapFS command template. Use {pcap}, {mountpoint}.
  -h, --help                Show this help.

Outputs:
  runtime_phase_metrics.csv
  runtime_phase_speedups.csv
  runtime_phase_summary.csv
  runtime_phase_speedup_summary.csv
  runs/<case>/run_<N>/<tool>/runtime.json
  runs/<case>/run_<N>/comparison/runtime_comparison.{json,md}

Environment overrides:
  PCAP_DIR, GT_DIR, OUT_DIR, MOUNT_ROOT, REPEATS, TIMEOUT_SECONDS,
  PROGRESS_INTERVAL_SECONDS, TIMESTAMP_MODE, READER, TOOL_MODE,
  PYTHON_BIN, CASE_FILE, SMBMOUNT_COMMAND_TEMPLATE, PCAPFS_COMMAND_TEMPLATE
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case-file) CASE_FILE="$2"; shift 2 ;;
    --repeats) REPEATS="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --mount-root) MOUNT_ROOT="$2"; shift 2 ;;
    --timeout) TIMEOUT_SECONDS="$2"; shift 2 ;;
    --timestamp-mode) TIMESTAMP_MODE="$2"; shift 2 ;;
    --reader) READER="$2"; shift 2 ;;
    --tool) TOOL_MODE="$2"; shift 2 ;;
    --progress-interval) PROGRESS_INTERVAL_SECONDS="$2"; shift 2 ;;
    --python-bin) PYTHON_BIN="$2"; shift 2 ;;
    --smbmount-command) SMBMOUNT_COMMAND_TEMPLATE="$2"; shift 2 ;;
    --pcapfs-command) PCAPFS_COMMAND_TEMPLATE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$TOOL_MODE" in
  smbmount|pcapfs|both) ;;
  *) echo "[ERROR] --tool must be smbmount, pcapfs, or both" >&2; exit 2 ;;
esac

if [[ "$TOOL_MODE" != "smbmount" ]] && ! command -v pcapfs >/dev/null 2>&1; then
  echo "[ERROR] Missing command: pcapfs" >&2
  exit 1
fi

mkdir -p "$OUT_DIR" "$MOUNT_ROOT"
PHASE_CSV="$OUT_DIR/runtime_phase_metrics.csv"
SPEEDUP_CSV="$OUT_DIR/runtime_phase_speedups.csv"
PHASE_SUMMARY_CSV="$OUT_DIR/runtime_phase_summary.csv"
SPEEDUP_SUMMARY_CSV="$OUT_DIR/runtime_phase_speedup_summary.csv"
LOCK_FILE="$OUT_DIR/.measure_runtime_phases.lock"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[ERROR] Another phase runtime benchmark is already running for OUT_DIR=$OUT_DIR" >&2
  exit 1
fi

cleanup_mounts() {
  find "$MOUNT_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | while read -r mount_dir; do
    if mountpoint -q "$mount_dir" 2>/dev/null; then
      fusermount3 -u "$mount_dir" 2>/dev/null \
        || fusermount -u "$mount_dir" 2>/dev/null \
        || umount -l "$mount_dir" 2>/dev/null \
        || true
    fi
  done
}

trap cleanup_mounts EXIT INT TERM

elapsed_seconds() {
  local started_epoch="$1"
  local now_epoch
  now_epoch="$(date +%s)"
  echo $((now_epoch - started_epoch))
}

write_headers() {
  echo "tool,case,files,run,run_started_at,tool_started_at,tool_finished_at,status,mount_ready,strict_path_content_f1,start_to_mount_ready_s,export_s,hash_s,scoring_s,post_mount_s,end_to_end_s,parse_s,reconstruct_s,mount_prepare_s,internal_total_s,runtime_json,extra" > "$PHASE_CSV"
  echo "case,files,run,run_started_at,phase,smbmount_s,pcapfs_s,speedup_pcapfs_over_smbmount" > "$SPEEDUP_CSV"
}

append_runtime_row() {
  local case_id="$1"
  local files="$2"
  local run_id="$3"
  local run_started_at="$4"
  local runtime_json="$5"

  "$PYTHON_BIN" - "$case_id" "$files" "$run_id" "$run_started_at" "$runtime_json" "$PHASE_CSV" <<'PY'
import csv
import json
import sys

case_id, files, run_id, run_started_at, runtime_json, csv_path = sys.argv[1:]

with open(runtime_json, "r", encoding="utf-8") as f:
    runtime = json.load(f)

external = runtime.get("external") or {}
internal = runtime.get("internal") or {}
correctness = runtime.get("correctness") or {}

row = {
    "tool": runtime.get("tool", ""),
    "case": case_id,
    "files": files,
    "run": run_id,
    "run_started_at": run_started_at,
    "tool_started_at": runtime.get("started_at", ""),
    "tool_finished_at": runtime.get("finished_at", ""),
    "status": runtime.get("status", ""),
    "mount_ready": runtime.get("mount_ready", ""),
    "strict_path_content_f1": correctness.get("strict_path_content_f1", ""),
    "start_to_mount_ready_s": external.get("start_to_mount_ready_seconds", ""),
    "export_s": external.get("export_seconds", ""),
    "hash_s": external.get("hash_seconds", ""),
    "scoring_s": external.get("scoring_seconds", ""),
    "post_mount_s": external.get("post_mount_seconds", ""),
    "end_to_end_s": external.get("end_to_end_seconds", ""),
    "parse_s": internal.get("parse_seconds", ""),
    "reconstruct_s": internal.get("reconstruct_seconds", ""),
    "mount_prepare_s": internal.get("mount_prepare_seconds", ""),
    "internal_total_s": internal.get("internal_total_seconds", ""),
    "runtime_json": runtime_json,
    "extra": runtime.get("error", "") or runtime.get("timeout_seconds", ""),
}

fieldnames = [
    "tool", "case", "files", "run", "run_started_at", "tool_started_at",
    "tool_finished_at", "status", "mount_ready",
    "strict_path_content_f1", "start_to_mount_ready_s", "export_s", "hash_s",
    "scoring_s", "post_mount_s", "end_to_end_s", "parse_s", "reconstruct_s",
    "mount_prepare_s", "internal_total_s", "runtime_json", "extra",
]

with open(csv_path, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writerow(row)
PY
}

append_speedup_rows() {
  local case_id="$1"
  local files="$2"
  local run_id="$3"
  local run_started_at="$4"
  local comparison_json="$5"

  "$PYTHON_BIN" - "$case_id" "$files" "$run_id" "$run_started_at" "$comparison_json" "$SPEEDUP_CSV" <<'PY'
import csv
import json
import sys

case_id, files, run_id, run_started_at, comparison_json, csv_path = sys.argv[1:]

with open(comparison_json, "r", encoding="utf-8") as f:
    comparison = json.load(f)

smb_external = (comparison.get("smbmount") or {}).get("external") or {}
pcap_external = (comparison.get("pcapfs") or {}).get("external") or {}
speedups = comparison.get("speedups") or {}

labels = {
    "start_to_mount_ready_seconds": "start_to_mount_ready",
    "export_seconds": "export",
    "hash_seconds": "hash",
    "scoring_seconds": "scoring",
    "post_mount_seconds": "post_mount",
    "end_to_end_seconds": "end_to_end",
}

with open(csv_path, "a", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "case", "files", "run", "run_started_at", "phase", "smbmount_s",
            "pcapfs_s", "speedup_pcapfs_over_smbmount",
        ],
    )

    for key, label in labels.items():
        writer.writerow({
            "case": case_id,
            "files": files,
            "run": run_id,
            "run_started_at": run_started_at,
            "phase": label,
            "smbmount_s": smb_external.get(key, ""),
            "pcapfs_s": pcap_external.get(key, ""),
            "speedup_pcapfs_over_smbmount": speedups.get(key, ""),
        })
PY
}

write_summaries() {
  "$PYTHON_BIN" - "$PHASE_CSV" "$SPEEDUP_CSV" "$PHASE_SUMMARY_CSV" "$SPEEDUP_SUMMARY_CSV" <<'PY'
import csv
import statistics
import sys
from collections import defaultdict

phase_csv, speedup_csv, phase_summary_csv, speedup_summary_csv = sys.argv[1:]


def parse_float(value):
    if value in ("", None):
        return None
    try:
        return float(value)
    except Exception:
        return None


def mean_std(values):
    values = [value for value in values if value is not None]
    if not values:
        return "", ""
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)


phase_fields = [
    "strict_path_content_f1",
    "start_to_mount_ready_s",
    "export_s",
    "hash_s",
    "scoring_s",
    "post_mount_s",
    "end_to_end_s",
    "parse_s",
    "reconstruct_s",
    "mount_prepare_s",
    "internal_total_s",
]

phase_rows = []
with open(phase_csv, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row.get("status") != "success":
            continue
        for field in phase_fields:
            row[field] = parse_float(row.get(field))
        phase_rows.append(row)

phase_groups = defaultdict(list)
for row in phase_rows:
    phase_groups[(row["tool"], row["case"], row["files"])].append(row)

phase_summary_fields = ["tool", "case", "files", "runs"]
for field in phase_fields:
    phase_summary_fields.extend([f"{field}_mean", f"{field}_std"])

with open(phase_summary_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=phase_summary_fields)
    writer.writeheader()
    for (tool, case, files), rows in sorted(phase_groups.items(), key=lambda x: (x[0][1], x[0][0])):
        item = {"tool": tool, "case": case, "files": files, "runs": len(rows)}
        for field in phase_fields:
            mean, std = mean_std(row[field] for row in rows)
            item[f"{field}_mean"] = mean
            item[f"{field}_std"] = std
        writer.writerow(item)

speedup_fields = ["smbmount_s", "pcapfs_s", "speedup_pcapfs_over_smbmount"]
speedup_rows = []
with open(speedup_csv, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        for field in speedup_fields:
            row[field] = parse_float(row.get(field))
        speedup_rows.append(row)

speedup_groups = defaultdict(list)
for row in speedup_rows:
    speedup_groups[(row["case"], row["files"], row["phase"])].append(row)

speedup_summary_fields = ["case", "files", "phase", "runs"]
for field in speedup_fields:
    speedup_summary_fields.extend([f"{field}_mean", f"{field}_std"])

with open(speedup_summary_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=speedup_summary_fields)
    writer.writeheader()
    for (case, files, phase), rows in sorted(speedup_groups.items(), key=lambda x: (x[0][0], x[0][2])):
        item = {"case": case, "files": files, "phase": phase, "runs": len(rows)}
        for field in speedup_fields:
            mean, std = mean_std(row[field] for row in rows)
            item[f"{field}_mean"] = mean
            item[f"{field}_std"] = std
        writer.writerow(item)
PY
}

run_tool() {
  local tool="$1"
  local case_id="$2"
  local files="$3"
  local run_id="$4"
  local run_started_at="$5"
  local pcap="$6"
  local ground_truth="$7"
  local scenario_dir="$8"
  local run_dir="$9"
  local mountpoint="${10}"
  local command_template="${11}"

  rm -rf "$mountpoint"
  mkdir -p "$mountpoint"

  local args=(
    "$PYTHON_BIN" -m smbmount.pcapfs.benchmark.runtime "run-$tool"
    --pcap "$pcap"
    --ground-truth "$ground_truth"
    --mountpoint "$mountpoint"
    --out "$run_dir/$tool"
    --timeout "$TIMEOUT_SECONDS"
    --timestamp-mode "$TIMESTAMP_MODE"
    --reader "$READER"
    --scenario-dir "$scenario_dir"
  )

  if [[ -n "$command_template" ]]; then
    args+=(--command-template "$command_template")
  fi

  local tool_started_at
  local tool_started_epoch
  local stdout_json="$run_dir/${tool}_runtime_stdout.json"
  local runtime_json="$run_dir/$tool/runtime.json"

  tool_started_at="$(date -Iseconds)"
  tool_started_epoch="$(date +%s)"

  echo "    [$tool] run $run_id started_at=$tool_started_at"
  echo "    [$tool] command: ${args[*]}"

  "${args[@]}" > "$stdout_json" &
  local tool_pid=$!
  local wait_status=0

  if (( PROGRESS_INTERVAL_SECONDS > 0 )); then
    while kill -0 "$tool_pid" 2>/dev/null; do
      sleep "$PROGRESS_INTERVAL_SECONDS"
      if kill -0 "$tool_pid" 2>/dev/null; then
        echo "    [$tool] run $run_id still running elapsed=$(elapsed_seconds "$tool_started_epoch")s"
      fi
    done
  fi

  wait "$tool_pid" || wait_status=$?

  if [[ -f "$runtime_json" ]]; then
    "$PYTHON_BIN" - "$tool" "$run_id" "$runtime_json" "$tool_started_epoch" <<'PY'
import json
import sys
import time

tool, run_id, runtime_json, started_epoch = sys.argv[1:]

with open(runtime_json, "r", encoding="utf-8") as f:
    runtime = json.load(f)

elapsed = int(time.time()) - int(started_epoch)
external = runtime.get("external") or {}
status = runtime.get("status", "unknown")
end_to_end = external.get("end_to_end_seconds")
mount_ready = external.get("start_to_mount_ready_seconds")

parts = [
    f"    [{tool}] run {run_id} finished status={status}",
    f"wall_elapsed={elapsed}s",
]
if mount_ready is not None:
    parts.append(f"mount_ready={float(mount_ready):.3f}s")
if end_to_end is not None:
    parts.append(f"end_to_end={float(end_to_end):.3f}s")

print(" ".join(parts))
PY
  else
    echo "    [$tool] run $run_id finished without runtime.json elapsed=$(elapsed_seconds "$tool_started_epoch")s"
  fi

  if [[ "$wait_status" -eq 0 ]]; then
    append_runtime_row "$case_id" "$files" "$run_id" "$run_started_at" "$runtime_json"
  else
    append_runtime_row "$case_id" "$files" "$run_id" "$run_started_at" "$runtime_json"
    return 1
  fi
}

run_case() {
  local case_id="$1"
  local files="$2"
  local pcap="$3"
  local ground_truth="$4"
  local scenario_dir="$5"

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

  for run_id in $(seq 1 "$REPEATS"); do
    local run_started_at
    run_started_at="$(date -Iseconds)"
    local run_dir="$OUT_DIR/runs/$case_id/run_$run_id"
    local smb_mount="$MOUNT_ROOT/${case_id}_run${run_id}_smbmount"
    local pcapfs_mount="$MOUNT_ROOT/${case_id}_run${run_id}_pcapfs"

    rm -rf "$run_dir"
    mkdir -p "$run_dir"

    echo "  [RUN] $run_id/$REPEATS started_at=$run_started_at"

    local smb_ok=0
    local pcapfs_ok=0

    if [[ "$TOOL_MODE" == "smbmount" || "$TOOL_MODE" == "both" ]]; then
      run_tool \
        "smbmount" "$case_id" "$files" "$run_id" "$run_started_at" \
        "$pcap" "$ground_truth" "$scenario_dir" \
        "$run_dir" "$smb_mount" "$SMBMOUNT_COMMAND_TEMPLATE" || smb_ok=1
    fi

    if [[ "$TOOL_MODE" == "pcapfs" || "$TOOL_MODE" == "both" ]]; then
      run_tool \
        "pcapfs" "$case_id" "$files" "$run_id" "$run_started_at" \
        "$pcap" "$ground_truth" "$scenario_dir" \
        "$run_dir" "$pcapfs_mount" "$PCAPFS_COMMAND_TEMPLATE" || pcapfs_ok=1
    fi

    if [[ "$TOOL_MODE" == "both" && "$smb_ok" -eq 0 && "$pcapfs_ok" -eq 0 ]]; then
      echo "    [compare] comparable speedups"
      "$PYTHON_BIN" -m smbmount.pcapfs.benchmark.runtime compare \
        --smbmount-runtime "$run_dir/smbmount/runtime.json" \
        --pcapfs-runtime "$run_dir/pcapfs/runtime.json" \
        --out "$run_dir/comparison" \
        > "$run_dir/comparison_stdout.txt"
      append_speedup_rows \
        "$case_id" "$files" "$run_id" "$run_started_at" \
        "$run_dir/comparison/runtime_comparison.json"
    fi
  done
}

write_headers
cd "$ROOT_DIR"

if [[ -n "$CASE_FILE" ]]; then
  while IFS=$'\t' read -r case_id files pcap ground_truth scenario_dir; do
    [[ -z "${case_id:-}" || "${case_id:0:1}" == "#" ]] && continue
    run_case "$case_id" "$files" "$pcap" "$ground_truth" "$scenario_dir"
  done < "$CASE_FILE"
else
  run_case \
    "scale_0500_mixed" \
    "500" \
    "$PCAP_DIR/scale_0500_mixed.pcapng" \
    "$GT_DIR/scale_0500_mixed.json" \
    "bench_scale_0500_mixed"

  run_case \
    "scale_1000_mixed" \
    "1000" \
    "$PCAP_DIR/scale_1000_mixed.pcapng" \
    "$GT_DIR/scale_1000_mixed.json" \
    "bench_scale_1000_mixed"

  run_case \
    "scale_5000_mixed" \
    "5000" \
    "$PCAP_DIR/scale_5000_mixed.pcapng" \
    "$GT_DIR/scale_5000_mixed.json" \
    "bench_scale_5000_mixed"
fi

echo
echo "[OK] Phase CSV: $PHASE_CSV"
echo "[OK] Speedup CSV: $SPEEDUP_CSV"
write_summaries
echo "[OK] Phase summary CSV: $PHASE_SUMMARY_CSV"
echo "[OK] Speedup summary CSV: $SPEEDUP_SUMMARY_CSV"
