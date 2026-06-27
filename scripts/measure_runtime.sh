#!/usr/bin/env bash
set -euo pipefail

REPEATS="${REPEATS:-3}"

PCAP_DIR="${PCAP_DIR:-data/pcaps/benchmark}"
OUT_DIR="${OUT_DIR:-outputs/runtime_benchmark}"
JSON_DIR="$OUT_DIR/json"
LOG_DIR="$OUT_DIR/logs"

PCAPFS_MOUNT="${PCAPFS_MOUNT:-/tmp/pcapfs_mount}"

mkdir -p "$OUT_DIR" "$JSON_DIR" "$LOG_DIR"

CSV="$OUT_DIR/runtime.csv"
echo "tool,case,run,seconds,status,extra" > "$CSV"

now_ns() {
  python3 -c 'import time; print(time.time_ns())'
}

elapsed_sec() {
  python3 - "$1" "$2" <<'PY'
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

wait_for_pcapfs_ready() {
  local mount_dir="$1"

  # Đợi tối đa 60s, mỗi lần 0.1s
  for _ in $(seq 1 600); do
    if mountpoint -q "$mount_dir" 2>/dev/null; then
      return 0
    fi

    sleep 0.1
  done

  return 1
}

measure_smbmount() {
  local case_id="$1"
  local pcap="$2"
  local scenario_dir="$3"
  local run_id="$4"

  local out_json="$JSON_DIR/${case_id}_run${run_id}.json"
  local log_file="$LOG_DIR/${case_id}_smbmount_run${run_id}.log"

  rm -f "$out_json"

  local start
  local end
  local sec

  start="$(now_ns)"

  if python -m smbmount parse-pcap \
      "$pcap" \
      "$out_json" \
      --timestamp-mode network \
      >"$log_file" 2>&1; then

    end="$(now_ns)"
    sec="$(elapsed_sec "$start" "$end")"

    echo "smbmount,$case_id,$run_id,$sec,ok,$out_json" >> "$CSV"
  else
    end="$(now_ns)"
    sec="$(elapsed_sec "$start" "$end")"

    echo "smbmount,$case_id,$run_id,$sec,fail,$log_file" >> "$CSV"
  fi
}

measure_pcapfs() {
  local case_id="$1"
  local pcap="$2"
  local scenario_dir="$3"
  local run_id="$4"

  local mount_dir="$PCAPFS_MOUNT"
  local log_file="$LOG_DIR/${case_id}_pcapfs_run${run_id}.log"

  cleanup_pcapfs_mount "$mount_dir"
  rm -rf "$mount_dir"
  mkdir -p "$mount_dir"

  local start
  local end
  local sec

  start="$(now_ns)"

  # pcapFS là FUSE process, phải chạy background.
  # -f giữ foreground trong process pcapfs, còn & để script lấy lại control.
  pcapfs \
    --timestamp-mode network \
    --show-metadata \
    -f \
    "$pcap" \
    "$mount_dir" \
    >"$log_file" 2>&1 &

  local pcapfs_pid=$!

  if wait_for_pcapfs_ready "$mount_dir"; then
    end="$(now_ns)"
    sec="$(elapsed_sec "$start" "$end")"

    echo "pcapFS,$case_id,$run_id,$sec,ok,$mount_dir" >> "$CSV"
  else
    end="$(now_ns)"
    sec="$(elapsed_sec "$start" "$end")"

    echo "pcapFS,$case_id,$run_id,$sec,timeout_waiting_mount,$log_file" >> "$CSV"
  fi

  cleanup_pcapfs_mount "$mount_dir"

  kill "$pcapfs_pid" 2>/dev/null || true
  wait "$pcapfs_pid" 2>/dev/null || true
}

run_case() {
  local case_id="$1"
  local pcap_file="$2"
  local scenario_dir="$3"

  local pcap="$PCAP_DIR/$pcap_file"

  if [[ ! -f "$pcap" ]]; then
    echo "[SKIP] Missing PCAP: $pcap"
    return
  fi

  echo
  echo "[CASE] $case_id"
  echo "  PCAP: $pcap"
  echo "  Scenario dir: $scenario_dir"

  for run_id in $(seq 1 "$REPEATS"); do
    echo "  [smbmount] run $run_id/$REPEATS"
    measure_smbmount "$case_id" "$pcap" "$scenario_dir" "$run_id"

    echo "  [pcapFS] run $run_id/$REPEATS"
    measure_pcapfs "$case_id" "$pcap" "$scenario_dir" "$run_id"
  done
}

run_case \
  "multi_file_versioning_001" \
  "multi_file_versioning_001.pcapng" \
  "bench_multi_version_001"

run_case \
  "scale_020_mixed" \
  "scale_020_mixed.pcapng" \
  "bench_scale_020_mixed"

run_case \
  "scale_100_mixed" \
  "scale_100_mixed.pcapng" \
  "bench_scale_100_mixed"

echo
echo "[OK] Runtime CSV: $CSV"

python3 - "$CSV" <<'PY'
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
        row["seconds"] = float(row["seconds"])
        rows.append(row)

groups = defaultdict(list)

for row in rows:
    groups[(row["tool"], row["case"])].append(row["seconds"])

print()
print("Runtime summary")
print("=" * 86)
print(
    f"{'tool':<10} "
    f"{'case':<30} "
    f"{'runs':>5} "
    f"{'mean_s':>10} "
    f"{'median_s':>10} "
    f"{'min_s':>10} "
    f"{'max_s':>10}"
)
print("-" * 86)

for (tool, case), values in sorted(groups.items()):
    print(
        f"{tool:<10} "
        f"{case:<30} "
        f"{len(values):>5} "
        f"{statistics.mean(values):>10.4f} "
        f"{statistics.median(values):>10.4f} "
        f"{min(values):>10.4f} "
        f"{max(values):>10.4f}"
    )

print()
print("Failed / timeout runs")
print("-" * 86)

failed = []
with open(path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row["status"] != "ok":
            failed.append(row)

if not failed:
    print("None")
else:
    for row in failed:
        print(row)
PY