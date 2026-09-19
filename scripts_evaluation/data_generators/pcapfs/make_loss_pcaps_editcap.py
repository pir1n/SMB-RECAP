#!/usr/bin/env python3
import argparse
import os
import random
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


DEFAULT_INPUT = Path("data/pcaps/benchmark_parse-pcap/scale_1000_mixed.pcapng")
LOSS_CASES = [
    ("scale_1000_mixed_loss_01.pcapng", 0.01),
    ("scale_1000_mixed_loss_05.pcapng", 0.05),
    ("scale_1000_mixed_loss_10.pcapng", 0.10),
]


def require_tool(name):
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"Required tool not found in PATH: {name}")
    return path


def frame_count_with_capinfos(input_path):
    output = subprocess.check_output(
        ["capinfos", "-M", "-c", str(input_path)],
        text=True,
        stderr=subprocess.STDOUT,
    )

    match = re.search(r"Number of packets:\s*(\d+)", output)
    if not match:
        raise RuntimeError(f"Could not parse frame count from capinfos output:\n{output}")

    return int(match.group(1))


def frame_count_with_tshark(input_path):
    output = subprocess.check_output(
        ["tshark", "-r", str(input_path), "-q", "-z", "io,stat,0"],
        text=True,
        stderr=subprocess.STDOUT,
    )

    for line in output.splitlines():
        parts = [part.strip() for part in line.split("|")]
        if len(parts) >= 3 and parts[1] == "<>":
            try:
                return int(parts[2])
            except ValueError:
                continue

    raise RuntimeError(f"Could not parse frame count from tshark output:\n{output}")


def frame_count(input_path):
    if shutil.which("capinfos"):
        return frame_count_with_capinfos(input_path)
    if shutil.which("tshark"):
        return frame_count_with_tshark(input_path)
    raise SystemExit("Need capinfos or tshark to count frames")


def group_ranges(frames):
    frames = sorted(frames)
    if not frames:
        return []

    ranges = []
    start = frames[0]
    prev = frames[0]

    for frame in frames[1:]:
        if frame == prev + 1:
            prev = frame
            continue

        ranges.append((start, prev))
        start = frame
        prev = frame

    ranges.append((start, prev))

    return [
        str(start) if start == end else f"{start}-{end}"
        for start, end in ranges
    ]


def deterministic_drop_frames(total_frames, drop_rate, seed, label):
    rng = random.Random(f"{seed}:{label}:{drop_rate}")
    drop_count = round(total_frames * drop_rate)
    return sorted(rng.sample(range(1, total_frames + 1), drop_count))


def range_start(range_text):
    return int(range_text.split("-", 1)[0])


def chunked(items, size):
    for index in range(0, len(items), size):
        yield items[index:index + size]


def count_after_editcap(output_path):
    return frame_count(output_path)


def run_editcap_once(input_path, output_path, drop_ranges):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["editcap", str(input_path), str(output_path), *drop_ranges]
    subprocess.run(cmd, check=True)


def run_editcap(input_path, output_path, drop_ranges, max_ranges_per_pass):
    """
    editcap has a finite packet-selection buffer. For random loss the range
    list can be huge, so delete in batches from high frame numbers downwards.

    Deleting higher frames first keeps lower original frame numbers valid for
    later passes.
    """
    if len(drop_ranges) <= max_ranges_per_pass:
        run_editcap_once(input_path, output_path, drop_ranges)
        return

    sorted_ranges = sorted(drop_ranges, key=range_start, reverse=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="editcap_loss_") as tmp_dir:
        tmp_dir = Path(tmp_dir)
        current = input_path

        chunks = list(chunked(sorted_ranges, max_ranges_per_pass))

        for idx, ranges_chunk in enumerate(chunks, start=1):
            target = output_path if idx == len(chunks) else tmp_dir / f"pass_{idx:04d}.pcapng"

            # Keep ranges ascending within one editcap invocation for readability.
            ranges_chunk = sorted(ranges_chunk, key=range_start)
            run_editcap_once(current, target, ranges_chunk)

            if current != input_path and current.exists():
                current.unlink()

            current = target


def main():
    parser = argparse.ArgumentParser(
        description="Create deterministic lossy PCAPNG files with editcap."
    )
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--out-dir", default="data/pcaps/benchmark_parse-pcap")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--max-ranges-per-pass",
        type=int,
        default=200,
        help="Maximum packet/range selections per editcap invocation.",
    )

    args = parser.parse_args()

    require_tool("editcap")

    input_path = Path(args.input)
    out_dir = Path(args.out_dir)

    if not input_path.exists():
        raise SystemExit(f"Input PCAP not found: {input_path}")

    total = frame_count(input_path)

    for filename, rate in LOSS_CASES:
        output_path = out_dir / filename
        drop_frames = deterministic_drop_frames(total, rate, args.seed, filename)
        ranges = group_ranges(drop_frames)

        run_editcap(
            input_path,
            output_path,
            ranges,
            max_ranges_per_pass=args.max_ranges_per_pass,
        )

        output_total = count_after_editcap(output_path)
        actual_dropped = total - output_total

        actual_rate = actual_dropped / total if total else 0.0
        print(f"input={input_path}")
        print(f"output={output_path}")
        print(f"total_frames={total}")
        print(f"dropped_frames={len(drop_frames)}")
        print(f"output_frames={output_total}")
        print(f"actual_dropped_frames={actual_dropped}")
        print(f"drop_rate={actual_rate:.6f}")
        print(f"editcap_ranges={len(ranges)}")
        print(f"editcap_passes={(len(ranges) + args.max_ranges_per_pass - 1) // args.max_ranges_per_pass}")
        if actual_dropped != len(drop_frames):
            raise RuntimeError(
                f"editcap dropped {actual_dropped} frames, expected {len(drop_frames)}"
            )
        print()


if __name__ == "__main__":
    main()
