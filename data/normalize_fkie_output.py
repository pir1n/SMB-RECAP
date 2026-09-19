#!/usr/bin/env python3
"""Convert FKIE's text output into the canonical timeline JSON format."""

import argparse
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--adapter", type=Path, required=True)
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("fkie_adapter", args.adapter)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows = module.load_fkie(args.raw)
    timeline = [
        {
            "timestamp": row["timestamp"],
            "action": row["action"],
            "path": row["path"],
            "target_path": row["target_path"],
            "success": True,
            "source_line": row["line"],
            "raw": row["raw"],
        }
        for row in rows
        if row["action"] != "unclassified"
    ]
    args.output.write_text(
        json.dumps(timeline, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"parsed_rows": len(rows), "canonical_predictions": len(timeline)}))


if __name__ == "__main__":
    main()
