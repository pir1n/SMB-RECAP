#!/usr/bin/env python3
"""Export one auditable score row per Nature_data ground-truth action."""
import argparse, csv, json
from pathlib import Path

def load(path): return json.loads(path.read_text(encoding="utf-8"))

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("ground_truth",type=Path); parser.add_argument("metrics_dir",type=Path); parser.add_argument("output",type=Path); args=parser.parse_args()
    gt=[json.loads(line) for line in args.ground_truth.read_text(encoding="utf-8").splitlines() if line.strip()]
    matches=load(args.metrics_dir/"matches.json"); errors=load(args.metrics_dir/"fp_fn_debug.json")
    result={}
    for item in matches:
        truth=item["ground_truth"]; result[str(truth["op_id"])]=(item["type"],item.get("prediction",{}))
    for item in errors:
        truth=item.get("ground_truth")
        if truth: result[str(truth["op_id"])]=(item["error_type"],item.get("prediction",{}))
    fields=["op_id","client","started_at","ended_at","expected_event","status","predicted_event","rule_id","path","target_path","command"]
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("w",encoding="utf-8-sig",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=fields); writer.writeheader()
        for row in gt:
            status,pred=result.get(str(row["op_id"]),("FN",{}))
            writer.writerow({"op_id":row["op_id"],"client":row["client"],"started_at":row["start_time"],"ended_at":row["end_time"],"expected_event":row["event"],"status":status,"predicted_event":pred.get("action") or pred.get("event"),"rule_id":pred.get("rule_id"),"path":row.get("path"),"target_path":row.get("target_path"),"command":row.get("command")})

if __name__=="__main__": main()
