#!/usr/bin/env python3
"""Convert the hand-annotated Nature_data table into auditable canonical JSONL."""
import argparse, json, ntpath, re
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath

ROW_RE = re.compile(r"^(\S+)\s+(\S+)\s+(cmd|powershell|explorer)\s+(\d+)\s*(.*)$", re.I)
VN = timezone(timedelta(hours=7))

def parse_time(text):
    fixed = re.sub(r"T(\d{2}):(\d{2})\.(\d{2})$", r"T\1:\2:\3", text.strip())
    return datetime.fromisoformat(fixed).replace(tzinfo=VN), fixed != text.strip()

def share_path(value):
    text = str(value or "").strip().strip('"').replace("/", "\\")
    text = re.sub(r"^[A-Za-z]:\\+", "", text)
    return ntpath.normpath(text).strip("\\") if text else ""

def destination(command):
    match = re.search(r"\b(?:to|at|drop at)\s+(Z:\\.+)$", command, re.I)
    return share_path(match.group(1)) if match else ""

def classify(app, text, cwd):
    low = text.casefold()
    if app == "explorer":
        if low.startswith(("change directory", "directory listing", "open file explorer")):
            return "directory_listing", destination(text), None
        if low.startswith(("open and read ", "read ")):
            return "read_file", share_path(re.sub(r"^(?:open and read|read)\s+", "", text, flags=re.I)), None
        if low.startswith("edit "):
            return "write_file", share_path(text[5:]), None
        if low.startswith("create new file "):
            return "create_file", share_path(text[16:]), None
        if low.startswith("rename file ") and " to " in low:
            source, target = re.split(r"\s+to\s+", text[12:], maxsplit=1, flags=re.I)
            return "rename_file", share_path(source), share_path(target)
        if low.startswith("cut ") and " to " in low:
            source, target = re.split(r"\s+to\s+", text[4:], maxsplit=1, flags=re.I)
            return "rename_file", share_path(source), share_path(ntpath.join(target, PureWindowsPath(source).name))
        if low.startswith(("copy ", "drag file ", "drag folder ")):
            target = destination(text)
            source = re.sub(r"^(?:copy|drag file|drag folder)\s+", "", text, flags=re.I)
            source = re.split(r"\s+(?:to|and drop at)\s+", source, maxsplit=1, flags=re.I)[0]
            if target and not PureWindowsPath(target).suffix:
                target = ntpath.join(target, PureWindowsPath(source).name)
            return "upload_file", share_path(target), None
        return None, None, None
    if low in {"dir", "dir .", "ls", "get-childitem", "get-childitem ."}:
        return "directory_listing", share_path(cwd), None
    if low.startswith(("type ", "more ")) or "convert_ground_truth.ps1" in low:
        name = "convert_ground_truth.ps1" if "convert_ground_truth.ps1" in low else text.split(maxsplit=1)[1]
        return "read_file", share_path(ntpath.join(cwd, name)), None
    if low.startswith(("mkdir ", "md ")):
        return "create_directory", share_path(ntpath.join(cwd, text.split(maxsplit=1)[1])), None
    if low.startswith("echo ") and ">>" in text:
        return "append_file", share_path(ntpath.join(cwd, text.rsplit(">>", 1)[1].strip())), None
    if low.startswith("echo ") and ">" in text:
        return "create_file", share_path(ntpath.join(cwd, text.rsplit(">", 1)[1].strip())), None
    if low.startswith(("del ", "erase ")):
        return "delete_file", share_path(ntpath.join(cwd, text.split(maxsplit=1)[1])), None
    if low.startswith("rmdir "):
        return "delete_directory", share_path(ntpath.join(cwd, text.split(maxsplit=1)[1])), None
    if low.startswith(("copy ", "move ")):
        words = re.findall(r'"[^"]+"|\S+', text)
        if len(words) < 3: return None, None, None
        source, target = words[1].strip('"'), words[2].strip('"')
        if source.casefold().startswith("c:\\"):
            name = PureWindowsPath(source).name if target == "." else target
            return "upload_file", share_path(ntpath.join(cwd, name)), None
        src = share_path(ntpath.join(cwd, source))
        dst = ntpath.join(cwd, target)
        if target.endswith(("\\", "/")): dst = ntpath.join(dst, PureWindowsPath(source).name)
        return "rename_file", src, share_path(dst)
    return None, None, None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path); parser.add_argument("out_dir", type=Path)
    args = parser.parse_args(); args.out_dir.mkdir(parents=True, exist_ok=True)
    rows, audit, source_count = [], [], 0
    current_cwd = {"cmd": "Z:\\", "powershell": "Z:\\"}
    for line_no, raw in enumerate(args.source.read_text(encoding="utf-8-sig").splitlines()[1:], 2):
        source_count += 1; match = ROW_RE.match(raw.strip())
        if not match:
            audit.append({"line":line_no,"status":"invalid_row","raw":raw}); continue
        start_s, end_s, app, exit_s, tail = match.groups(); parts = raw.split("\t")
        cwd = parts[-2].strip() if len(parts) >= 4 else ""
        command = parts[-1].strip() if len(parts) >= 2 else tail.strip()
        app = app.casefold()
        if cwd:
            current_cwd[app] = cwd
        effective_cwd = cwd or current_cwd.get(app, "")
        start, fixed_start = parse_time(start_s); end, fixed_end = parse_time(end_s)
        if end < start:
            audit.append({"line":line_no,"status":"end_before_start_clamped","start":start_s,"end":end_s}); end = start
        if int(exit_s) != 0:
            audit.append({"line":line_no,"status":"failed_excluded","command":command}); continue
        cd_match = re.match(r"^(?:cd|set-location)\s+(?:/d\s+)?(.+)$", command, re.I)
        if cd_match and app in current_cwd:
            operand = cd_match.group(1).strip().strip('"')
            current_cwd[app] = ntpath.normpath(operand if ntpath.isabs(operand) else ntpath.join(effective_cwd, operand))
        event, path, target = classify(app, command, effective_cwd)
        if not event:
            audit.append({"line":line_no,"status":"non_scoreable_excluded","application":app,"command":command}); continue
        rows.append({"run_id":"Nature_data","op_id":f"tsv-{line_no}","client":app,"event":event,"path":path,"target_path":target,"start_time":start.isoformat(),"end_time":end.isoformat(),"status":"success","command":command,"source_line":line_no})
        if fixed_start or fixed_end: audit.append({"line":line_no,"status":"timestamp_syntax_normalized"})
    behavior = [dict(row, event={"upload_file":"create_file","append_file":"write_file","overwrite_file":"write_file"}.get(row["event"], row["event"])) for row in rows]
    for name, data in (("cross_application_ground_truth.jsonl",rows),("behavior_ground_truth.jsonl",behavior)):
        with (args.out_dir/name).open("w",encoding="utf-8",newline="\n") as handle:
            for row in data: handle.write(json.dumps(row,ensure_ascii=False)+"\n")
    (args.out_dir/"conversion_audit.json").write_text(json.dumps({"source_rows":source_count,"scoreable_rows":len(rows),"audit":audit},ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"source_rows":source_count,"cross_application":len(rows),"behavior":len(behavior),"audit_records":len(audit)}))

if __name__ == "__main__": main()
