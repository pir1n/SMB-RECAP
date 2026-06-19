from rich.console import Console
from rich.table import Table

from datetime import datetime


console = Console()


def fmt(ts):
    if ts is None:
        return "N/A"

    try:
        ts = float(ts)
    except Exception:
        return str(ts)

    return datetime.fromtimestamp(
        ts
    ).strftime("%H:%M:%S.%f")[:-3]

def fmt_status(success):
    if success is True:
        return "OK"
    if success is False:
        return "FAIL"
    return "UNKNOWN"


def render(events):
    table = Table(
        title="Reconstructed SMB Activities"
    )

    table.add_column("Timestamp")
    table.add_column("Source")
    table.add_column("Rule")
    table.add_column("Status")
    table.add_column("Frames")
    table.add_column("Activity")

    for e in events:
        activity = e.get("action") or "unknown activity"

        if e.get("path"):
            activity += f": {e['path']}"

        table.add_row(
            fmt(e.get("timestamp")),
            str(e.get("src_ip")),
            str(e.get("rule_id") or ""),
            fmt_status(e.get("success")),
            ",".join(str(x) for x in e.get("frames", []) if x is not None),
            activity,
        )

    console.print(table)