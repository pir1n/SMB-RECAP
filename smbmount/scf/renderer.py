from rich.console import Console
from rich.table import Table

from datetime import datetime


console = Console()


def fmt(ts):

    if ts is None:
        return "N/A"

    return datetime.fromtimestamp(
        ts
    ).strftime("%H:%M:%S.%f")[:-3]


def render(events):

    table = Table(
        title="Reconstructed SMB Activities"
    )

    table.add_column("Timestamp")
    table.add_column("Source")
    table.add_column("Activity")

    for e in events:

        activity = e["action"]

        if e["path"]:
            activity += f": {e['path']}"

        table.add_row(
            fmt(e["timestamp"]),
            str(e["src_ip"]),
            activity,
        )

    console.print(table)