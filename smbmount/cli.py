import click
from rich.console import Console
import os

from smbmount.parser.pcap_reader import parse_pcap_to_json
from smbmount.parser.pcap_reader import (
    read_pcap_basic,
    enrich_with_request_mapping,
    enrich_with_file_metadata_mapping,
    enrich_with_query_info_timestamps,
)
from smbmount.scf.loader import load_rules
from smbmount.scf.detector import SCFDetector
from smbmount.scf.timeline import build_timeline
from smbmount.scf.renderer import render
from smbmount.scf.fingerprint import fingerprint_packet
from smbmount.scf.normalize import normalize_packet, packet_features


from smbmount.parser.pcap_reader import write_json

console = Console()


@click.group()
def main():
    """
    mount-SMB.pcap reproduce toolkit.
    """
    pass


@main.command("parse-pcap")
@click.argument("input_pcap", type=click.Path(exists=True))
@click.argument("output_json", type=click.Path())
@click.option(
    "--timestamp-mode",
    type=click.Choice(["network", "fs", "hybrid"]),
    default="hybrid",
    show_default=True,
    help="Timestamp mode: network, fs, or hybrid.",
)
@click.option(
    "--snapshot-at",
    type=float,
    default=None,
    help="Export filesystem snapshot at this timestamp.",
)
@click.option(
    "--snapshot-time-source",
    type=click.Choice(["network", "fs"]),
    default="network",
    show_default=True,
    help="Timestamp source used to decide snapshot membership.",
)
@click.option(
    "--snapshot-include-deleted/--no-snapshot-include-deleted",
    default=True,
    show_default=True,
    help="Include deleted files in snapshot output.",
)
@click.option(
    "--fuse-mount",
    type=click.Path(file_okay=False, dir_okay=True),
    default=None,
    help="Mount reconstructed filesystem at this mountpoint using FUSE. This keeps the process running.",
)
@click.option(
    "--fuse-include-deleted/--no-fuse-include-deleted",
    default=False,
    show_default=True,
    help="Include deleted files in FUSE view.",
)
@click.option(
    "--fuse-allow-other/--no-fuse-allow-other",
    default=False,
    show_default=True,
    help="Allow other users to access the FUSE mount. Requires system FUSE config.",
)
@click.option(
    "--fuse-debug/--no-fuse-debug",
    default=False,
    show_default=True,
    help="Enable FUSE debug output.",
)
def parse_pcap_cmd(
    input_pcap: str,
    output_json: str,
    timestamp_mode: str,
    snapshot_at,
    snapshot_time_source,
    snapshot_include_deleted,
    fuse_mount,
    fuse_include_deleted,
    fuse_allow_other,
    fuse_debug,
):
    """
    Đọc PCAP/PCAPNG và extract SMB2 packet metadata ra JSON.
    """
    console.print(f"[bold cyan]Reading PCAP:[/bold cyan] {input_pcap}")
    console.print(f"[bold cyan]Output JSON:[/bold cyan] {output_json}")
    console.print(f"[bold cyan]Timestamp mode:[/bold cyan] {timestamp_mode}")
    if snapshot_at is not None:
        console.print(f"[bold cyan]Snapshot at:[/bold cyan] {snapshot_at}")
        console.print(f"[bold cyan]Snapshot time source:[/bold cyan] {snapshot_time_source}")
    
    file_table, result = parse_pcap_to_json(
        input_pcap,
        output_json,
        timestamp_mode=timestamp_mode,
        snapshot_at=snapshot_at,
        snapshot_time_source=snapshot_time_source,
        snapshot_include_deleted=snapshot_include_deleted,
    )
    
    if fuse_mount:
        try:
            from smbmount.output.fuse_mount import mount_reconstructed_fs
        except ModuleNotFoundError as exc:
            if exc.name == "mfusepy":
                raise click.ClickException(
                    "FUSE support requires mfusepy. Install dependencies from requirements.txt "
                    "before using --fuse-mount."
                ) from exc
            raise

        os.makedirs(fuse_mount, exist_ok=True)

        console.print(f"[bold cyan]FUSE mount:[/bold cyan] {fuse_mount}")

        if snapshot_at is not None:
            console.print(
                f"[bold cyan]FUSE view:[/bold cyan] snapshot at {snapshot_at} "
                f"using {snapshot_time_source} time"
            )
        else:
            console.print("[bold cyan]FUSE view:[/bold cyan] latest reconstructed state")

        console.print("[yellow]FUSE is running. Press Ctrl+C to unmount/stop.[/yellow]")

        try:
            mount_reconstructed_fs(
                file_table,
                mountpoint=fuse_mount,
                snapshot_at=snapshot_at,
                snapshot_time_source=snapshot_time_source,
                include_deleted=fuse_include_deleted,
                foreground=True,
                debug=fuse_debug,
                allow_other=fuse_allow_other,
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]FUSE stopped.[/yellow]")
            return
        except RuntimeError as exc:
            # mfusepy may return RuntimeError("7") when FUSE is interrupted by Ctrl+C.
            if str(exc) == "7":
                console.print("\n[yellow]FUSE stopped.[/yellow]")
                return
            raise
        

    console.print("[bold green]Done.[/bold green]")
    
@main.command("scf")
@click.argument("input_pcap", type=click.Path(exists=True))
@click.argument("rule_or_output", type=click.Path(), required=True)
@click.argument("output_file", type=click.Path(), required=False)
@click.option(
    "--with-builtin-rules",
    is_flag=True,
    help="Load built-in semantic SCF rules in addition to the supplied rule file.",
)
@click.option(
    "--print-table/--no-print-table",
    default=False,
    show_default=True,
    help="Print the Rich activity table. Disable for faster large timeline generation.",
)
@click.option(
    "--progress/--no-progress",
    default=True,
    show_default=True,
    help="Print SCF detection progress every 10 percent.",
)
def scf_cmd(
    input_pcap: str,
    rule_or_output: str,
    output_file: str,
    with_builtin_rules: bool,
    print_table: bool,
    progress: bool,
):
    """
    Detect SMB activities with SCF.

    Forms:
    python -m smbmount scf input.pcap rules.json output.json
    python -m smbmount scf input.pcap output.json
    """

    console.print(f"[bold cyan]Reading PCAP:[/bold cyan] {input_pcap}")

    if output_file is None:
        rule_file = None
        output_file = rule_or_output
        include_builtin = True
    else:
        rule_file = rule_or_output
        include_builtin = with_builtin_rules

    #
    # parse
    #
    packets = read_pcap_basic(input_pcap)

    #
    # enrich
    #
    packets = enrich_with_request_mapping(packets)

    packets = enrich_with_file_metadata_mapping(
        packets
    )

    packets = enrich_with_query_info_timestamps(
        packets
    )

    #
    # rules
    #
    rules = load_rules(rule_file, include_builtin=include_builtin)

    #
    # detect
    #
    detector = SCFDetector(rules)

    def print_progress(percent):
        console.print(f"[cyan]SCF progress:[/cyan] {percent}%")

    events = detector.detect(
        packets,
        progress_callback=print_progress if progress else None,
    )

    #
    # timeline
    #
    timeline = build_timeline(events)

    #
    # render
    #
    if print_table:
        render(timeline)

    #
    # export json
    #
    write_json(timeline, output_file)

    console.print(
        f"[bold green]SCF complete:[/bold green] {output_file}"
    )
    
@main.command("scf-dump")
@click.argument("input_pcap", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
def scf_dump_cmd(input_pcap: str, output_file: str):
    """
    Dump normalized SMB request + packet SCF để tạo rule.
    """
    console.print(f"[bold cyan]Reading PCAP:[/bold cyan] {input_pcap}")

    packets = read_pcap_basic(input_pcap)
    packets = enrich_with_request_mapping(packets)
    packets = enrich_with_file_metadata_mapping(packets)
    packets = enrich_with_query_info_timestamps(packets)

    rows = []

    for pkt in packets:
        if pkt.get("smb2_is_response") is not False:
            continue

        rows.append({
            "frame_number": pkt.get("frame_number"),
            "timestamp": float(pkt.get("timestamp")) if pkt.get("timestamp") is not None else None,
            "src_ip": pkt.get("src_ip"),
            "dst_ip": pkt.get("dst_ip"),
            "src_port": pkt.get("src_port"),
            "dst_port": pkt.get("dst_port"),
            "session_id": pkt.get("smb2_session_id"),
            "tree_id": pkt.get("smb2_tree_id"),
            "message_id": pkt.get("smb2_message_id"),
            "command": pkt.get("smb2_command_name"),
            "path": pkt.get("smb2_filename"),
            "target_path": pkt.get("smb2_rename_target"),
            "normalized": normalize_packet(pkt),
            "features": packet_features(pkt),
            "scf": fingerprint_packet(pkt),
        })

    write_json(rows, output_file)

    console.print(
        f"[bold green]SCF dump complete:[/bold green] {output_file}"
    )
    
if __name__ == "__main__":
    main()
