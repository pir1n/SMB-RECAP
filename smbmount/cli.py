import click
from rich.console import Console

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
def parse_pcap_cmd(input_pcap: str, output_json: str):
    """
    Đọc PCAP/PCAPNG và extract SMB2 packet metadata ra JSON.
    """
    console.print(f"[bold cyan]Reading PCAP:[/bold cyan] {input_pcap}")
    console.print(f"[bold cyan]Output JSON:[/bold cyan] {output_json}")

    parse_pcap_to_json(input_pcap, output_json)

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
