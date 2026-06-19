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
from smbmount.scf.normalize import normalize_packet


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
@click.argument("rule_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
def scf_cmd(input_pcap: str, rule_file: str, output_file: str):

    console.print(f"[bold cyan]Reading PCAP:[/bold cyan] {input_pcap}")

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
    rules = load_rules(rule_file)

    #
    # detect
    #
    detector = SCFDetector(rules)

    events = detector.detect(packets)

    #
    # timeline
    #
    timeline = build_timeline(events)

    #
    # render
    #
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
            "normalized": normalize_packet(pkt),
            "scf": fingerprint_packet(pkt),
        })

    write_json(rows, output_file)

    console.print(
        f"[bold green]SCF dump complete:[/bold green] {output_file}"
    )
    
if __name__ == "__main__":
    main()