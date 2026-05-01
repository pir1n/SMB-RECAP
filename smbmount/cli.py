import click
from rich.console import Console

from smbmount.parser.pcap_reader import parse_pcap_to_json


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


if __name__ == "__main__":
    main()