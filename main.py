import argparse

from discovery import discover_hosts, save_to_csv
from port_scanner import scan_ports, parse_ports

def main():

    parser = argparse.ArgumentParser(
        description="AegisScan - Network Security & Reconnaissance Toolkit"
    )

    parser.add_argument("-t","--target",required=True,help="Target IP address or CIDR range")

    parser.add_argument("-p","--ports",required=True,help="Ports to scan (example: 22,80,443 or 20-25)")

    args = parser.parse_args()
