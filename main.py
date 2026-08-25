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

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    print("\n===== AegisScan =====")
    print(f"[*] Target: {args.target}")
    print(f"[*] Ports: {ports}")

    # Step 1: Discover active hosts
    print("\n[*] Discovering active hosts...")

    try:
        devices = discover_hosts(args.target)
    except PermissionError:
        print("[-] Administrator/root privileges are required.")
        return
    except Exception as error:
        print(f"[-] Host discovery failed: {error}")
        return

    if not devices:
        print("[-] No active hosts found.")
        return

    print(f"[+] Found {len(devices)} active host(s).")

    # Step 2: Scan each discovered host
    print("\n[*] Starting TCP port scan...")

    for device in devices:
        ip_address = device["ip"]

        print(f"[*] Scanning {ip_address}...")

        open_ports = scan_ports(
            target_ip=ip_address,
            ports=ports
        )

        # Progressively enrich the device object
        device["open_ports"] = open_ports

        if open_ports:
            print(f"[+] {ip_address}: Open ports {open_ports}")
        else:
            print(f"[-] {ip_address}: No selected ports open")

    # Step 3: Save enriched results
    print("\n[*] Saving scan results...")
    save_to_csv(devices)

    print("[+] AegisScan completed successfully.")

if __name__ == "__main__":
    main()
