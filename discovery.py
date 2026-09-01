from scapy.all import ARP, Ether, srp
import pandas as pd
import datetime
import os

def discover_hosts(target_ip):
    """
    AegisScan Discovery Engine
    pdst: Protocol Destination (The IP we are looking for)
    srp: Send/Receive Packets at Layer 2 (Data Link Layer)
    """
    # Create an ARP request packet
    # pdst: Protocol Destination (The target IP or range)
    arp = ARP(pdst=target_ip)
    
    # Create an Ethernet broadcast frame
    # dst: Destination (ff:ff:ff:ff:ff:ff hits every device on the subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Stack layers: Ethernet Frame + ARP Packet
    packet = ether/arp
    
    # Send packet and wait for response
    # timeout: Wait 3 seconds for a reply
    # [0]: Access only the 'Answered' list of packets
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        # psrc: Protocol Source (IP of the responding device)
        # hwsrc: Hardware Source (MAC address of the responding device)
        devices.append({
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ip': received.psrc, 
            'mac': received.hwsrc,
            "status": "active"})
    
    return devices

def save_to_csv(device_list, file_name="AegisScan_results.csv"):
    """
    Saves the current AegisScan results to a CSV file.
    Each device object contains progressively enriched scan data.
    """

    df = pd.DataFrame(device_list)

    df.to_csv(file_name, index=False)

    print(f"[+] Results saved to '{file_name}'")

# --- EXECUTION BLOCK ---
if __name__ == "__main__":
    # IMPORTANT: Use /32 for a single device (e.g., your phone) to be safe on campus.
    # Use /24 only on your private home network.
    TARGET_RANGE = "192.168.1.0/24" # <-- EDIT THIS IP
    
    print(f"[*] Starting AegisScan on {TARGET_RANGE}...")
    
    found_devices = discover_hosts(TARGET_RANGE)
    
    if found_devices:
        save_to_csv(found_devices)
    else:
        print("[-] No devices responded. Check your IP range or network isolation.")
