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
    Handles data persistence with a 70% Vision Scaffold.
    Ensures the dataset is consistent for future ML model training.
    """
    # Feature Scaffolding: Reserving space for A through G features
    scaffold = {
        'Vendor': "Unknown",
        'Latency': "0",
        'Open_Ports': "[]",
        'Service_Banners': "None",
        'TTL': "0",
        'TCP_Window': "0",
        'TCP_Options': "None",
        'IP_Flags': "None",
        'Payload_Entropy': "0.0",
        'Anomaly_Score': "0.0",
        'Vuln_Link': "None"
    }

    # Merge discovered data with the scaffold
    final_data = []
    for dev in device_list:
        entry = {**dev, **scaffold} 
        final_data.append(entry)

    df = pd.DataFrame(final_data)

    # Save logic: Create file if new, append if it exists
    if not os.path.isfile(file_name):
        df.to_csv(file_name, index=False)
        print(f"[+] SUCCESS: Created new database '{file_name}'")
    else:
        df.to_csv(file_name, mode='a', header=False, index=False)
        print(f"[+] SUCCESS: Appended {len(device_list)} results to '{file_name}'")

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
