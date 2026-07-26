# AegisScan

A Python-based network security reconnaissance toolkit.

The goal of this project is to understand how network scanning works internally by implementing core security concepts like host discovery and port scanning.

## Current Features

### Host Discovery (`discovery.py`)
- Discovers active devices in a local network using ARP requests.
- Collects:
  - IP Address
  - MAC Address

### Port Scanner (`port_scanner.py`)
- TCP connect port scanner using Python sockets.
- Supports:
  - Custom ports
  - Port ranges
  - Timeout handling
  - Input validation

## Workflow

```
Network
   |
   ↓
Host Discovery
   |
   ↓
Port Scanner
   |
   ↓
Open Ports
```

## Tech Used

- Python
- Scapy
- Socket Programming
- Networking Fundamentals

## Progress

✅ ARP Host Discovery  
✅ TCP Port Scanner  
✅ Port Input Parser  
✅ Modular Structure  

## Future Plans

- Banner Grabbing
- Service Detection
- Reporting
- Logging

Built for learning cybersecurity, networking, and security automation.
