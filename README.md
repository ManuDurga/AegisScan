\# AegisScan



A Python-based network security reconnaissance toolkit.



The goal of this project is to understand how network scanning works internally by implementing core security concepts like host discovery and port scanning.



\## Current Features



\### Host Discovery (`discovery.py`)

\- Discovers active devices in a local network using ARP requests.

\- Collects:

&#x20; - IP Address

&#x20; - MAC Address



\### Port Scanner (`port\_scanner.py`)

\- TCP connect port scanner using Python sockets.

\- Supports:

&#x20; - Custom ports

&#x20; - Port ranges

&#x20; - Timeout handling

&#x20; - Input validation



\## Workflow



```

Network

&#x20;  |

&#x20;  ↓

Host Discovery

&#x20;  |

&#x20;  ↓

Port Scanner

&#x20;  |

&#x20;  ↓

Open Ports

```



\## Tech Used



\- Python

\- Scapy

\- Socket Programming

\- Networking Fundamentals



\## Progress



✅ ARP Host Discovery  

✅ TCP Port Scanner  

✅ Port Input Parser  

✅ Modular Structure  



\## Future Plans



\- Banner Grabbing

\- Service Detection

\- Reporting

\- Logging



Built for learning cybersecurity, networking, and security automation.

