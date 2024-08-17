# Network Packet Sniffer

This Python script captures and analyzes network packets on your local machine using the `scapy` library. It identifies various network protocols, including TCP, UDP, ICMP, and HTTP, and logs detailed information about each packet for further analysis.

## Features

- Captures packets on a specified network interface.
- Identifies and logs the following protocols:
  - **HTTP** (HyperText Transfer Protocol)
  - **TCP** (Transmission Control Protocol)
  - **UDP** (User Datagram Protocol)
  - **ICMP** (Internet Control Message Protocol)
  - And several others, including IGMP, ESP, AH, OSPF, IPv4, IPv6, GRE, ICMPv6, PIM, and SCTP.
- Logs packet data, including HTTP request and response details, to a file (`packet_log.txt`).

## Installation

### Prerequisites

- Python 3.x
- `scapy` library

### Download and Setup

1. **Clone the repository:**

   ```bash
   git clone <GitHub-Repo-URL>
   cd network_sniffer
   ```

2. **Install the required Python library:**

   ```bash
   pip install scapy
   ```

## Running the Script

1. **Identify your network interface:**
    
   Use the following command to find your network interface name (e.g., `eth0`, `wlan0`):

   ```bash
   ifconfig
   ```

   or

   ```bash
   ip addr
   ```

2. **Run the script with elevated privileges:**

   ```bash
   sudo python3 sniffer.py
   ```

   Ensure you update the `interface` variable in the script to match your network interface name.

## Example Output

When you run the script, you may see output similar to the following:

[*] Starting packet sniffing on interface eth0
HTTP Packet: 192.168.1.104:55936 -> 142.250.187.110:80
GET / HTTP/1.1
Host: google.com
...

TCP Packet: 192.168.1.104:55936 -> 142.250.187.110:80
UDP Packet: 192.168.1.104:60734 -> 208.67.222.222:53



## Logs

Captured packets are logged to `packet_log.txt` in the project directory. Each entry includes the protocol, source and destination IPs, and ports (if applicable). For HTTP traffic, the HTTP request/response data is also logged.

## Notes

- Running the script requires root privileges (`sudo`).
- Make sure to specify the correct network interface in the script.
- The script captures packets in real-time, so let it run to observe different types of network traffic.

