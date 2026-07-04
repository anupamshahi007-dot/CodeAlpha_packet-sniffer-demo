# Network Packet Sniffer

A comprehensive Python program to capture, analyze, and understand network traffic using Scapy.

## Overview

This packet sniffer allows you to:
- ✅ Capture network traffic in real-time
- ✅ Analyze packet structure and content
- ✅ Filter traffic by protocol, port, or IP address
- ✅ Extract useful information (IPs, ports, protocols, payloads)
- ✅ Learn network protocol fundamentals

## Project Structure

```
packet-sniffer-demo/
├── packet_sniffer.py        # Main sniffer module
├── example_basic.py         # Example: Basic capture
├── example_http.py          # Example: HTTP/HTTPS traffic
├── example_dns.py           # Example: DNS queries
├── example_arp.py           # Example: ARP traffic
├── example_specific_ip.py   # Example: Specific IP filtering
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Installation

### Prerequisites
- Python 3.7+
- Administrator/Root privileges (required for packet capture)
- Windows, macOS, or Linux

### Setup

1. **Clone or download this project**
   ```bash
   cd packet-sniffer-demo
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run with appropriate privileges**

   **Windows (Command Prompt as Administrator):**
   ```bash
   python example_basic.py
   ```

   **Linux/macOS (Terminal with sudo):**
   ```bash
   sudo python example_basic.py
   ```

## Understanding Network Packets

### Packet Structure

Network packets are layered, following the OSI model:

```
┌─────────────────────┐
│  Application Layer  │  HTTP, DNS, SMTP, etc.
├─────────────────────┤
│  Transport Layer    │  TCP (Transmission Control Protocol)
│                     │  UDP (User Datagram Protocol)
├─────────────────────┤
│  Internet Layer     │  IP (Internet Protocol)
├─────────────────────┤
│  Link Layer         │  Ethernet, ARP (Address Resolution Protocol)
└─────────────────────┘
```

### Key Packet Information

**IP Layer:**
- **Source IP**: Where packet originates
- **Destination IP**: Where packet is going
- **TTL (Time To Live)**: Hop limit to prevent infinite loops
- **Protocol**: TCP, UDP, ICMP, etc.

**TCP (Connection-oriented):**
- **Source Port**: Originating port
- **Destination Port**: Target port
- **Flags**: SYN, ACK, FIN (control signals)
- **Sequence Number**: For ordered delivery
- **Acknowledgment Number**: Confirms received data

**UDP (Connectionless):**
- **Source Port**: Originating port
- **Destination Port**: Target port
- **Length**: Size of data

**ICMP (Ping, Traceroute):**
- **Type**: Request, Reply, etc.
- **Code**: Additional details

**ARP (Address Resolution):**
- Maps IP addresses to MAC addresses
- Enables devices to find each other on LAN

## Examples

### Example 1: Basic Packet Sniffing
Capture first 10 packets of all traffic:
```bash
python example_basic.py
```

### Example 2: HTTP/HTTPS Traffic
Capture web browser traffic (ports 80, 443):
```bash
python example_http.py
```

### Example 3: DNS Queries
Monitor DNS requests (port 53):
```bash
python example_dns.py
```

### Example 4: ARP Traffic
Capture network discovery packets:
```bash
python example_arp.py
```

### Example 5: Specific IP
Monitor traffic to/from a specific IP:
```bash
python example_specific_ip.py
```

## Custom Usage

### Create Your Own Sniffer

```python
from packet_sniffer import create_sniffer

# Create sniffer for 50 packets
sniffer = create_sniffer(packet_count=50)

# Start sniffing with TCP filter
sniffer.start_sniffing(packet_filter="tcp")

# Print summary
sniffer.print_summary()
```

### Common Filters (BPF Syntax)

```python
# All traffic
sniffer.start_sniffing()

# Specific protocol
sniffer.start_sniffing(packet_filter="tcp")        # TCP only
sniffer.start_sniffing(packet_filter="udp")        # UDP only
sniffer.start_sniffing(packet_filter="arp")        # ARP only
sniffer.start_sniffing(packet_filter="icmp")       # ICMP (ping)

# Specific port
sniffer.start_sniffing(packet_filter="port 80")    # Port 80
sniffer.start_sniffing(packet_filter="port 443")   # Port 443 (HTTPS)

# Specific IP
sniffer.start_sniffing(packet_filter="host 8.8.8.8")        # To/from 8.8.8.8
sniffer.start_sniffing(packet_filter="src host 192.168.1.1") # From specific IP
sniffer.start_sniffing(packet_filter="dst host 8.8.8.8")     # To specific IP

# Combination
sniffer.start_sniffing(packet_filter="tcp port 80 or tcp port 443")
sniffer.start_sniffing(packet_filter="tcp and host 8.8.8.8")
sniffer.start_sniffing(packet_filter="udp port 53")          # DNS queries
```

### Specify Network Interface

```python
# Linux/Mac: See interfaces with: ifconfig
sniffer.start_sniffing(iface="eth0")

# Windows: See interfaces with: ipconfig
sniffer.start_sniffing(iface="Ethernet")
```

## Understanding the Output

### Packet Display

```
======================================================================
Packet #1 | Size: 56 bytes
Layers: IP -> ICMP

[IP]
  Source IP:      192.168.1.1
  Destination IP: 8.8.8.8
  TTL:            64
  Protocol:       1

[ICMP]
  Type:           8
  Code:           0
======================================================================
```

### Packet Summary

```
======================================================================
Capture Summary
======================================================================
Total packets captured: 25

Protocol Distribution:
  IP: 23
  TCP: 18
  UDP: 5
```

## Learning Points

### What You Learn

1. **Packet Structure**: How data is organized in network packets
2. **Protocols**: Differences between TCP, UDP, ICMP, ARP
3. **Port Numbers**: How applications are identified (HTTP=80, HTTPS=443, DNS=53)
4. **IP Addressing**: Source and destination routing
5. **Data Flow**: How information flows through networks
6. **Filtering**: Techniques to capture specific traffic

### Protocol Reference

| Protocol | Layer | Purpose | Port |
|----------|-------|---------|------|
| TCP | Transport | Reliable, connection-oriented | Variable |
| UDP | Transport | Fast, connectionless | Variable |
| ICMP | Internet | Diagnostics (ping) | N/A |
| ARP | Link | IP ↔ MAC mapping | N/A |
| HTTP | Application | Web browsing | 80 |
| HTTPS | Application | Secure web | 443 |
| DNS | Application | Domain name resolution | 53 |
| SSH | Application | Secure shell | 22 |
| FTP | Application | File transfer | 21 |
| SMTP | Application | Email | 25 |

## Troubleshooting

### "Permission denied" or "Access denied"

**Windows:**
- Run Command Prompt as Administrator
- Then run your Python script

**Linux/macOS:**
- Use `sudo`: `sudo python example_basic.py`

### "No module named 'scapy'"

Install dependencies:
```bash
pip install -r requirements.txt
```

### "No packets captured"

- Ensure network activity is happening
- Try different filters
- Check your internet connection
- Verify network interface name with `ipconfig` (Windows) or `ifconfig` (Mac/Linux)

### Program hangs

- Press `Ctrl+C` to stop
- Packet capture will display summary

## Advanced Topics

### Packet Analysis Use Cases

1. **Network Troubleshooting**: Diagnose connectivity issues
2. **Security**: Detect suspicious traffic patterns
3. **Performance**: Identify slow connections or bottlenecks
4. **Learning**: Understand how protocols work
5. **Development**: Debug networking code

### Next Steps

- Explore Scapy documentation: https://scapy.readthedocs.io/
- Learn more about network protocols
- Build custom analysis tools
- Monitor specific applications
- Create packet capture filters for your needs

## Important Notes

### Legal and Ethical Considerations

- ⚠️ **Only sniff traffic on networks you own or have permission to monitor**
- Monitor only your own devices or with explicit authorization
- Unauthorized network sniffing may be illegal
- Use for educational purposes and legitimate system administration

### Performance

- Packet capture can be CPU-intensive
- Large captures may use significant memory
- Consider using filters to reduce volume
- Stop capture when done (Ctrl+C)

## Resources

- **Scapy Documentation**: https://scapy.readthedocs.io/
- **BPF Filter Syntax**: https://www.tcpdump.org/papers/sniffing-faq.html
- **TCP/IP Protocol Suite**: RFC standards (IETF)
- **Port Numbers**: https://www.iana.org/assignments/service-names-port-numbers/

## License

This project is provided for educational purposes.

## Questions?

Refer to the examples or modify them to fit your learning goals!
