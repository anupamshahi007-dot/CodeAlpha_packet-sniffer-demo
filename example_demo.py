"""
Demonstration: Packet Analysis Without Live Capture
Shows how the sniffer analyzes packets using simulated data
Perfect for learning - no admin privileges needed!
"""

import struct
from packet_sniffer_windows import WindowsPacketSniffer


def create_sample_icmp_packet():
    """Create a simulated ICMP packet (ping request)."""
    # IPv4 Header (20 bytes)
    packet = bytearray(32)
    
    # Version (4 bits) = 4, IHL (4 bits) = 5
    packet[0] = 0x45
    # DSCP/ECN
    packet[1] = 0x00
    # Total Length
    packet[2:4] = struct.pack('!H', 32)
    # Identification
    packet[4:6] = struct.pack('!H', 54321)
    # Flags and Fragment Offset
    packet[6:8] = struct.pack('!H', 0x4000)
    # TTL
    packet[8] = 64
    # Protocol (ICMP = 1)
    packet[9] = 1
    # Header Checksum (simplified, should be calculated)
    packet[10:12] = struct.pack('!H', 0xFFFF)
    # Source IP: 192.168.1.100
    packet[12:16] = struct.pack('!4B', 192, 168, 1, 100)
    # Destination IP: 8.8.8.8
    packet[16:20] = struct.pack('!4B', 8, 8, 8, 8)
    
    # ICMP Echo Request (12 bytes)
    packet[20] = 8   # Type: Echo Request
    packet[21] = 0   # Code
    packet[22:24] = struct.pack('!H', 0xFFFF)  # Checksum
    packet[24:26] = struct.pack('!H', 0)       # Identifier
    packet[26:28] = struct.pack('!H', 0)       # Sequence Number
    
    return bytes(packet)


def create_sample_tcp_packet():
    """Create a simulated TCP packet."""
    # IPv4 Header (20 bytes)
    packet = bytearray(60)
    
    # Version (4 bits) = 4, IHL (4 bits) = 5
    packet[0] = 0x45
    # DSCP/ECN
    packet[1] = 0x00
    # Total Length
    packet[2:4] = struct.pack('!H', 60)
    # Identification
    packet[4:6] = struct.pack('!H', 54322)
    # Flags and Fragment Offset
    packet[6:8] = struct.pack('!H', 0x4000)
    # TTL
    packet[8] = 64
    # Protocol (TCP = 6)
    packet[9] = 6
    # Header Checksum
    packet[10:12] = struct.pack('!H', 0xFFFF)
    # Source IP: 192.168.1.50
    packet[12:16] = struct.pack('!4B', 192, 168, 1, 50)
    # Destination IP: 142.251.41.14 (Google)
    packet[16:20] = struct.pack('!4B', 142, 251, 41, 14)
    
    # TCP Header (20 bytes)
    # Source Port
    packet[20:22] = struct.pack('!H', 54321)
    # Destination Port (443 = HTTPS)
    packet[22:24] = struct.pack('!H', 443)
    # Sequence Number
    packet[24:28] = struct.pack('!I', 1000000)
    # Acknowledgment Number
    packet[28:32] = struct.pack('!I', 0)
    # Data Offset (5 << 4) + Reserved (0) + Flags (SYN = 0x02)
    packet[32:34] = struct.pack('!H', (5 << 12) | 0x0002)
    # Window Size
    packet[34:36] = struct.pack('!H', 65535)
    # Checksum
    packet[36:38] = struct.pack('!H', 0xFFFF)
    # Urgent Pointer
    packet[38:40] = struct.pack('!H', 0)
    
    return bytes(packet)


def create_sample_udp_packet():
    """Create a simulated UDP packet (DNS query)."""
    # IPv4 Header (20 bytes) + UDP Header (8 bytes) + DNS Data
    packet = bytearray(42)
    
    # IPv4 Header
    # Version (4 bits) = 4, IHL (4 bits) = 5
    packet[0] = 0x45
    # DSCP/ECN
    packet[1] = 0x00
    # Total Length
    packet[2:4] = struct.pack('!H', 42)
    # Identification
    packet[4:6] = struct.pack('!H', 54323)
    # Flags and Fragment Offset
    packet[6:8] = struct.pack('!H', 0x4000)
    # TTL
    packet[8] = 64
    # Protocol (UDP = 17)
    packet[9] = 17
    # Header Checksum
    packet[10:12] = struct.pack('!H', 0xFFFF)
    # Source IP: 192.168.1.100
    packet[12:16] = struct.pack('!4B', 192, 168, 1, 100)
    # Destination IP: 8.8.8.8 (Google DNS)
    packet[16:20] = struct.pack('!4B', 8, 8, 8, 8)
    
    # UDP Header (8 bytes)
    # Source Port
    packet[20:22] = struct.pack('!H', 52345)
    # Destination Port (53 = DNS)
    packet[22:24] = struct.pack('!H', 53)
    # Length
    packet[24:26] = struct.pack('!H', 22)
    # Checksum
    packet[26:28] = struct.pack('!H', 0)
    
    return bytes(packet)


def main():
    """Run packet analysis demonstration."""
    print("\n" + "="*70)
    print("PACKET ANALYSIS DEMONSTRATION")
    print("="*70)
    print("Simulated packets - No admin privileges needed!")
    print("="*70 + "\n")
    
    sniffer = WindowsPacketSniffer(packet_count=0)
    
    # Simulate ICMP packet
    print("--- Simulated ICMP Packet (Ping) ---\n")
    icmp_packet = create_sample_icmp_packet()
    sniffer.display_packet(icmp_packet)
    
    # Simulate TCP packet
    print("--- Simulated TCP Packet (HTTPS) ---\n")
    tcp_packet = create_sample_tcp_packet()
    sniffer.display_packet(tcp_packet)
    
    # Simulate UDP packet
    print("--- Simulated UDP Packet (DNS) ---\n")
    udp_packet = create_sample_udp_packet()
    sniffer.display_packet(udp_packet)
    
    print("="*70)
    print("DEMONSTRATION COMPLETE")
    print("="*70)
    print("\nTo capture real packets on Windows:")
    print("1. Right-click Command Prompt")
    print("2. Select 'Run as Administrator'")
    print("3. Run: python example_windows_raw.py")
    print("\nFor Linux/macOS:")
    print("Run: sudo python example_basic.py")
    print("(Requires Scapy: pip install scapy)")


if __name__ == "__main__":
    main()
