"""
Packet Sniffer Module
Captures and analyzes network traffic using Scapy
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, conf
from scapy.layers.inet import IP
import sys
import platform
from typing import Callable, Optional

# Configure Scapy for Windows compatibility
if platform.system() == "Windows":
    conf.use_pcap = False


class PacketSniffer:
    """Main packet sniffer class for capturing and analyzing network traffic."""
    
    def __init__(self, packet_count: int = 0, interface: Optional[str] = None):
        """
        Initialize the packet sniffer.
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            interface: Network interface to sniff on (None = default)
        """
        self.packet_count = packet_count
        self.interface = interface
        self.packets = []
        
    def analyze_packet(self, packet) -> dict:
        """
        Analyze a single packet and extract relevant information.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary containing packet information
        """
        packet_info = {
            'timestamp': packet.time,
            'size': len(packet),
            'layers': []
        }
        
        # IP Layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['ip'] = {
                'src': ip_layer.src,
                'dst': ip_layer.dst,
                'version': ip_layer.version,
                'ttl': ip_layer.ttl,
                'protocol': ip_layer.proto
            }
            packet_info['layers'].append('IP')
        
        # ARP Layer
        if ARP in packet:
            arp_layer = packet[ARP]
            packet_info['arp'] = {
                'src_ip': arp_layer.psrc,
                'dst_ip': arp_layer.pdst,
                'src_mac': arp_layer.hwsrc,
                'dst_mac': arp_layer.hwdst,
                'operation': 'Request' if arp_layer.op == 1 else 'Reply'
            }
            packet_info['layers'].append('ARP')
        
        # TCP Layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info['tcp'] = {
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'flags': str(tcp_layer.flags),
                'seq': tcp_layer.seq,
                'ack': tcp_layer.ack
            }
            packet_info['layers'].append('TCP')
        
        # UDP Layer
        if UDP in packet:
            udp_layer = packet[UDP]
            packet_info['udp'] = {
                'src_port': udp_layer.sport,
                'dst_port': udp_layer.dport,
                'length': udp_layer.len
            }
            packet_info['layers'].append('UDP')
        
        # ICMP Layer
        if ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_info['icmp'] = {
                'type': icmp_layer.type,
                'code': icmp_layer.code
            }
            packet_info['layers'].append('ICMP')
        
        # Payload
        if Raw in packet:
            raw_layer = packet[Raw]
            packet_info['payload'] = raw_layer.load[:50]  # First 50 bytes
            packet_info['layers'].append('Raw')
        
        return packet_info
    
    def packet_callback(self, packet):
        """
        Callback function for each captured packet.
        
        Args:
            packet: Scapy packet object
        """
        packet_info = self.analyze_packet(packet)
        self.packets.append(packet_info)
        self.display_packet(packet_info)
    
    def display_packet(self, packet_info: dict):
        """
        Display formatted packet information.
        
        Args:
            packet_info: Dictionary containing packet information
        """
        print("\n" + "="*70)
        print(f"Packet #{len(self.packets)} | Size: {packet_info['size']} bytes")
        print(f"Layers: {' -> '.join(packet_info['layers'])}")
        
        if 'ip' in packet_info:
            ip = packet_info['ip']
            print(f"\n[IP]")
            print(f"  Source IP:      {ip['src']}")
            print(f"  Destination IP: {ip['dst']}")
            print(f"  TTL:            {ip['ttl']}")
            print(f"  Protocol:       {ip['protocol']}")
        
        if 'arp' in packet_info:
            arp = packet_info['arp']
            print(f"\n[ARP]")
            print(f"  Operation:      {arp['operation']}")
            print(f"  Source IP:      {arp['src_ip']} ({arp['src_mac']})")
            print(f"  Dest IP:        {arp['dst_ip']} ({arp['dst_mac']})")
        
        if 'tcp' in packet_info:
            tcp = packet_info['tcp']
            print(f"\n[TCP]")
            print(f"  Source Port:    {tcp['src_port']}")
            print(f"  Dest Port:      {tcp['dst_port']}")
            print(f"  Flags:          {tcp['flags']}")
        
        if 'udp' in packet_info:
            udp = packet_info['udp']
            print(f"\n[UDP]")
            print(f"  Source Port:    {udp['src_port']}")
            print(f"  Dest Port:      {udp['dst_port']}")
            print(f"  Length:         {udp['length']}")
        
        if 'icmp' in packet_info:
            icmp = packet_info['icmp']
            print(f"\n[ICMP]")
            print(f"  Type:           {icmp['type']}")
            print(f"  Code:           {icmp['code']}")
        
        if 'payload' in packet_info:
            try:
                payload = packet_info['payload'].decode('utf-8', errors='ignore')
                print(f"\n[Payload Preview]")
                print(f"  {payload[:50]}")
            except:
                print(f"\n[Payload] Binary data")
    
    def start_sniffing(self, packet_filter: str = "", iface: Optional[str] = None):
        """
        Start capturing packets.
        
        Args:
            packet_filter: BPF filter expression (e.g., "tcp port 80")
            iface: Network interface to use
        """
        print(f"\n{'='*70}")
        print(f"Starting packet capture...")
        print(f"Filter: {packet_filter if packet_filter else 'None (all traffic)'}")
        print(f"Interface: {iface if iface else 'Default'}")
        print(f"Packet count: {self.packet_count if self.packet_count > 0 else 'Unlimited'}")
        print(f"{'='*70}\n")
        
        try:
            # Windows requires special socket configuration
            if platform.system() == "Windows":
                sniff(
                    prn=self.packet_callback,
                    count=self.packet_count if self.packet_count > 0 else 0,
                    filter=packet_filter,
                    iface=iface or self.interface,
                    store=False,
                    socket=conf.L3socket
                )
            else:
                sniff(
                    prn=self.packet_callback,
                    count=self.packet_count if self.packet_count > 0 else 0,
                    filter=packet_filter,
                    iface=iface or self.interface,
                    store=False
                )
        except KeyboardInterrupt:
            print("\n\nCapture interrupted by user.")
            self.print_summary()
        except PermissionError:
            print("ERROR: This program requires administrator privileges!")
            print("Please run with 'sudo' on Linux/Mac or as Administrator on Windows.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)
    
    def print_summary(self):
        """Print a summary of captured packets."""
        print(f"\n{'='*70}")
        print(f"Capture Summary")
        print(f"{'='*70}")
        print(f"Total packets captured: {len(self.packets)}")
        
        # Count by protocol
        protocols = {}
        for packet in self.packets:
            for layer in packet['layers']:
                protocols[layer] = protocols.get(layer, 0) + 1
        
        if protocols:
            print("\nProtocol Distribution:")
            for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                print(f"  {protocol}: {count}")


def create_sniffer(packet_count: int = 0, interface: Optional[str] = None) -> PacketSniffer:
    """
    Factory function to create a packet sniffer instance.
    
    Args:
        packet_count: Number of packets to capture
        interface: Network interface to use
        
    Returns:
        PacketSniffer instance
    """
    return PacketSniffer(packet_count, interface)
