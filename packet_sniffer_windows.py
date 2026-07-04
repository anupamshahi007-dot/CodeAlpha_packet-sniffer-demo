"""
Windows-Compatible Packet Sniffer using Raw Sockets
Works without requiring WinPcap or Npcap installation
"""

import socket
import struct
import textwrap
import sys
import platform

if platform.system() != "Windows":
    print("This version is designed for Windows.")
    print("Use the standard packet_sniffer.py on Linux/macOS with Scapy.")
    sys.exit(1)


class WindowsPacketSniffer:
    """Windows-compatible packet sniffer using raw sockets."""
    
    def __init__(self, packet_count: int = 0):
        """
        Initialize the Windows packet sniffer.
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
        """
        self.packet_count = packet_count
        self.packets = []
        self.packet_num = 0
    
    def format_ipv4_packet(self, data):
        """Parse and format IPv4 packet."""
        if len(data) < 20:
            return None, 0
        
        version_header_length = data[0]
        header_length = (version_header_length & 15) * 4
        ttl = data[8]
        proto = data[9]
        src = '.'.join(map(str, data[12:16]))
        dest = '.'.join(map(str, data[16:20]))
        
        return self.format_ipv4(version_header_length, header_length, ttl, proto, src, dest), header_length
    
    def format_icmp_packet(self, data):
        """Parse and format ICMP packet."""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum
    
    def format_tcp_segment(self, data):
        """Parse and format TCP segment."""
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, offset
    
    def format_udp_segment(self, data):
        """Parse and format UDP segment."""
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, length
    
    def format_ipv4(self, version_header_length, header_length, ttl, proto, src, dest):
        """Format IPv4 information."""
        version = version_header_length >> 4
        header_length = version_header_length & 15
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        protocol = protocols.get(proto, 'Other')
        
        return version, header_length, ttl, protocol, src, dest
    
    def display_ipv4_info(self, version, header_length, ttl, proto, src, dest):
        """Display IPv4 packet info."""
        print(f"  IPv4:")
        print(f"    Version: {version}")
        print(f"    Header Length: {header_length}")
        print(f"    TTL: {ttl}")
        print(f"    Protocol: {proto}")
        print(f"    Source: {src}")
        print(f"    Destination: {dest}")
    
    def display_icmp_info(self, icmp_type, code, checksum):
        """Display ICMP packet info."""
        print(f"  ICMP:")
        print(f"    Type: {icmp_type}")
        print(f"    Code: {code}")
        print(f"    Checksum: {checksum}")
    
    def display_tcp_info(self, src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, 
                        flag_psh, flag_rst, flag_syn, flag_fin, offset):
        """Display TCP segment info."""
        print(f"  TCP:")
        print(f"    Source Port: {src_port}")
        print(f"    Destination Port: {dest_port}")
        print(f"    Sequence: {sequence}")
        print(f"    Acknowledgment: {acknowledgment}")
        print(f"    Offset: {offset}")
        print(f"    Flags:")
        print(f"      URG: {flag_urg}")
        print(f"      ACK: {flag_ack}")
        print(f"      PSH: {flag_psh}")
        print(f"      RST: {flag_rst}")
        print(f"      SYN: {flag_syn}")
        print(f"      FIN: {flag_fin}")
    
    def display_udp_info(self, src_port, dest_port, length):
        """Display UDP segment info."""
        print(f"  UDP:")
        print(f"    Source Port: {src_port}")
        print(f"    Destination Port: {dest_port}")
        print(f"    Length: {length}")
    
    def display_payload(self, data, size):
        """Display packet payload."""
        if size > 0:
            print(f"  Payload ({size} bytes):")
            print(self.format_payload(data, size))
    
    def format_payload(self, data, size):
        """Format payload data for display."""
        lines = textwrap.wrap(data.hex(), 32)
        payload_text = ''
        for line in lines:
            payload_text += line + '\n'
        return payload_text
    
    def start_sniffing(self):
        """Start capturing packets using raw sockets."""
        print("\n" + "="*70)
        print("Windows Packet Sniffer (Raw Socket Mode)")
        print("="*70)
        print(f"Packet count: {self.packet_count if self.packet_count > 0 else 'Unlimited'}")
        print("="*70 + "\n")
        
        try:
            # Create raw socket
            # IPPROTO_IP = 0, SOCK_RAW = 3
            if platform.system() == "Windows":
                sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sniffer_socket.bind((socket.gethostbyname(socket.gethostname()), 0))
                sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                print("This version is for Windows only.")
                return
            
            print(f"Listening for packets...\n")
            
            while True:
                if self.packet_count > 0 and self.packet_num >= self.packet_count:
                    break
                
                try:
                    raw_buffer = sniffer_socket.recvfrom(65535)[0]
                    self.packet_num += 1
                    self.display_packet(raw_buffer)
                except Exception as e:
                    continue
            
            print("\nCapture complete.")
            self.print_summary()
            
            if platform.system() == "Windows":
                sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            
        except PermissionError:
            print("ERROR: This program requires administrator privileges!")
            print("Please run as Administrator on Windows.")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)
    
    def display_packet(self, data):
        """Display packet information."""
        print("="*70)
        print(f"Packet #{self.packet_num} | Size: {len(data)} bytes")
        print("="*70)
        
        # Parse IPv4
        ipv4_packet = data[:20]
        version, header_length, ttl, proto, src, dest = self.format_ipv4_packet(ipv4_packet)[0]
        self.display_ipv4_info(version, header_length, ttl, proto, src, dest)
        
        # Parse protocol-specific data
        if proto == 'ICMP':
            icmp_packet = data[20:28]
            icmp_type, code, checksum = self.format_icmp_packet(icmp_packet)
            self.display_icmp_info(icmp_type, code, checksum)
        
        elif proto == 'TCP':
            tcp_segment = data[20:]
            src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, offset = self.format_tcp_segment(tcp_segment)
            self.display_tcp_info(src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, 
                                 flag_psh, flag_rst, flag_syn, flag_fin, offset)
        
        elif proto == 'UDP':
            udp_segment = data[20:]
            src_port, dest_port, length = self.format_udp_segment(udp_segment)
            self.display_udp_info(src_port, dest_port, length)
        
        print()
    
    def print_summary(self):
        """Print capture summary."""
        print("="*70)
        print("Capture Summary")
        print("="*70)
        print(f"Total packets captured: {self.packet_num}\n")


def create_windows_sniffer(packet_count: int = 0):
    """Create a Windows packet sniffer instance."""
    return WindowsPacketSniffer(packet_count)
