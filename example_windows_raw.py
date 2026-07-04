"""
Example: Windows Packet Capture using Raw Sockets
No external dependencies required - uses only Python standard library
Run as Administrator
"""

from packet_sniffer_windows import create_windows_sniffer


def main():
    """Run Windows packet sniffer."""
    print("\n" + "="*70)
    print("EXAMPLE: Windows Packet Sniffing (Raw Sockets)")
    print("="*70)
    print("\nThis example uses raw sockets to capture packets.")
    print("Requires: Administrator privileges")
    print("No external packet capture libraries needed!\n")
    
    # Create sniffer to capture 10 packets
    sniffer = create_windows_sniffer(packet_count=10)
    
    # Start sniffing
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()
