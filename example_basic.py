"""
Example 1: Basic Packet Sniffing
Capture the first 10 packets with no filter (all traffic)
"""

from packet_sniffer import create_sniffer


def main():
    """Run basic packet sniffer."""
    print("\n" + "="*70)
    print("EXAMPLE 1: Basic Packet Sniffing")
    print("="*70)
    print("This example captures the first 10 packets of all traffic.\n")
    
    # Create sniffer to capture 10 packets
    sniffer = create_sniffer(packet_count=10)
    
    # Start sniffing (no filter = all traffic)
    sniffer.start_sniffing()
    
    # Print summary
    sniffer.print_summary()


if __name__ == "__main__":
    main()
