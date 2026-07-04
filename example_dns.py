"""
Example 3: DNS Traffic Capture
Capture DNS queries (UDP port 53)
"""

from packet_sniffer import create_sniffer


def main():
    """Run DNS packet sniffer."""
    print("\n" + "="*70)
    print("EXAMPLE 3: DNS Traffic Capture")
    print("="*70)
    print("This example captures DNS queries on UDP port 53.\n")
    
    # Create sniffer
    sniffer = create_sniffer(packet_count=15)
    
    # Capture DNS traffic (port 53)
    dns_filter = "udp port 53"
    
    print("Starting capture for DNS traffic...\n")
    sniffer.start_sniffing(packet_filter=dns_filter)
    
    # Print summary
    sniffer.print_summary()


if __name__ == "__main__":
    main()
