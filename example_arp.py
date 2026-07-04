"""
Example 4: ARP Traffic Capture
Capture ARP requests and replies (network discovery)
"""

from packet_sniffer import create_sniffer


def main():
    """Run ARP packet sniffer."""
    print("\n" + "="*70)
    print("EXAMPLE 4: ARP Traffic Capture")
    print("="*70)
    print("This example captures ARP packets (network discovery).\n")
    
    # Create sniffer
    sniffer = create_sniffer(packet_count=10)
    
    # Capture ARP traffic
    arp_filter = "arp"
    
    print("Starting capture for ARP traffic...\n")
    sniffer.start_sniffing(packet_filter=arp_filter)
    
    # Print summary
    sniffer.print_summary()


if __name__ == "__main__":
    main()
