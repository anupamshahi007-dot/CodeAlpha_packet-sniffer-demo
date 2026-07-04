"""
Example 2: HTTP/HTTPS Traffic Capture
Capture packets on port 80 (HTTP) and 443 (HTTPS)
"""

from packet_sniffer import create_sniffer


def main():
    """Run HTTP/HTTPS packet sniffer."""
    print("\n" + "="*70)
    print("EXAMPLE 2: HTTP/HTTPS Traffic Capture")
    print("="*70)
    print("This example captures HTTP (port 80) and HTTPS (port 443) traffic.\n")
    
    # Create sniffer
    sniffer = create_sniffer(packet_count=20)
    
    # Capture TCP packets on port 80 or 443
    # BPF (Berkeley Packet Filter) syntax
    http_filter = "tcp port 80 or tcp port 443"
    
    print("Starting capture for HTTP/HTTPS traffic...\n")
    sniffer.start_sniffing(packet_filter=http_filter)
    
    # Print summary
    sniffer.print_summary()


if __name__ == "__main__":
    main()
