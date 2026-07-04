"""
Example 5: Traffic from Specific IP
Capture packets to/from a specific IP address
"""

from packet_sniffer import create_sniffer


def main():
    """Run sniffer for specific IP traffic."""
    print("\n" + "="*70)
    print("EXAMPLE 5: Traffic from Specific IP")
    print("="*70)
    print("This example captures packets to/from a specific IP address.\n")
    
    # Replace with the IP you want to monitor
    target_ip = "8.8.8.8"  # Google DNS as example
    
    # Create sniffer
    sniffer = create_sniffer(packet_count=20)
    
    # Capture traffic from/to specific IP
    ip_filter = f"host {target_ip}"
    
    print(f"Starting capture for traffic to/from {target_ip}...\n")
    sniffer.start_sniffing(packet_filter=ip_filter)
    
    # Print summary
    sniffer.print_summary()


if __name__ == "__main__":
    main()
