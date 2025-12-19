#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP or IP range, use --help")
    return options
def scan(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = scapy.srp(
            arp_request_broadcast,
            timeout=1,
            verbose=False
        )[0]

        client_list = []
        for element in answered_list:
            client_dict = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc
            }
            client_list.append(client_dict)

        return client_list

    except PermissionError:
        print("\n[!] Permission denied.")
        print("[!] Run this script as root:")
        print("    sudo python3 network_scanner.py -t <target>")
        exit(1)

    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        return []


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    # Print all discovered IPs and MACs neatly
    for client in results_list:
        print(f"{client['ip']:<16} {client['mac']}")

options = get_arguments()

try:
    scan_result = scan(options.target)

    if not scan_result:
        print("\n[-] No hosts found or scan failed.")
    else:
        print_result(scan_result)

except KeyboardInterrupt:
    print("\n[!] Scan interrupted by user. Exiting.")
