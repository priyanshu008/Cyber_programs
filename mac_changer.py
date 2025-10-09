#!/usr/bin/env python

import subprocess
import argparse
import re
import platform
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to check/change MAC")
    parser.add_argument("-m", "--mac", dest="new_mac", help="New MAC address (Linux only)")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    return options

def get_current_mac(interface):
    os_name = platform.system()
    
    if os_name == "Linux":
        ifconfig_result = subprocess.check_output(["ifconfig", interface]).decode()
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
        if mac_address_search_result:
            return mac_address_search_result.group(0)
    elif os_name == "Windows":
        output = subprocess.check_output(["getmac", "/v", "/fo", "list"]).decode()
        pattern = re.compile(r"Physical Address:\s+([0-9A-Fa-f:-]{17})")
        matches = pattern.findall(output)
        if matches:
            return matches[0]
    return None

def change_mac_linux(interface, new_mac):
    print(f"[+] Changing MAC address for {interface} to {new_mac}")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def main():
    options = get_arguments()
    os_name = platform.system()
    
    current_mac = get_current_mac(options.interface)
    print(f"Current MAC = {current_mac}")

    if options.new_mac:
        if os_name == "Linux":
            change_mac_linux(options.interface, options.new_mac)
            current_mac = get_current_mac(options.interface)
            if current_mac == options.new_mac:
                print(f"[+] MAC address was successfully changed to {current_mac}")
            else:
                print("[-] MAC address did not get changed.")
        elif os_name == "Windows":
            print("[-] Changing MAC on Windows requires admin and registry edits. Only reading MAC is supported.")
    else:
        print("[*] No new MAC provided. Only showing current MAC.")

if __name__ == "__main__":
    main()