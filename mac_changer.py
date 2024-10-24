import subprocess
import optparse
import re

def get_argunents():
    #for making it a command line application
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")

    #options contains the values of interface and newmac i.e. wlan0, 00:11:22:33:44:77
    #arguments contains -i and -m
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more infu")
    elif not options.new_mac:
        parser.error("[-] Please specify an interface, use --help for more infu")
    return options 

def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig ", interface," down "])
    subprocess.call(["ifconfig ", interface, " hw ether "+ new_mac])
    subprocess.call(["ifconfig ", interface, " up"])

def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    # this will search for mac looking texts using regex module
    #use pythex to create your own codes
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else: 
        print("[-] Could not read MAC Address")

options = get_argunents()

current_mac = get_current_mac(options.interface)
print("Current maac = ", str(current_mac))

#calling the function defined by us
change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to " + current_mac) 
else:
    print("[-] MAC address did not get changed.")