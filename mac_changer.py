import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="The interface")
    parser.add_option("-m", "--mac", dest="new_mac", help="The new MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-]Use -i or --i to specify the interface, use --help for more info")
    if not options.new_mac:
        parser.error("[-]Use -m or --mac to specify the new MAC address, use --help for more info")
    return options.interface, options.new_mac


def change_mac(interface, new_mac):
    print("[+] Changing MAC address of", interface, "to", new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    ifconfig_result = str(subprocess.check_output(["ifconfig",interface]))
    mac_address_result = re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_result:
        return mac_address_result
    else:
        print("[-]Could not read MAC address")

(interface, new_mac) = get_arguments()
current_mac = get_current_mac(interface)
print("Current MAC: " + str(current_mac))
change_mac(interface, new_mac)
current_mac = get_current_mac(interface)
if current_mac==new_mac:
    print("MAC changed successfully to:",new_mac)



