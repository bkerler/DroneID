import pwinput
import os
from scapy.all import *
from subprocess import Popen, PIPE
sudopw = None

def cexec(command, pipe=''):
    p = Popen(command, stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True)
    stdout_data = p.communicate(input=pipe)
    return stdout_data[0]

def sudo(command):
    global sudopw
    euid = os.geteuid()
    if euid != 0:
        if sudopw is None and not 'SUDO_UID' in os.environ:
            sudopw = pwinput.pwinput('Enter your sudo password: ')
        pr = ["sudo", "-S"]
    else:
        pr = []
    for cmd in command:
        pr.append(cmd)
    res = cexec(pipe=sudopw, command=pr)
    return res

def channel_hopping(interface):
    try:
        # List to store the channel number and Association Response packet
        result = []

        # Loop through channels 1 to 14
        for channel in range(1, 15):
            # Set the channel using Scapy's set_channel() function
            sudo(["iwconfig",interface,"channel",channel])

            # Sniff for Association Response packets on the current channel
            packets = sniff(filter="subtype 0x01", timeout=5)

            # Check if any Association Response packets were captured
            if packets:
                # Add the channel number and the first Association Response packet to the result list
                result.append((channel, packets[0]))

        return result

    except ImportError:
        raise ImportError("Scapy library is not installed.")

def search_interfaces():
    l = get_if_list()
    idict = IFACES.data
    interfaces = []
    for item in l:
        name = idict[item].name
        desc = idict[item].description
        if "wifi" in name.lower() or name[:2] == "wl":
            interfaces.append(name)
    return interfaces

def enable_monitor_mode(i2d, interface):
    info = cexec(["iw", i2d[interface][0], "info"])
    if "* monitor" not in info:
        print("Interface {interface} doesn't support monitoring mode :(")
        exit(1)
    if i2d[interface][1] != "monitor":
        print("Trying to enable monitoring mode")
        sudo(["ip", "link", "set", f"{interface}", "down"])
        sudo(["iwconfig", f"{interface}", "mode", "monitor"])
        sudo(["ip", "link", "set", f"{interface}", "up"])

def set_interface_channel(interface, channel):
    return sudo(["iwconfig", interface, "channel", str(channel)])

def extract_wifi_if_details(interface):
    i2d = {}
    devl = cexec(["iw", "dev"]).split("\n\t")
    ptype = ""
    for i in range(len(devl) - 1):
        if "Interface" in devl[i + 1]:
            iface = devl[i + 1].split(" ")[-1]
            dev = devl[i].split(" ")[-1].replace("#", "")
            for x in range(i + 2, len(devl), 1):
                if "type" in devl[x]:
                    ptype = devl[x].split(" ")[-1]
                    break
                elif "Interface" in devl[x]:
                    break
            i2d[iface] = (dev, ptype)
    if interface not in i2d:
        print("Invalid interface chosen.")
        exit(1)
    return i2d


def get_iw_interfaces(interfaces):
    print("Found interfaces:\n-----------------")
    for i in range(len(interfaces)):
        print(f"{i}:{interfaces[i]}")
    x = input("Enter interface number:")
    if int(x) < len(interfaces):
        interface = interfaces[int(x)]
    else:
        print("Invalid interface chosen.")
        exit(1)
    return interface
