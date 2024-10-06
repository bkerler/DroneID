#!/usr/bin/env python3
# (c) 2024 B.Kerler
import os
import sys
from subprocess import Popen, PIPE, STDOUT
import argparse
import json

from Library.utils import search_interfaces, get_iw_interfaces, extract_wifi_if_details, enable_monitor_mode, \
    set_interface_channel, cexec
from OpenDroneID.wifi_parser import oui_to_parser
from scapy.all import *
from scapy.layers.dot11 import Dot11EltVendorSpecific, Dot11, Dot11Elt
import zmq


context = zmq.Context()
socket = context.socket(zmq.XPUB)


def pcapng_parser(filename: str):
    for packet in PcapReader(filename):
        try:
            filter_frames(packet)
        except Exception as err:
            pass


def filter_frames(packet: Packet) -> None:
    global socket
    macdb = {}
    pt = packet.getlayer(Dot11)
    # subtype 0 = Management, 0x8 = Beacon, 0x13 = Action
    # NAN Service Discovery Frames shall be encoded in 0x13 and contain DRI Info
    # NAN Synchronization Beacon shall be encoded in 0x8 but doesn't contain DRI Info
    # Broadcast Message can only happen on channel 6 and contains DRI Info
    if pt.subtype in [0, 0x8, 0x13]:
        if packet.haslayer(Dot11EltVendorSpecific):  # check vendor specific ID -> 221
            vendor_spec: Dot11EltVendorSpecific = packet.getlayer(Dot11EltVendorSpecific)
            mac = packet.payload.addr2
            macdb[mac] = []
            while vendor_spec:
                parser = oui_to_parser(vendor_spec.oui, vendor_spec.info)
                if parser is not None:
                    if "DRI" in parser.msg:
                        macdb[mac] = parser.msg["DRI"]
                    elif "Beacon" in parser.msg:
                        macdb[mac] = parser.msg["Beacon"]
                    if socket:
                        socket.send_string(json.dumps(macdb))
                        print(json.dumps(macdb))
                break

def main():
    info = "Host-side receiver for OpenDrone ID wifi (c) B.Kerler 2024"
    print(info)
    aparse = argparse.ArgumentParser(description=info)
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable zmq")
    aparse.add_argument("--zmqport", default="4225", help="Define zmq port")
    aparse.add_argument("--zmqhost", default="127.0.0.1", help="Define zmq host")
    aparse.add_argument("--interface", help="Define zmq host")
    aparse.add_argument("--pcap", help="Use pcap file")
    args = aparse.parse_args()
    current_python_executable = cexec(["readlink", "-f", f"{sys.executable}"]).replace("\n", "")
    res = cexec(["getcap", f"{current_python_executable}"])
    if not "cap_net_admin" in res or not "cap_net_raw" in res:
        print(
            f"Please run: \"sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' {current_python_executable}\" before running this script.")
        exit(1)

    interfaces = search_interfaces()
    if args.interface is None and args.pcap is None:
        interface = get_iw_interfaces(interfaces)
    elif args.interface is not None:
        interface = args.interface
    elif args.pcap is not None:
        interface = None
    else:
        print("--pcap [file.pcapng] or --interface [wifi_monitor_interface] needed")
        exit(1)

    if interface is not None:
        i2d = extract_wifi_if_details(interface)
        enable_monitor_mode(i2d, interface)
        print("Setting wifi channel 6")
        set_interface_channel(interface,6)

    zthread = None
    if args.zmq:
        url = f"tcp://{args.zmqhost}:{args.zmqport}"
        socket.setsockopt(zmq.XPUB_VERBOSE, True)
        socket.bind(url)

        def zmq_thread(socket):
            try:
                while True:
                    event = socket.recv()
                    # Event is one byte 0=unsub or 1=sub, followed by topic
                    if event[0] == 1:
                        log("new subscriber for", event[1:])
                    elif event[0] == 0:
                        log("unsubscribed", event[1:])
            except zmq.error.ContextTerminated:
                pass

        def log(*msg):
            s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print("%s:" % s, *msg, end="\n", file=sys.stderr)

        from threading import Thread
        zthread = Thread(target=zmq_thread, args=[socket], daemon=True, name='zmq')
        zthread.start()

    if interface is not None:
        #success = switch_dev_mode(interface, "monitor")
        sniffer = AsyncSniffer(
            iface=interface,
            lfilter=lambda s: s.getlayer(Dot11).subtype==0x8,
            prn=filter_frames,
        )
        sniffer.start()
        print(f"Starting sniffer on interface {interface}")
        while True:
            try:
                sniffer.join()
                time.sleep(1)
            except KeyboardInterrupt:
                break
        print(f"Stopping sniffer on interface {interface}")
        sniffer.stop()
        if args.zmq:
            zthread.join()
        #success = switch_dev_mode(interface, "managed")
    else:
        pcapng_parser(args.pcap)





if __name__ == "__main__":
    main()
