#!/usr/bin/env python3
# (c) B. Kerler 2025

import os
import sys
import argparse


try:
    from sniffle.python_cli.sniff_receiver import main
except ImportError:
    script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "sniffle", "python_cli")
    sys.path.insert(0, script_path)
    from sniff_receiver import main

if __name__ == "__main__":
    aparse = argparse.ArgumentParser(description="Host-side receiver for Sniffle BLE5 sniffer")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baud rate")
    aparse.add_argument("-c", "--advchan", default=40, choices=[37, 38, 39], type=int,
            help="Advertising channel to listen on")
    aparse.add_argument("-p", "--pause", action="store_true",
            help="Pause sniffer after disconnect")
    aparse.add_argument("-r", "--rssi", default=-128, type=int,
            help="Filter packets by minimum RSSI")
    aparse.add_argument("-m", "--mac", default=None, help="Filter packets by advertiser MAC")
    aparse.add_argument("-i", "--irk", default=None, help="Filter packets by advertiser IRK")
    aparse.add_argument("-S", "--string", default=None,
            help="Filter for advertisements containing the specified string")
    aparse.add_argument("-a", "--advonly", action="store_true",
            help="Passive scanning, don't follow connections")
    aparse.add_argument("-A", "--scan", action="store_true",
            help="Active scanning, don't follow connections")
    aparse.add_argument("-e", "--extadv", action="store_true",
            help="Capture BT5 extended (auxiliary) advertising")
    aparse.add_argument("-H", "--hop", action="store_true",
            help="Hop primary advertising channels in extended mode")
    aparse.add_argument("-l", "--longrange", action="store_true",
            help="Use long range (coded) PHY for primary advertising")
    aparse.add_argument("-q", "--quiet", action="store_true",
            help="Don't display empty packets")
    aparse.add_argument("-Q", "--preload", default=None, help="Preload expected encrypted "
            "connection parameter changes")
    aparse.add_argument("-n", "--nophychange", action="store_true",
            help="Ignore encrypted PHY mode changes")
    aparse.add_argument("-C", "--crcerr", action="store_true",
            help="Capture packets with CRC errors")
    aparse.add_argument("-d", "--decode", action="store_true",
            help="Decode advertising data")
    aparse.add_argument("-o", "--output", default=None, help="PCAP output file name")
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable zmq")
    aparse.add_argument("--zmqsetting", default="127.0.0.1:4222", help="Define zmq server settings")
    aparse.add_argument("-v", "--verbose", action="store_true", help="Print messages")
    args = aparse.parse_args()
    args.zmq = True
    args.longrange = True
    args.extadv = True
    main(args)
