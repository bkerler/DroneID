#!/usr/bin/env python3
# (c) B. Kerler 2024

import argparse
import os
import sys
import time

from OpenDroneID.Messages.definitions import ProtoVersions
from OpenDroneID.encoder import OpenDroneID
from OpenDroneID.json_parser import json_to_packets
from OpenDroneID.selftest import self_test_encoder, test_dict
from sniffle.python_cli.sniffle.constants import BLE_ADV_AA
from sniffle.python_cli.sniffle.sniffle_hw import SniffleHW, PhyMode

# global variable to access hardware
HW = None


def main():
    print("\nOpenDroneID spoofer (c) B.Kerler 2024\n-------------------------------------\n")
    aparse = argparse.ArgumentParser(description="OpenID drone spoofer")
    aparse.add_argument("dronefile", default="drone.json", nargs="?")
    aparse.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
    aparse.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baudrate")
    aparse.add_argument("-v", "--selftest", action="store_true", help="Run Self-Test")
    aparse.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int,
                        help="Advertising channel")
    args = aparse.parse_args()
    if args.selftest:
        self_test_encoder()
        test_dict()

    if os.path.exists(args.dronefile):
        dronefile = args.dronefile
    else:
        print(f"File {args.dronefile} doesn't exist. Aborting.")
        sys.exit(1)

    # timeout in ms
    timeout = 50
    global HW
    HW = SniffleHW(args.serport, baudrate=args.baudrate)

    # set the advertising channel (and return to ad-sniffing mode)
    HW.cmd_chan_aa_phy(args.advchan, BLE_ADV_AA, PhyMode.PHY_CODED_S8)

    # pause after sniffing
    HW.cmd_pause_done(True)

    # Accept/follow connections
    HW.cmd_follow(False)

    # turn off RSSI filter
    HW.cmd_rssi()

    # Turn off MAC filter
    HW.cmd_mac()

    # initiator doesn't care about this setting, it always accepts aux
    HW.cmd_auxadv(True)

    HW.random_addr()

    # advertise roughly every 200 ms
    HW.cmd_adv_interval(timeout)

    # reset preloaded encrypted connection interval changes
    HW.cmd_interval_preload()

    # zero timestamps and flush old packets
    HW.mark_and_flush()

    # advertising and scan response data
    uuid_type = int.to_bytes(0x16, 1, 'little')
    uuid = int.to_bytes(0xfffa, 2, 'little')
    appcode = int.to_bytes(0x0D, 1, 'little')
    counter = 0
    packets = json_to_packets(dronefile)
    # Packets are ordered by droneid and seqno,
    # now we need to sort it by seqno to simulate movements
    send_data = {}
    for droneid in packets:
        mac = None
        adi = int.to_bytes(0x161E, 2, 'little')
        if "MAC" in packets[droneid]:
            mac = [int(h, 16) for h in reversed(packets[droneid]["MAC"].split(":"))]
        if "ADI" in packets[droneid]:
            adi = int.to_bytes(packets[droneid]["ADI"], 2, 'little')
        for seqno in packets[droneid]:
            if seqno in ["MAC","ADI"]:
                continue
            msgs = packets[droneid][seqno]
            msg_counter = int.to_bytes(seqno, 1, 'little')
            data = bytes(uuid_type + uuid + appcode + msg_counter +
                         OpenDroneID(protocol_version=ProtoVersions.F3411_19.value,
                                     msgs=msgs).parse())
            if len(data) < 245:
                adv_data = int.to_bytes(len(data), 1, 'little') + data
                counter += 1
                sys.stdout.flush()
                if seqno not in send_data:
                    send_data[seqno] = [(droneid,mac,adi,adv_data)]
                else:
                    send_data[seqno].append((droneid,mac,adi,adv_data))

    # Send the packets
    for seqno in send_data:
        for droneid, mac, adi, packet in send_data[seqno]:
            if mac is None:
                HW.random_addr()
            else:
                HW.cmd_setaddr(mac, is_random=False)
            print(f"Sending packet {droneid} -> Seqno: {seqno}")
            # now enter advertiser mode, mode 0 = Non-Connectable Non-scannable
            HW.cmd_advertise_ext(advData=packet, mode=0, adi=adi, phy1=PhyMode.PHY_1M,
                                 phy2=PhyMode.PHY_CODED_S8)
            time.sleep((timeout / 1000) * 2)
            HW.cmd_scan()
            HW.cmd_advertise_ext(advData=packet, mode=0, adi=adi, phy1=PhyMode.PHY_CODED_S8,
                                 phy2=PhyMode.PHY_CODED_S8)
            time.sleep((timeout/1000)*2)
            HW.cmd_scan()
    print("Done.")

if __name__ == "__main__":
    main()
