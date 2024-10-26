#!/usr/bin/env python3
# (c) B. Kerler 2024
# Kevin Leon 2024

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

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
WAIT_LOOP = 10

class DroneIDSpoof:
    def __init__(self) -> None:
        self.msg       = None
        self.msgsize   = 0
        self.timeout   = 50
        self.hw        = None
        self.args      = None
        self.dronefile = None
        self.run_loop  = False
    
    def load_args(self, args=None) -> None:
        aparser = argparse.ArgumentParser(description="OpenID drone spoofer")
        aparser.add_argument("dronefile", default="drone.json", nargs="?")
        aparser.add_argument("-s", "--serport", default=None, help="Sniffer serial port name")
        aparser.add_argument("-b", "--baudrate", default=None, help="Sniffer serial port baudrate")
        aparser.add_argument("-v", "--selftest", action="store_true", help="Run Self-Test")
        aparser.add_argument("-c", "--advchan", default=37, choices=[37, 38, 39], type=int, help="Advertising channel")
        aparser.add_argument("-loop", "--loop", action="store_true", help="Loop the packets")
        self.args = aparser.parse_args(args)
    
    def parse_args(self) -> None:
        if self.args.selftest:
            self_test_encoder()
            test_dict()

        if os.path.exists(self.args.dronefile):
            self.dronefile = self.args.dronefile
        else:
            print(f"File {self.args.dronefile} doesn't exist. Aborting.")
            sys.exit(1)
        
        if self.args.loop:
            self.run_loop = True
    
    def init_hw(self) -> None:
        self.hw = SniffleHW(self.args.serport, baudrate=self.args.baudrate)

        # set the advertising channel (and return to ad-sniffing mode)
        self.hw.cmd_chan_aa_phy(self.args.advchan, BLE_ADV_AA, PhyMode.PHY_CODED_S8)

        # pause after sniffing
        self.hw.cmd_pause_done(True)

        # Accept/follow connections
        self.hw.cmd_follow(False)

        # turn off RSSI filter
        self.hw.cmd_rssi()

        # Turn off MAC filter
        self.hw.cmd_mac()

        # initiator doesn't care about this setting, it always accepts aux
        self.hw.cmd_auxadv(True)

        self.hw.random_addr()

        # advertise roughly every 200 ms
        self.hw.cmd_adv_interval(self.timeout)

        # reset preloaded encrypted connection interval changes
        self.hw.cmd_interval_preload()

        # zero timestamps and flush old packets
        self.hw.mark_and_flush()
    
    def send_adv_rsp_packets(self):
        # advertising and scan response data
        uuid_type = int.to_bytes(0x16, 1, 'little')
        uuid = int.to_bytes(0xfffa, 2, 'little')
        appcode = int.to_bytes(0x0D, 1, 'little')
        counter = 0
        packets = json_to_packets(self.dronefile)
        # Packets are ordered by droneid and seqno, now we need to sort it by seqno to simulate movements
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
                    advData = int.to_bytes(len(data), 1, 'little') + data
                    counter += 1
                    sys.stdout.flush()
                    if seqno not in send_data:
                        send_data[seqno] = [(droneid,mac,adi,advData)]
                    else:
                        send_data[seqno].append((droneid,mac,adi,advData))

        # Send the packets
        for seqno in send_data:
            for droneid, mac, adi, packet in send_data[seqno]:
                if mac is None:
                    self.hw.random_addr()
                else:
                    self.hw.cmd_setaddr(mac, is_random=False)
                print(f"Sending packet {droneid} -> Seqno: {seqno}")
                # now enter advertiser mode, mode 0 = Non-Connectable Non-scannable
                self.hw.cmd_advertise_ext(advData=packet, mode=0, adi=adi, phy1=PhyMode.PHY_1M,
                                    phy2=PhyMode.PHY_CODED_S8)
                time.sleep((self.timeout / 1000) * 2)
                self.hw.cmd_scan()
                self.hw.cmd_advertise_ext(advData=packet, mode=0, adi=adi, phy1=PhyMode.PHY_CODED_S8,
                                    phy2=PhyMode.PHY_CODED_S8)
                time.sleep((self.timeout/1000)*2)
                self.hw.cmd_scan()
        print("Done.")

    def stop_running(self):
        self.run_loop = False

    def main(self, args=None):
        self.load_args(args)
        self.parse_args()
        self.init_hw()
        if self.run_loop:
            print("Looping packets...")
            print("Press Ctrl+C to stop.")
            while self.run_loop:
                self.send_adv_rsp_packets()
                time.sleep(WAIT_LOOP)
        else:
            self.send_adv_rsp_packets()
if __name__ == "__main__":
    drone_spoof = DroneIDSpoof()
    try:
        drone_spoof.main()
    except KeyboardInterrupt:
        drone_spoof.stop_running()
        print("Exiting...")
        sys.exit(0)
