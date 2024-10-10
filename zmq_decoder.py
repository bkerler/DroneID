#!/usr/bin/env python3
import json
import sys
import time
from io import BytesIO

import zmq
import argparse
from threading import Thread
from OpenDroneID.decoder import decode_ble, decode
from OpenDroneID.utils import structhelper_io


def log(*msg):
    s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print("%s:" % s, *msg, end="\n", file=sys.stderr)

stop = False

def zmq_thread(socket):
    global stop
    try:
        while not stop:
            event = socket.recv()
            # Event is one byte 0=unsub or 1=sub, followed by topic
            if event[0] == 1:
                log("new subscriber for", event[1:])
            elif event[0] == 0:
                log("unsubscribed", event[1:])
    except zmq.error.ContextTerminated:
        pass


def decoder_thread(socket, pub):
    global stop
    try:
        while not stop:
            try:
                data = socket.recv(zmq.NOBLOCK)
            except:
                data = None
            if data is not None:
                dc = json.loads(data.decode('utf-8'))
                if "AUX_ADV_IND" in dc and "aa" in dc["AUX_ADV_IND"] and dc["AUX_ADV_IND"]["aa"] == 0x8e89bed6:
                    if "AdvData" in dc:
                        advdata = bytearray(bytes.fromhex(dc["AdvData"]))
                        if advdata[1] == 0x16 and int.from_bytes(advdata[2:4], 'little') == 0xFFFA and advdata[
                            4] == 0x0D:
                            # Open Drone ID
                            print("Open Drone ID BT4/BT5\n-------------------------\n")
                            json_data = decode_ble(advdata)
                            if pub:
                                pub.send_string(json_data)
                            print(json_data)
                            print()
                            sys.stdout.flush()
                elif "DroneID" in dc:
                    for mac in dc["DroneID"]:
                        # Open Drone ID
                        field = dc["DroneID"][mac]
                        print("Open Drone ID WIFI\n-------------------------\n")
                        if "AdvData" in field:
                            try:
                                fields = decode(structhelper_io(bytes.fromhex(field["AdvData"])))
                                for field in fields:
                                    field["MAC"]=mac
                                    json_data = json.dumps(field)
                                    if pub:
                                        pub.send_string(json_data)
                                    print(json_data)
                            except Exception as e:
                                print(e)
                                pass
                        else:
                            try:
                                field["MAC"]=mac
                                json_data = json.dumps(field)
                                if pub:
                                    pub.send_string(json_data)
                                print(json_data)
                            except Exception as e:
                                print(e)
                                pass
                        print()
                        sys.stdout.flush()
    except zmq.error.ContextTerminated:
        pass

def main():
    global stop
    info = "ZMQ decoder for BLE4/5 + WIFI ZMQ clients (c) B.Kerler 2024"
    aparse = argparse.ArgumentParser(description=info)
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable zmq")
    aparse.add_argument("--zmqsetting", default="127.0.0.1:4224", help="Define zmq server settings")
    aparse.add_argument("--zmqclients", default="127.0.0.1:4222,127.0.0.1:4223", help="Define bluetooth/wifi zmq clients")
    args = aparse.parse_args()

    sctx = zmq.Context()
    pub = sctx.socket(zmq.XPUB)
    sctx.setsockopt(zmq.XPUB_VERBOSE, True)
    purl = f"tcp://{args.zmqsetting}"
    pub.bind(purl)

    zthread = Thread(target=zmq_thread, args=[pub], daemon=True, name='zmq')
    zthread.start()

    clients = args.zmqclients.split(",")
    subs = []
    for client in clients:
        url=f"tcp://{client}"
        ctx = zmq.Context()
        sub = ctx.socket(zmq.SUB)
        sub.setsockopt(zmq.SUBSCRIBE, bytes('{"AUX_ADV_IND"', 'utf-8'))
        sub.setsockopt(zmq.SUBSCRIBE, bytes('{"DroneID"', 'utf-8'))
        if sub.connect(url):
            zthread = Thread(target=decoder_thread, args=[sub,pub], daemon=True, name='zmq')
            zthread.start()
            subs.append(zthread)

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
    stop = True
    for thread in subs:
        thread.join()
    zthread.join()

if __name__ == "__main__":
    main()
