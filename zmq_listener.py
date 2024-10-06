#!/usr/bin/env python3
import json
import sys
import time
import zmq
import argparse

from OpenDroneID.decoder import decode_ble

def log(*msg):
    s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print("%s:" % s, *msg, end="\n", file=sys.stderr)

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

def main():
    aparse = argparse.ArgumentParser(description="ZMQ receiver for Sniffle BLE4/5 sniffer")
    aparse.add_argument("--zmq", default="4224", help="Enable zmq server")
    aparse.add_argument("--zmqport", default="4224", help="Define server zmq port")
    aparse.add_argument("--zmqhost", default="127.0.0.1", help="Define server zmq host")
    aparse.add_argument("--port", default="4222", help="Define sniffle zmq port")
    aparse.add_argument("--host", default="127.0.0.1", help="Define sniffle zmq host")
    args = aparse.parse_args()


    ctx = zmq.Context()
    sctx = zmq.Context()
    sub = ctx.socket(zmq.SUB)
    pub = sctx.socket(zmq.XPUB)

    url = f"tcp://{args.host}:{args.port}"
    purl = f"tcp://{args.zmqhost}:{args.zmqport}"
    sub.connect(url)
    pub.bind(purl)
    pkttype = "AUX_ADV_IND"
    sub.setsockopt(zmq.SUBSCRIBE, bytes('{"'+pkttype+'"','utf-8'))
    time.sleep(1)

    from threading import Thread
    zthread = Thread(target=zmq_thread, args=[pub], daemon=True, name='zmq')
    zthread.start()

    while True:
        try:
            data=sub.recv(zmq.NOBLOCK)
        except:
            data = None
        if data is not None:
            dc=json.loads(data.decode('utf-8'))[pkttype]
            if "Pkt" in dc and "aa" in dc["Pkt"] and dc["Pkt"]["aa"]==0x8e89bed6:
                if "AdvData" in dc:
                    advdata=bytearray(bytes.fromhex(dc["AdvData"]))
                    if advdata[1] == 0x16 and int.from_bytes(advdata[2:4], 'little') == 0xFFFA and advdata[4] == 0x0D:
                        # Open Drone ID
                        print("Open Drone ID\n-------------------------\n")
                        json_data = decode_ble(advdata)
                        if args.zmq:
                            pub.send_string(json_data)
                        print(json_data)
                        print()
                        sys.stdout.flush()

if __name__ == "__main__":
    main()

