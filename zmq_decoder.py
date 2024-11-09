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
    print(f"{s}:", *msg, end="\n", file=sys.stderr)


stop = False


def zmq_thread(pub_socket):
    global stop
    try:
        while not stop:
            try:
                event = pub_socket.recv()
                # Event is one byte 0=unsub or 1=sub, followed by topic
                if event[0] == 1:
                    log("new subscriber for", event[1:])
                elif event[0] == 0:
                    log("unsubscribed", event[1:])
            except zmq.error.ContextTerminated:
                break
            except Exception as e:
                log("ZMQ Thread Error:", e)
    except zmq.error.ContextTerminated:
        pass


def decoder_thread(socket, pub, verbose):
    global stop
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    try:
        while not stop:
            socks = dict(poller.poll(1000))  # Poll with 1000ms timeout
            if socket in socks and socks[socket] == zmq.POLLIN:
                try:
                    data = socket.recv()
                except zmq.error.ZMQError as e:
                    if verbose:
                        log("Receive Error:", e)
                    continue

                if data:
                    try:
                        dc = json.loads(data.decode('utf-8'))
                    except json.JSONDecodeError as e:
                        if verbose:
                            log("JSON Decode Error:", e)
                        continue

                    if "AUX_ADV_IND" in dc and "aa" in dc["AUX_ADV_IND"] and dc["AUX_ADV_IND"]["aa"] == 0x8e89bed6:
                        if "AdvData" in dc:
                            try:
                                advdata = bytearray(bytes.fromhex(dc["AdvData"]))
                            except ValueError as e:
                                if verbose:
                                    log("AdvData Decode Error:", e)
                                continue

                            if advdata[1] == 0x16 and int.from_bytes(advdata[2:4], 'little') == 0xFFFA and advdata[4] == 0x0D:
                                # Open Drone ID
                                if verbose:
                                    print("Open Drone ID BT4/BT5\n-------------------------\n")
                                try:
                                    json_data = decode_ble(advdata)
                                except Exception as e:
                                    if verbose:
                                        log("decode_ble Error:", e)
                                    continue

                                if pub:
                                    pub.send_string(json_data)
                                if verbose:
                                    print(json_data)
                                    print()
                                sys.stdout.flush()
                    elif "DroneID" in dc:
                        for mac, field in dc["DroneID"].items():
                            # Open Drone ID
                            if verbose:
                                print("Open Drone ID WIFI\n-------------------------\n")
                            if "AdvData" in field:
                                try:
                                    fields = decode(structhelper_io(bytes.fromhex(field["AdvData"])))
                                    for field_decoded in fields:
                                        field_decoded["MAC"] = mac
                                        json_data = json.dumps(field_decoded).decode('utf-8')
                                        if pub:
                                            pub.send_string(json_data)
                                        if verbose:
                                            print(json_data)
                                except Exception as e:
                                    if verbose:
                                        log("Decoding Error:", e)
                                    pass
                            else:
                                try:
                                    field["MAC"] = mac
                                    json_data = json.dumps(field).decode('utf-8')
                                    if pub:
                                        pub.send_string(json_data)
                                    if verbose:
                                        print(json_data)
                                except Exception as e:
                                    if verbose:
                                        log("JSON Dump Error:", e)
                                    pass
                            if verbose:
                                print()
                            sys.stdout.flush()
    except zmq.error.ContextTerminated:
        pass
    except Exception as e:
        if verbose:
            log("Decoder Thread Error:", e)


def main():
    global stop
    verbose = False
    info = "ZMQ decoder for BLE4/5 + WIFI ZMQ clients (c) B.Kerler 2024"
    aparse = argparse.ArgumentParser(description=info)
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable zmq")
    aparse.add_argument("-v", "--verbose", action="store_true", help="Print decoded messages")
    aparse.add_argument("--zmqsetting", default="127.0.0.1:4224", help="Define zmq server settings")
    aparse.add_argument("--zmqclients", default="127.0.0.1:4222,127.0.0.1:4223", help="Define bluetooth/wifi zmq clients")
    args = aparse.parse_args()

    verbose = args.verbose

    # Initialize a single ZMQ context
    sctx = zmq.Context()

    if args.zmq:
        pub = sctx.socket(zmq.XPUB)
        sctx.setsockopt(zmq.XPUB_VERBOSE, True)
        purl = f"tcp://{args.zmqsetting}"
        pub.bind(purl)

        zthread = Thread(target=zmq_thread, args=(pub,), daemon=True, name='zmq')
        zthread.start()
    else:
        pub = None
        zthread = None

    clients = args.zmqclients.split(",")
    subs = []
    for client in clients:
        url = f"tcp://{client}"
        sub = sctx.socket(zmq.SUB)
        # Subscribe to both topics
        sub.setsockopt(zmq.SUBSCRIBE, b'{"AUX_ADV_IND"')
        sub.setsockopt(zmq.SUBSCRIBE, b'{"DroneID"')
        try:
            sub.connect(url)
        except zmq.error.ZMQError as e:
            log(f"Failed to connect to {url}: {e}")
            continue

        dthread = Thread(target=decoder_thread, args=(sub, pub, verbose), daemon=True, name=f'decoder-{client}')
        dthread.start()
        subs.append(dthread)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Interrupt received, shutting down...")
    finally:
        stop = True
        # Close all sockets
        for client in clients:
            try:
                sub.close()
            except:
                pass
        if pub:
            pub.close()
        # Terminate context
        sctx.term()
        # Wait for threads to finish
        for thread in subs:
            thread.join()
        if zthread:
            zthread.join()
        log("Shutdown complete.")


if __name__ == "__main__":
    main()
