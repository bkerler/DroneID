#!/usr/bin/env python3
# (c) 2024 B.Kerler
import json
import sys
import time
import zmq
import argparse
import serial
from threading import Thread
from OpenDroneID.decoder import decode_ble, decode
from OpenDroneID.utils import structhelper_io

verbose = False  # Global variable to control verbosity
stop = False


def log(*msg):
    """Logs messages to stderr if verbose is enabled."""
    global verbose
    if verbose:
        s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"{s}:", *msg, end="\n", file=sys.stderr)


def zmq_thread(pub_socket):
    global stop
    try:
        while not stop:
            try:
                event = pub_socket.recv()
                if verbose:
                    if event[0] == 1:
                        log("New subscriber for", event[1:])
                    elif event[0] == 0:
                        log("Unsubscribed", event[1:])
            except zmq.error.ContextTerminated:
                break
            except Exception as e:
                log("ZMQ Thread Error:", e)
    except zmq.error.ContextTerminated:
        pass


def decoder_thread(socket, pub):
    global stop
    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN)
    try:
        while not stop:
            socks = dict(poller.poll(3000))  # Poll every 3 seconds
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

                    if verbose:
                        print("ZMQ Data Received:", json.dumps(dc, indent=2))
                    process_decoded_data(dc, pub)
    except zmq.error.ContextTerminated:
        pass
    except Exception as e:
        if verbose:
            log("Decoder Thread Error:", e)


def uart_listener(uart_device, pub):
    global stop
    buffer = ""
    with serial.Serial(uart_device, baudrate=115200, timeout=1) as ser:
        while not stop:
            if ser.in_waiting > 0:
                try:
                    data = ser.read(ser.in_waiting).decode('utf-8')
                    buffer += data
                    # Process only when a complete JSON message is detected
                    if buffer.count("{") == buffer.count("}"):
                        if verbose:
                            print("UART received:", buffer)

                        try:
                            dc = json.loads(buffer)
                            json_data = json.dumps(dc)
                            if pub:
                                pub.send_string(json_data)
                            if verbose:
                                print(f"Forwarded via ZMQ: {json_data}")
                            buffer = ""
                        except json.JSONDecodeError as e:
                            if verbose:
                                log("UART JSON Decode Error:", e)
                            buffer = ""
                except Exception as e:
                    if verbose:
                        log("UART Read Error:", e)
            else:
                time.sleep(0.1)


def process_decoded_data(dc, pub):
    """Processes and forwards the decoded data via ZMQ."""
    if "AUX_ADV_IND" in dc and "aa" in dc["AUX_ADV_IND"] and dc["AUX_ADV_IND"]["aa"] == 0x8e89bed6:
        if "AdvData" in dc:
            try:
                advdata = bytearray(bytes.fromhex(dc["AdvData"]))
                if advdata[1] == 0x16 and int.from_bytes(advdata[2:4], 'little') == 0xFFFA and advdata[4] == 0x0D:
                    if verbose:
                        print("Open Drone ID BT4/BT5\n-------------------------\n")
                    json_data = decode_ble(advdata)
                    if pub:
                        pub.send_string(json_data)
                    if verbose:
                        print(json_data)
                        print()
                    sys.stdout.flush()
            except ValueError as e:
                if verbose:
                    log("AdvData Decode Error:", e)

    elif "DroneID" in dc:
        for mac, field in dc["DroneID"].items():
            if verbose:
                print("Open Drone ID WIFI\n-------------------------\n")
            if "AdvData" in field:
                try:
                    fields = decode(structhelper_io(bytes.fromhex(field["AdvData"])))
                    for field_decoded in fields:
                        field_decoded["MAC"] = mac
                        json_data = json.dumps(field_decoded)
                        if pub:
                            pub.send_string(json_data)
                        if verbose:
                            print(json_data)
                except Exception as e:
                    if verbose:
                        log("Decoding Error:", e)
            else:
                try:
                    field["MAC"] = mac
                    json_data = json.dumps(field)
                    if pub:
                        pub.send_string(json_data)
                    if verbose:
                        print(json_data)
                except Exception as e:
                    if verbose:
                        log("JSON Dump Error:", e)
            if verbose:
                print()
            sys.stdout.flush()


def main():
    global stop
    global verbose
    verbose = False
    info = "ZMQ decoder for BLE4/5 + WIFI ZMQ clients (c) B.Kerler 2024"
    aparse = argparse.ArgumentParser(description=info)
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable ZMQ")
    aparse.add_argument("-v", "--verbose", action="store_true", help="Print decoded messages")
    aparse.add_argument("--zmqsetting", default="127.0.0.1:4224", help="Define ZMQ server settings")
    aparse.add_argument("--zmqclients", default="127.0.0.1:4222,127.0.0.1:4223", help="Define Bluetooth/Wi-Fi ZMQ clients")
    aparse.add_argument("--uart", help="UART device for pre-decoded ESP32 data (e.g., /dev/ttyACM0)")
    args = aparse.parse_args()

    verbose = args.verbose

    # Initialize a single ZMQ context
    sctx = zmq.Context()

    if args.zmq:
        pub = sctx.socket(zmq.XPUB)
        pub.setsockopt(zmq.XPUB_VERBOSE, True)
        purl = f"tcp://{args.zmqsetting}"
        pub.bind(purl)

        zthread = Thread(target=zmq_thread, args=(pub,), daemon=True, name='zmq')
        zthread.start()
    else:
        pub = None
        zthread = None

    # Set up UART and ZMQ client listeners concurrently
    if args.uart:
        uart_thread = Thread(target=uart_listener, args=(args.uart, pub), daemon=True)
        uart_thread.start()

    clients = args.zmqclients.split(",")
    subs = []
    for client in clients:
        url = f"tcp://{client}"
        sub = sctx.socket(zmq.SUB)
        sub.setsockopt(zmq.SUBSCRIBE, b'{"AUX_ADV_IND"')
        sub.setsockopt(zmq.SUBSCRIBE, b'{"DroneID"')
        try:
            sub.connect(url)
        except zmq.error.ZMQError as e:
            if verbose:
                log(f"Failed to connect to {url}: {e}")
            continue

        dthread = Thread(target=decoder_thread, args=(sub, pub), daemon=True, name=f'decoder-{client}')
        dthread.start()
        subs.append(dthread)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if verbose:
            log("Interrupt received, shutting down...")
    finally:
        stop = True
        if pub:
            pub.close()
        sctx.term()
        if args.uart:
            uart_thread.join()
        for thread in subs:
            thread.join()
        if zthread:
            zthread.join()
        if verbose:
            log("Shutdown complete.")


if __name__ == "__main__":
    main()
