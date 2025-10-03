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
    """Handles ZMQ subscriber notifications."""
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
    """Handles Bluetooth/Wi-Fi OpenDroneID messages."""
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
                    
                    # Process Bluetooth/Wi-Fi data
                    process_decoded_data(dc, pub)
    except zmq.error.ContextTerminated:
        pass
    except Exception as e:
        if verbose:
            log("Decoder Thread Error:", e)

def uart_listener(uart_device, pub):
    """Reads ESP32 UART data and forwards it via ZMQ."""
    global stop
    buffer = ""
    with serial.Serial(uart_device, baudrate=115200, timeout=1) as ser:
        while not stop:
            if ser.in_waiting > 0:
                try:
                    data = ser.read(ser.in_waiting).decode('utf-8')
                    buffer += data
                    if buffer.count("{") == buffer.count("}"):  # Complete JSON
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
                            log("UART JSON Decode Error:", e)
                            buffer = ""
                except Exception as e:
                    log("UART Read Error:", e)
            else:
                time.sleep(0.1)

def dji_listener(dji_url, pub):
    """Subscribes to DJI Receiver and forwards data as-is."""
    global stop
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.setsockopt(zmq.SUBSCRIBE, b'')  # Subscribe to all messages
    try:
        socket.connect(f"tcp://{dji_url}")
        log(f"Connected to DJI Receiver at {dji_url}")
        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)
        while not stop:
            socks = dict(poller.poll(3000))  # Poll every 3 seconds
            if socket in socks and socks[socket] == zmq.POLLIN:
                try:
                    data = socket.recv_string()
                    if pub:
                        pub.send_string(data)  # Forward raw DJI data
                    if verbose:
                        log(f"DJI Data Forwarded: {data}")
                except zmq.ZMQError as e:
                    log("DJI ZMQ Error:", e)
                    continue
    except zmq.error.ZMQError as e:
        log(f"Error connecting to DJI Receiver at {dji_url}: {e}")
    finally:
        socket.close()
        context.term()

def process_decoded_data(dc, pub):
    """Processes and forwards the decoded Bluetooth/Wi-Fi data."""
    # --- BLE path (unchanged behavior) ---
    if "AUX_ADV_IND" in dc and "aa" in dc["AUX_ADV_IND"] and dc["AUX_ADV_IND"]["aa"] == 0x8e89bed6:
        if "AdvData" in dc:
            try:
                advdata = bytearray(bytes.fromhex(dc["AdvData"]))
                if advdata[1] == 0x16 and int.from_bytes(advdata[2:4], 'little') == 0xFFFA and advdata[4] == 0x0D:
                    if verbose:
                        print("Open Drone ID BT4/BT5\n-------------------------\n")
                    json_data = decode_ble(advdata)

                    # Add AdvA address to JSON if available
                    if "aext" in dc and "AdvA" in dc["aext"]:
                        try:
                            json_obj = json.loads(json_data)
                            if isinstance(json_obj, list) and len(json_obj) > 0:
                                for msg in json_obj:
                                    if "Basic ID" in msg:
                                        adv_a = dc["aext"]["AdvA"].split()[0]
                                        msg["Basic ID"]["MAC"] = adv_a
                                        # Add RSSI from AUX_ADV_IND
                                        msg["Basic ID"]["RSSI"] = dc["AUX_ADV_IND"]["rssi"]
                            json_data = json.dumps(json_obj)
                        except json.JSONDecodeError:
                            pass

                    if pub:
                        pub.send_string(json_data)
                    if verbose:
                        print(json_data)
                        print()
                    sys.stdout.flush()
            except ValueError as e:
                log("AdvData Decode Error:", e)

    # --- Wi-Fi path (CHANGED: always publish a list like BLE) ---
    elif "DroneID" in dc:
        for mac, field in dc["DroneID"].items():
            if verbose:
                print("Open Drone ID WIFI\n-------------------------\n")

            merged = []  # CHANGED: accumulate decoded messages to publish as a list

            # If we have raw AdvData, decode into multiple messages
            if "AdvData" in field:
                try:
                    fields = decode(structhelper_io(bytes.fromhex(field["AdvData"])))
                    for field_decoded in fields:
                        field_decoded["MAC"] = mac
                        # Add RSSI to decoded fields if available
                        if "AUX_ADV_IND" in dc:
                            field_decoded["RSSI"] = dc["AUX_ADV_IND"]["rssi"]
                        merged.append(field_decoded)  # CHANGED
                except Exception as e:
                    log("Decoding Error:", e)
            else:
                # CHANGED: No AdvData present — still emit a list with a minimal entry
                entry = {"MAC": mac}
                if "AUX_ADV_IND" in dc:
                    entry["RSSI"] = dc["AUX_ADV_IND"]["rssi"]
                # If a pre-parsed structure is already in 'field', keep it alongside MAC/RSSI
                # but ensure we output a list for consistency with BLE
                if field:
                    try:
                        # shallow copy to avoid mutating original
                        base = dict(field)
                        base["MAC"] = entry["MAC"]
                        if "RSSI" in entry:
                            base["RSSI"] = entry["RSSI"]
                        merged.append(base)
                    except Exception:
                        merged.append(entry)
                else:
                    merged.append(entry)

            # CHANGED: Publish once as a JSON array (BLE-style)
            if merged:
                json_data = json.dumps(merged)
                if pub:
                    pub.send_string(json_data)
                if verbose:
                    print(json_data)
                print() if verbose else None
            sys.stdout.flush()

def main():
    global stop, verbose
    info = "ZMQ decoder for BLE4/5 + WIFI + DJI ZMQ clients (c) B.Kerler 2024"
    aparse = argparse.ArgumentParser(description=info)
    aparse.add_argument("-z", "--zmq", action="store_true", help="Enable ZMQ")
    aparse.add_argument("-v", "--verbose", action="store_true", help="Print decoded messages")
    aparse.add_argument("--zmqsetting", default="127.0.0.1:4224", help="Define ZMQ server settings")
    aparse.add_argument("--zmqclients", default="127.0.0.1:4222,127.0.0.1:4223", help="Define Bluetooth/Wi-Fi ZMQ clients")
    aparse.add_argument("--uart", help="UART device for pre-decoded ESP32 data (e.g., /dev/ttyACM0)")
    aparse.add_argument("--dji", help="DJI receiver ZMQ endpoint (e.g., 127.0.0.1:4221)")
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

    # Set up UART listener
    if args.uart:
        uart_thread = Thread(target=uart_listener, args=(args.uart, pub), daemon=True)
        uart_thread.start()

    # Set up DJI listener
    if args.dji:
        dji_thread = Thread(target=dji_listener, args=(args.dji, pub), daemon=True, name='dji')
        dji_thread.start()

    # Set up ZMQ client listeners
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
            log(f"Failed to connect to {url}: {e}")
            continue

        dthread = Thread(target=decoder_thread, args=(sub, pub), daemon=True, name=f'decoder-{client}')
        dthread.start()
        subs.append(dthread)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
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
        if args.dji:
            dji_thread.join()
        if zthread:
            zthread.join()
        log("Shutdown complete.")

if __name__ == "__main__":
    main()

