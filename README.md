# OpenDroneID receiver and spoofer

## Installation
```bash
git clone https://github.com/alphafox02/DroneID.git
cd DroneID
git submodule init
git submodule update
./setup.sh
```

## Run

### 1. Bluetooth receiver (using Sonoff Dongle)
1. Run 
```bash
./bluetooth_receiver.sh -b 2000000 -s /dev/ttyUSB0 --zmqsetting 127.0.0.1:4222 -v
```
```
Argument description:
---------------------
-b is Baudrate (only use 2000000 for newer Sonoff devices, otherwise leave away)
-s is the serial port of the bluetooth dongle
--zmqsetting zmq server addr is 127.0.0.1 with Port 4222
-v Print received messages
```

#### For spoofing messages
```bash
./bluetooth_spoof.py -s /dev/ttyUSB0 -b 2000000
```
Edit drone.json for data to spoof

### 2. Wifi receiver (using Wifi card in monitoring mode)
#### For pcap replay
```
./wifi_receiver.py --pcap examples/odid_wifi_sample.pcap -z --zmqsetting 127.0.0.1:4223
```

#### Using a wifi interface
```
./wifi_receiver.py --interface wlan0 -z --zmqsetting 127.0.0.1:4223
```

### 3. Decode and spawn zmq server
```bash
./zmq_decoder.py -z --zmqsetting 127.0.0.1:4224 --zmqclients 127.0.0.1:4222,127.0.0.1:4223 -v
```
```
Argument description:
---------------------
-z spawn a zmq server (optional)
--zmqsetting zmq server addr is 127.0.0.1 with Port 4224 (optional)
--zmqclients listen to bluetooth receiver at 127.0.0.1:4222 and wifi receiver at 127.0.0.1:4223  (optional)
-v print decoded messages (optional)
```
