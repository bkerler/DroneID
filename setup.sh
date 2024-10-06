#!/bin/sh
python -m venv .venv
source .venv/bin/activate
sudo setcap 'CAP_NET_RAW=eip CAP_NET_ADMIN=eip' $(readlink -f .venv/bin/python3)
.venv/bin/pip3 install -r requirements.txt

