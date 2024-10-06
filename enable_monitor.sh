sudo ip link set $1 down
sudo iwconfig $1 mode monitor
sudo ip link set $1 up
