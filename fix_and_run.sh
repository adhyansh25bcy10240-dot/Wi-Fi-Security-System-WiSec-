#!/bin/bash
echo "[1/4] Cleaning old containers & interfaces..."
sudo docker rm -f target_node 2>/dev/null
sudo ip link delete demo0 2>/dev/null

echo "[2/4] Setting up persistent virtual interface (demo0)..."
sudo ip link add demo0 type dummy
sudo ip addr add 10.5.0.1/24 dev demo0
sudo ip link set demo0 up

echo "[3/4] Enabling IP Forwarding..."
sudo sysctl -w net.ipv4.conf.demo0.forwarding=1 >/dev/null

echo "[+] Done! Interface 'demo0' is fresh, UP and persistent."
