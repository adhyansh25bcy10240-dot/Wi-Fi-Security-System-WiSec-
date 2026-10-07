import os
import random
import socket
import struct
import sys
import time

TARGET_IP = "127.0.0.1"
INTERFACE = "lo"


def send_raw_packet(packet_bytes, interface=INTERFACE):
    """Sends raw ethernet frame on specified interface."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
        s.send(packet_bytes)
        s.close()
    except Exception:
        pass


def build_ip_tcp_syn(src_ip, dst_ip, dst_port):
    """Builds IPv4 + TCP SYN packet."""
    eth_header = struct.pack("!6s6sH", b"\x00\x00\x00\x00\x00\x00", b"\x00\x00\x00\x00\x00\x00", 0x0800)

    ip_ihl_ver = (4 << 4) + 5
    ip_tos = 0
    ip_tot_len = 40
    ip_id = random.randint(1000, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    src_port = random.randint(1024, 65535)
    seq = random.randint(0, 4294967295)
    ack_seq = 0
    doff_reserved = (5 << 4) + 0
    flags = 0x02  # SYN Flag
    window = socket.htons(5840)
    check = 0
    urg_ptr = 0

    tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack_seq, doff_reserved, flags, window, check, urg_ptr)

    return eth_header + ip_header + tcp_header


def build_arp_reply(src_ip, src_mac_bytes):
    """Builds raw ARP Packet (0x0806 protocol)."""
    # Ethernet Header (Type 0x0806)
    eth_header = struct.pack("!6s6sH", b"\xff\xff\xff\xff\xff\xff", src_mac_bytes, 0x0806)

    # ARP Reply Payload
    htype = 1  # Ethernet
    ptype = 0x0800  # IPv4
    hlen = 6
    plen = 4
    opcode = 2  # ARP Reply
    sender_ip = socket.inet_aton(src_ip)
    target_mac = b"\x00\x00\x00\x00\x00\x00"
    target_ip = socket.inet_aton("127.0.0.1")

    arp_payload = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, opcode, src_mac_bytes, sender_ip, target_mac, target_ip)

    return eth_header + arp_payload


# ============================================================
# Attack Routines
# ============================================================
def simulate_normal_traffic(duration=8):
    print(f"[+] Generating Normal Traffic for {duration}s...")
    end_time = time.time() + duration
    while time.time() < end_time:
        port = random.choice([80, 443, 53])
        packet = build_ip_tcp_syn("127.0.0.1", TARGET_IP, port)
        send_raw_packet(packet)
        time.sleep(random.uniform(0.1, 0.4))


def simulate_portscan_attack(duration=10):
    print(f"[!] Triggering PortScan Attack for {duration}s...")
    end_time = time.time() + duration
    scanned_ports = list(range(20, 1024))
    random.shuffle(scanned_ports)

    for port in scanned_ports:
        if time.time() >= end_time:
            break
        packet = build_ip_tcp_syn("127.0.0.1", TARGET_IP, port)
        send_raw_packet(packet)
        time.sleep(random.uniform(0.005, 0.02))


def simulate_dos_syn_flood(duration=10):
    print(f"[!] Triggering DoS SYN Flood Attack for {duration}s...")
    end_time = time.time() + duration
    target_port = 80

    while time.time() < end_time:
        burst_size = random.randint(80, 200)
        for _ in range(burst_size):
            packet = build_ip_tcp_syn("127.0.0.1", TARGET_IP, target_port)
            send_raw_packet(packet)
        time.sleep(random.uniform(0.01, 0.05))


def simulate_arp_spoofing(duration=10):
    print(f"[!] Triggering ARP Spoofing Attack for {duration}s...")
    end_time = time.time() + duration
    fake_mac = b"\x00\x11\x22\x33\x44\x55"

    while time.time() < end_time:
        burst_size = random.randint(30, 80)
        for _ in range(burst_size):
            arp_pkt = build_arp_reply("192.168.1.1", fake_mac)
            send_raw_packet(arp_pkt)
        time.sleep(random.uniform(0.05, 0.1))


# ============================================================
# Main Orchestrator
# ============================================================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Error: Root privileges required. Run with sudo.")
        sys.exit(1)

    print("==================================================")
    print("      WiSec Real-time Attack Simulator           ")
    print("==================================================")

    simulate_normal_traffic(duration=6)
    time.sleep(1)

    simulate_portscan_attack(duration=8)
    time.sleep(1)

    simulate_dos_syn_flood(duration=8)
    time.sleep(1)

    simulate_arp_spoofing(duration=8)
    time.sleep(1)

    simulate_normal_traffic(duration=5)
    print("\n[+] Attack Simulation Finished.")