import time
import socket
import struct
import collections
import sys
import os
import ipaddress
from datetime import datetime

# Add the parent directory (wifi-scanner) to Python search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ai.predict import ThreatPredictor

THREAT_DETAILS = {
    "PortScan": {
        "description": "An attacker is rapidly probing open ports to find vulnerable services.",
        "risk_level": "MEDIUM",
        "action": "Block source IP using iptables: 'sudo iptables -A INPUT -s {ip} -j DROP'"
    },
    "DoS_SYN": {
        "description": "High volume TCP SYN flood detected! System resources exhaustion attempt.",
        "risk_level": "HIGH / CRITICAL",
        "action": "Enable SYN cookies: 'sudo sysctl -w net.ipv4.tcp_syncookies=1'"
    },
    "ARP_Spoofing": {
        "description": "Unsolicited or spoofed ARP responses detected. Potential Man-in-the-Middle attack.",
        "risk_level": "CRITICAL",
        "action": "Inspect ARP table using 'arp -a' and enable static bindings."
    },
    "Normal": {
        "description": "Standard baseline network traffic.",
        "risk_level": "LOW",
        "action": "None"
    }
}

def format_mac(bytes_addr):
    """Converts raw 6-byte MAC address into human readable string."""
    return ':'.join(f'{b:02x}' for b in bytes_addr)

def is_local_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return not ip.is_loopback
    except ValueError:
        return False

def print_ai_alert(ip, mac, status, score, pps=0, syn_ratio=0, ports=None):
    info = THREAT_DETAILS.get(status, THREAT_DETAILS["Normal"])
    ports_str = ', '.join(map(str, sorted(list(ports))[:10])) if ports else "N/A"
    
    if status != "Normal":
        print(f"\n{'='*65}")
        print(f"🚨 [ALERT DETECTED] Target IP: {ip} | MAC: {mac}")
        print(f"📌 Attack Type  : {status} (Confidence: {score:.2f})")
        print(f"⚠️  Risk Level   : {info['risk_level']}")
        print(f"🔍 Description  : {info['description']}")
        print(f"🎯 Ports Hit    : [{ports_str}]")
        print(f"📊 Traffic Stats: PPS={pps:.1f}, SYN Ratio={syn_ratio:.2f}")
        print(f"🛡️  Action       : {info['action'].format(ip=ip)}")
        print(f"{'='*65}\n")
    else:
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] [AI Verdict] IP: {ip:<15} | MAC: {mac} | Status: {status:<10} | Score: {score:.2f} | Ports Probed: [{ports_str}]")

# Tracking stats per IP (5-second sliding window)
window_seconds = 5
traffic_stats = collections.defaultdict(lambda: {
    'mac': 'Unknown',
    'pkts': 0,
    'syn_count': 0,
    'rst_count': 0,
    'ports': set(),
    'bytes': 0,
    'start_time': time.time()
})

predictor = ThreatPredictor()

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    proto = ip_header[6]
    return src_ip, dst_ip, proto

def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    flags = tcp_header[5]
    is_syn = (flags & 0x02) != 0
    is_rst = (flags & 0x04) != 0
    return src_port, dst_port, is_syn, is_rst

def start_live_monitoring(interface="eth2"):
    print(f"[*] AI Real-Time Traffic Sniffer Started on [{interface}]...")
    
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_sock.bind((interface, 0))
        raw_sock.settimeout(1.0)
    except Exception as e:
        print(f"[!] Socket creation error (Must run as sudo): {e}")
        return

    last_analysis_time = time.time()
    total_raw_packets = 0

    try:
        while True:
            try:
                raw_data, _ = raw_sock.recvfrom(65535)
                total_raw_packets += 1
                
                # Extract Ethernet MAC Addresses & Protocol
                dst_mac_bytes, src_mac_bytes, eth_protocol = struct.unpack('!6s6sH', raw_data[:14])
                src_mac = format_mac(src_mac_bytes)
                
                # 1. ARP Protocol (0x0806) -> Discover all active subnet IPs + MACs
                if eth_protocol == 0x0806:
                    arp_header = raw_data[14:42]
                    if len(arp_header) >= 28:
                        sender_ip = socket.inet_ntoa(arp_header[14:18])
                        if is_local_ip(sender_ip):
                            stats = traffic_stats[sender_ip]
                            stats['mac'] = src_mac
                            stats['pkts'] += 1

                # 2. IPv4 Protocol (0x0800)
                elif eth_protocol == 0x0800:
                    ip_payload = raw_data[14:]
                    src_ip, dst_ip, proto = parse_ip_header(ip_payload)
                    
                    if is_local_ip(src_ip):
                        stats = traffic_stats[src_ip]
                        stats['mac'] = src_mac
                        stats['pkts'] += 1
                        stats['bytes'] += len(raw_data)
                        
                        # Proto 6 = TCP
                        if proto == 6:
                            tcp_payload = ip_payload[20:]
                            if len(tcp_payload) >= 20:
                                src_port, dst_port, is_syn, is_rst = parse_tcp_header(tcp_payload)
                                stats['ports'].add(dst_port)
                                if is_syn: stats['syn_count'] += 1
                                if is_rst: stats['rst_count'] += 1

            except socket.timeout:
                pass
            except Exception:
                pass

            # 5-second Evaluation Cycle
            now = time.time()
            if now - last_analysis_time >= window_seconds:
                if not traffic_stats:
                    ts = datetime.now().strftime('%H:%M:%S')
                    print(f"[{ts}] 📡 Sniffing on [{interface}]... ({total_raw_packets} raw frames processed)")
                else:
                    for ip, stats in list(traffic_stats.items()):
                        if stats['pkts'] < 1:
                            continue
                        
                        duration = max(now - stats['start_time'], 1.0)
                        total_pkts = float(stats['pkts'])
                        syn_ratio = float(stats['syn_count']) / total_pkts if total_pkts > 0 else 0.0
                        rst_ratio = float(stats['rst_count']) / total_pkts if total_pkts > 0 else 0.0
                        avg_pkt_size = float(stats['bytes']) / total_pkts if total_pkts > 0 else 0.0
                        unique_ports = float(len(stats['ports']))

                        feature_vector = [
                            total_pkts, syn_ratio, unique_ports,
                            avg_pkt_size, rst_ratio, duration
                        ]

                        status, score = predictor.predict_vector(feature_vector)
                        predictor.update_database(ip, status, score)
                        
                        pps = total_pkts / duration
                        print_ai_alert(ip, stats['mac'], status, score, pps=pps, syn_ratio=syn_ratio, ports=stats['ports'])

                # Reset window
                traffic_stats.clear()
                total_raw_packets = 0
                last_analysis_time = time.time()

    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth2"
    start_live_monitoring(iface)