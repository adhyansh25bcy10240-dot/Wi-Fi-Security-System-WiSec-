import time
import socket
import struct
import collections
import sys
import os
import ipaddress
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ai.predict import ThreatPredictor

THREAT_DETAILS = {
    "PortScan": {
        "description": "Rapid probing of multiple open ports detected.",
        "risk_level": "MEDIUM",
        "action": "Block source IP using iptables: 'sudo iptables -A INPUT -s {ip} -j DROP'"
    },
    "DoS_SYN": {
        "description": "High volume SYN packet flood detected!",
        "risk_level": "HIGH / CRITICAL",
        "action": "Enable SYN cookies: 'sudo sysctl -w net.ipv4.tcp_syncookies=1'"
    },
    "Normal": {
        "description": "Standard network traffic.",
        "risk_level": "LOW",
        "action": "None"
    }
}

def is_relevant_ip(ip_str):
    """Checks if IP is private or active local subnet."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not ip.is_loopback
    except ValueError:
        return False

def print_ai_alert(ip, status, score, pps=0, syn_ratio=0, unique_ports=0):
    info = THREAT_DETAILS.get(status, THREAT_DETAILS["Normal"])
    
    if status != "Normal":
        print(f"\n{'='*60}")
        print(f"🚨 [ALERT DETECTED] Target IP: {ip}")
        print(f"📌 Attack Type : {status} (Risk Score: {score:.2f})")
        print(f"⚠️  Risk Level  : {info['risk_level']}")
        print(f"🔍 Description : {info['description']}")
        print(f"📊 Features    : PPS={pps:.1f}, SYN Ratio={syn_ratio:.2f}, Ports={unique_ports}")
        print(f"🛡️  Action      : {info['action'].format(ip=ip)}")
        print(f"{'='*60}\n")
    else:
        # Ab Normal traffic par bhi reason dikhayega
        reason = f"Low SYN ratio ({syn_ratio:.2f}), Single/Few ports probed ({int(unique_ports)})"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [AI Verdict] IP: {ip:<15} | Status: {status:<10} | Score: {score:.2f} | Reason: {reason}")

window_seconds = 5
traffic_stats = collections.defaultdict(lambda: {
    'pkts': 0, 'syn_count': 0, 'rst_count': 0,
    'ports': set(), 'bytes': 0, 'start_time': time.time()
})

predictor = ThreatPredictor()

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    return socket.inet_ntoa(ip_header[8]), socket.inet_ntoa(ip_header[9]), ip_header[6]

def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    flags = tcp_header[5]
    return tcp_header[0], tcp_header[1], (flags & 0x02) != 0, (flags & 0x04) != 0

def start_live_monitoring(interface="eth2"):
    print(f"[*] AI Real-Time Traffic Sniffer Started on [{interface}]...")
    
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_sock.bind((interface, 0))
        raw_sock.settimeout(1.0)
    except Exception as e:
        print(f"[!] Socket creation failed: {e}")
        return

    last_analysis_time = time.time()
    total_raw_packets = 0

    try:
        while True:
            try:
                raw_data, _ = raw_sock.recvfrom(65535)
                total_raw_packets += 1
                
                eth_protocol = struct.unpack('!H', raw_data[12:14])[0]
                if eth_protocol == 0x0800:  # IPv4
                    ip_payload = raw_data[14:]
                    src_ip, dst_ip, proto = parse_ip_header(ip_payload)
                    
                    if proto == 6 and (is_relevant_ip(src_ip) or is_relevant_ip(dst_ip)):
                        tcp_payload = ip_payload[20:]
                        if len(tcp_payload) >= 20:
                            src_port, dst_port, is_syn, is_rst = parse_tcp_header(tcp_payload)
                            
                            # Track per source IP
                            stats = traffic_stats[src_ip]
                            stats['pkts'] += 1
                            stats['bytes'] += len(raw_data)
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
                # HEARTBEAT LOG: Yeh batayega ki socket kitne packets receive kar raha hai
                timestamp = datetime.now().strftime('%H:%M:%S')
                
                if not traffic_stats:
                    print(f"[{timestamp}] 📡 Sniffing on [{interface}]... (Captured {total_raw_packets} raw packets, 0 TCP matches)")
                else:
                    for ip, stats in list(traffic_stats.items()):
                        if stats['pkts'] < 1:
                            continue
                        
                        duration = max(now - stats['start_time'], 1.0)
                        total_pkts = float(stats['pkts'])
                        syn_ratio = float(stats['syn_count']) / total_pkts
                        rst_ratio = float(stats['rst_count']) / total_pkts
                        avg_pkt_size = float(stats['bytes']) / total_pkts
                        unique_ports = float(len(stats['ports']))

                        feature_vector = [
                            total_pkts, syn_ratio, unique_ports,
                            avg_pkt_size, rst_ratio, duration
                        ]

                        status, score = predictor.predict_vector(feature_vector)
                        predictor.update_database(ip, status, score)
                        
                        pps = total_pkts / duration
                        print_ai_alert(ip, status, score, pps=pps, syn_ratio=syn_ratio)

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