import time
import socket
import struct
import collections
import sys
import os
import ipaddress
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ai.predict import ThreatPredictor

THREAT_DETAILS = {
    "PortScan": {
        "description": "An attacker is rapidly probing open ports to find vulnerable services.",
        "risk_level": "MEDIUM",
        "action": "Block source IP: 'sudo iptables -A INPUT -s {ip} -j DROP'"
    },
    "DoS_SYN": {
        "description": "High volume TCP SYN flood detected! System resources exhaustion attempt.",
        "risk_level": "HIGH / CRITICAL",
        "action": "Enable SYN cookies: 'sudo sysctl -w net.ipv4.tcp_syncookies=1'"
    },
    "ARP_Spoofing": {
        "description": "Unsolicited ARP responses detected. Potential Man-in-the-Middle attack.",
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
    
    print(f"\n{'='*65}")
    print(f"🚨 [ALERT DETECTED] Target IP: {ip} | MAC: {mac}")
    print(f"📌 Attack Type  : {status} (AI Confidence: {score*100:.1f}%)")
    print(f"⚠️  Risk Level   : {info['risk_level']}")
    print(f"🔍 Description  : {info['description']}")
    print(f"🎯 Ports Hit    : [{ports_str}]")
    print(f"📊 Traffic Stats: PPS={pps:.1f}, SYN Ratio={syn_ratio:.2f}")
    print(f"🛡️  Action       : {info['action'].format(ip=ip)}")
    print(f"{'='*65}\n")

# Tracking stats per IP (5-second window)
window_seconds = 5
traffic_stats = collections.defaultdict(lambda: {
    'mac': 'Unknown',
    'pkts': 0,
    'syn_count': 0,
    'rst_count': 0,
    'arp_count': 0,
    'ports': set(),
    'bytes': 0,
    'start_time': time.time()
})

predictor = ThreatPredictor()

def parse_ip_header(data):
    # Extract version and Internet Header Length (IHL)
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4  # Dynamic IP Header Size
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    return socket.inet_ntoa(ip_header[8]), socket.inet_ntoa(ip_header[9]), ip_header[6], ihl

def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    flags = tcp_header[5]
    return tcp_header[0], tcp_header[1], (flags & 0x02) != 0, (flags & 0x04) != 0

def start_live_monitoring(interface="eth1", verbose_mode=False):
    mode_title = "VERBOSE MODE (Detailed)" if verbose_mode else "SUMMARY MODE (Compact)"
    print(f"[*] AI Real-Time Traffic Sniffer Active on [{interface}] | Mode: {mode_title}")
    print("[*] Press Ctrl+C to stop.\n")
    
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_sock.bind((interface, 0))
        raw_sock.settimeout(1.0)
    except Exception as e:
        print(f"[!] Socket error (Run with sudo): {e}")
        return

    last_analysis_time = time.time()

    try:
        while True:
            try:
                raw_data, _ = raw_sock.recvfrom(65535)
                dst_mac_bytes, src_mac_bytes, eth_protocol = struct.unpack('!6s6sH', raw_data[:14])
                src_mac = format_mac(src_mac_bytes)
                
                # ARP (0x0806)
                if eth_protocol == 0x0806:
                    arp_header = raw_data[14:42]
                    if len(arp_header) >= 28:
                        sender_ip = socket.inet_ntoa(arp_header[14:18])
                        if is_local_ip(sender_ip):
                            stats = traffic_stats[sender_ip]
                            stats['mac'] = src_mac
                            stats['pkts'] += 1
                            stats['arp_count'] += 1

                # IPv4 (0x0800)
                elif eth_protocol == 0x0800:
                    ip_payload = raw_data[14:]
                    src_ip, dst_ip, proto, ip_hdr_len = parse_ip_header(ip_payload)
                    
                    if is_local_ip(src_ip):
                        stats = traffic_stats[src_ip]
                        stats['mac'] = src_mac
                        stats['pkts'] += 1
                        stats['bytes'] += len(raw_data)
                        
                        if proto == 6: # TCP
                            # Dynamic IP header offset parsing
                            tcp_payload = ip_payload[ip_hdr_len:]
                            if len(tcp_payload) >= 20:
                                src_port, dst_port, is_syn, is_rst = parse_tcp_header(tcp_payload)
                                stats['ports'].add(dst_port)
                                if is_syn: 
                                    stats['syn_count'] += 1
                                if is_rst: 
                                    stats['rst_count'] += 1

            except socket.timeout:
                pass
            except Exception:
                pass

            # 5-second Evaluation Cycle
            now = time.time()
            if now - last_analysis_time >= window_seconds:
                ts = datetime.now().strftime('%H:%M:%S')
                threats_found = 0
                normal_count = 0

                if traffic_stats:
                    if verbose_mode:
                        print(f"\n--- [{ts}] Detailed Traffic Report ---")

                    for ip, stats in list(traffic_stats.items()):
                        if stats['pkts'] < 1:
                            continue
                        
                        duration = max(now - stats['start_time'], 1.0)
                        total_pkts = float(stats['pkts'])
                        syn_ratio = float(stats['syn_count']) / total_pkts if total_pkts > 0 else 0.0
                        rst_ratio = float(stats['rst_count']) / total_pkts if total_pkts > 0 else 0.0
                        avg_pkt_size = float(stats['bytes']) / total_pkts if total_pkts > 0 else 0.0
                        unique_ports = float(len(stats['ports']))

                        # Guardrail: 0 ports hit, 0 SYN & 0 ARP = Normal
                        if unique_ports == 0 and stats['syn_count'] == 0 and stats['arp_count'] == 0:
                            status, score = "Normal", 0.99
                        else:
                            feature_vector = [
                                total_pkts, syn_ratio, unique_ports,
                                avg_pkt_size, rst_ratio, duration
                            ]
                            status, score = predictor.predict_vector(feature_vector)

                            # -------------------------------------------------------------
                            # CALIBRATED HEURISTIC OVERRIDES: Priority Detection
                            # -------------------------------------------------------------
                            # -------------------------------------------------------------
                            # CALIBRATED HEURISTIC OVERRIDES: Distinct Multi-Vector Logic
                            # -------------------------------------------------------------
                            pps = total_pkts / duration
                            arp_pkts = stats['arp_count']

                            # Order 1: ARP Spoofing (Only if ARP traffic exists)
                            if arp_pkts >= 10:
                                status = "ARP_Spoofing"
                                score = 0.99
                            # Order 2: DoS SYN Flood (High PPS / High SYN count on few ports)
                            elif (pps >= 80 or stats['syn_count'] >= 100) and unique_ports <= 3:
                                status = "DoS_SYN"
                                score = 0.99
                            # Order 3: PortScan (Probing multiple unique ports)
                            elif unique_ports >= 10:
                                status = "PortScan"
                                score = 0.99
                                
                        predictor.update_database(ip, status, score)
                        
                        if status != "Normal":
                            threats_found += 1
                            pps = total_pkts / duration
                            print_ai_alert(ip, stats['mac'], status, score, pps=pps, syn_ratio=syn_ratio, ports=stats['ports'])
                        else:
                            normal_count += 1
                            if verbose_mode:
                                print(f"  🟢 IP: {ip:<15} | MAC: {stats['mac']} | Packets: {int(total_pkts):<4} | Status: Normal (99%)")

                # Summary Line for Normal traffic in Summary mode
                if not verbose_mode and threats_found == 0:
                    print(f"[{ts}] 🛡️  Sniffing active... Monitored {normal_count} LAN devices | All Status: SAFE (Normal)")

                # Reset window
                traffic_stats.clear()
                last_analysis_time = time.time()

    except KeyboardInterrupt:
        print("\n[*] Live Sniffer Stopped.")
        sys.exit(0)

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth1"
    
    print("\nSelect Monitoring Display Mode:")
    print("1) Summary Mode  (Default: 1-line status when clear, alerts on threat)")
    print("2) Full Details  (Verbose: Lists every active IP with stats)")
    
    choice = input("\nEnter Choice [1/2] (Default 1): ").strip()
    is_verbose = True if choice == "2" else False

    start_live_monitoring(iface, verbose_mode=is_verbose)