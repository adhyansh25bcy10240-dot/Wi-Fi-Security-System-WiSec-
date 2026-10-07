import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, ARP, Raw

class NetworkFeatureExtractor:
    def __init__(self, interface: str = None):
        self.interface = interface

    def capture_window_features(self, duration: int = 5) -> dict:
        """
        Sniffs packets for 'duration' seconds and extracts per-IP feature vectors.
        """
        packets = sniff(timeout=duration, iface=self.interface)
        
        ip_stats = defaultdict(lambda: {
            "packets": 0,
            "bytes": 0,
            "syn_count": 0,
            "tcp_count": 0,
            "dest_ports": set(),
            "uncommon_ports": 0,
            "arp_replies": 0
        })

        for pkt in packets:
            # Handle IP / TCP Traffic
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                ip_stats[src_ip]["packets"] += 1
                ip_stats[src_ip]["bytes"] += len(pkt)

                if pkt.haslayer(TCP):
                    ip_stats[src_ip]["tcp_count"] += 1
                    dport = pkt[TCP].dport
                    ip_stats[src_ip]["dest_ports"].add(dport)

                    # Check SYN Flag
                    if pkt[TCP].flags == 0x02:  # SYN Flag set
                        ip_stats[src_ip]["syn_count"] += 1

                    if dport > 1024:
                        ip_stats[src_ip]["uncommon_ports"] += 1

            # Handle ARP Traffic
            elif pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                ip_stats[src_ip]["packets"] += 1
                if pkt[ARP].op == 2:  # ARP Reply
                    ip_stats[src_ip]["arp_replies"] += 1

        # Calculate final 6D feature vectors
        features_per_ip = {}
        for ip, stats in ip_stats.items():
            total_pkts = stats["packets"]
            if total_pkts == 0:
                continue

            pps = total_pkts / float(duration)
            syn_ratio = (stats["syn_count"] / float(stats["tcp_count"])) if stats["tcp_count"] > 0 else 0.0
            unique_ports = len(stats["dest_ports"])
            avg_payload_len = stats["bytes"] / float(total_pkts)
            arp_reply_rate = stats["arp_replies"] / float(duration)
            uncommon_ratio = (stats["uncommon_ports"] / float(stats["tcp_count"])) if stats["tcp_count"] > 0 else 0.0

            vector = [pps, syn_ratio, float(unique_ports), avg_payload_len, arp_reply_rate, uncommon_ratio]
            features_per_ip[ip] = vector

        return features_per_ip

if __name__ == "__main__":
    import scapy.all as scapy
    
    # Auto-detect default interface or specify manually e.g., interface="wlan0"
    default_iface = scapy.conf.iface
    print(f"[*] Sniffing on interface: {default_iface}")
    
    extractor = NetworkFeatureExtractor(interface=str(default_iface))
    print("[*] Sniffing traffic for 5 seconds...")
    data = extractor.capture_window_features(5)

    if not data:
        print("[!] No active IP/ARP packets captured in 5 seconds.")
        print("    --> Tip: Open a browser tab or run 'ping 8.8.8.8' in another terminal to generate traffic.")
    else:
        for ip, vec in data.items():
            print(f"IP: {ip} -> Features: {vec}")