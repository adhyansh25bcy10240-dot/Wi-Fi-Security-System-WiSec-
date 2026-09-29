import sys
import socket
import ssl
import subprocess
import concurrent.futures
import os
import json
from datetime import datetime

# ============================================================
# 1. AI Threat Predictor Module Import
# ============================================================
try:
    from ai.predict import ThreatPredictor
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("[!] Warning: AI Predictor module not found. Running in basic mode.")


# ============================================================
# 2. Network & Subnet Auto-Detection Helpers
# ============================================================
def sanitize_to_3_octets(ip_or_subnet: str) -> str:
    """
    Subnet ko strictly 3 octets mein clean karta hai (e.g. '192.168.1.100/24' -> '192.168.1').
    """
    clean = ip_or_subnet.split('/')[0].strip()
    parts = clean.split('.')
    if len(parts) >= 3:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return clean


def get_active_network_info():
    """
    Linux routing table se dynamic check karta hai ki konsa network interface 
    (wlan0, eth0) active hai aur uska IP sub-range kya hai.
    """
    interface = "eth0"
    subnet_prefix = "192.168.1"
    try:
        route_out = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], text=True)
        parts = route_out.split()
        if "dev" in parts:
            interface = parts[parts.index("dev") + 1]
        if "src" in parts:
            local_ip = parts[parts.index("src") + 1]
            subnet_prefix = sanitize_to_3_octets(local_ip)
    except Exception as e:
        print(f"[!] Auto-detection warning: {e}. Using fallback defaults.")
    return interface, subnet_prefix


def deduplicate_hosts(hosts: list[dict]) -> list[dict]:
    """
    C++ ARP scanner se milne wale duplicate IP entries ko remove karta hai.
    """
    seen = set()
    unique = []
    for h in hosts:
        ip = h.get("ip")
        if ip and ip not in seen:
            seen.add(ip)
            unique.append(h)
    return unique


# ============================================================
# 3. C++ ARP Discovery Binary Wrapper
# ============================================================
def run_cpp_scanner(interface: str, subnet_base: str) -> list[dict]:
    """
    Phase 2 C++ compiled binary ('./arp_scanner') ko subprocess se call karta hai.
    """
    subnet_clean = sanitize_to_3_octets(subnet_base)
    binary_path = "./arp_scanner"

    try:
        result = subprocess.run(
            ["sudo", binary_path, interface, subnet_clean],
            capture_output=True,
            text=True,
            check=True
        )
        devices = []
        for line in result.stdout.strip().split("\n"):
            if line and "," in line:
                parts = line.split(",")
                if len(parts) >= 2:
                    devices.append({"ip": parts[0].strip(), "mac": parts[1].strip()})
        return devices
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] Error executing C++ ARP scanner: {e}")
        return []


# ============================================================
# 4. Multithreaded Port Scanner & Banner Grabber
# ============================================================
class FullPortScanner:
    def __init__(self, ports=None, timeout=1.0, max_threads=50):
        # Scan hone wale target common ports
        self.ports = ports or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 8080, 8443]
        self.timeout = timeout
        self.max_threads = max_threads

    def _get_service_name(self, port: int) -> str:
        """Port number se standard service name resolve karta hai (e.g. 80 -> http)."""
        try:
            raw_service = socket.getservbyport(port, "tcp")
            return raw_service.split()[0] if raw_service else "unknown"
        except OSError:
            return "unknown"

    def _grab_banner(self, ip: str, port: int) -> str:
        """Open port par connection banakar service banner identify karta hai."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Web ports ke liye HTTP probe send karna
            if port in [80, 8080]:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port in [443, 8443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname=ip)
                ssl_sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = ssl_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                ssl_sock.close()
                return banner.split('\r\n')[0] if banner else "No banner returned"

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner.split('\r\n')[0] if banner else "No banner returned"
        except Exception:
            return "No banner returned"

    def _scan_single_port(self, ip: str, port: int):
        """Single port ke TCP connect check ke liye low-level socket function."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            res = sock.connect_ex((ip, port))
            sock.close()
            if res == 0:
                service = self._get_service_name(port)
                banner = self._grab_banner(ip, port)
                return {"port": port, "service": service, "banner": banner}
        except Exception:
            pass
        return None

    def scan_host(self, host_info: dict) -> dict:
        """ThreadPoolExecutor se ek single host ke saare ports multithreading se scan karta hai."""
        ip = host_info["ip"]
        mac = host_info.get("mac", "00:00:00:00:00:00")
        print(f"[*] Scanning ports and grabbing banners for: {ip}...")
        
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._scan_single_port, ip, port) for port in self.ports]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        return {"ip": ip, "mac": mac, "open_ports": open_ports}

    def scan_network_hosts(self, hosts: list[dict]) -> list[dict]:
        return [self.scan_host(h) for h in hosts]


# ============================================================
# 5. Logging Utilities
# ============================================================
def save_scan_logs(results: list[dict], log_dir: str = "logs"):
    """
    Results ko Text Log (cumulative append) aur JSON format (structured snapshot) mein save karta hai.
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    now_readable = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    txt_log_path = os.path.join(log_dir, "port_scan.log")
    json_log_path = os.path.join(log_dir, f"scan_{timestamp_str}.json")

    # 1. Human-readable text log append
    with open(txt_log_path, "a") as txt_file:
        txt_file.write(f"\n=== SCAN RUN AT {now_readable} ===\n")
        for host in results:
            ip = host["ip"]
            mac = host.get("mac", "UNKNOWN")
            ai_info = host.get("ai_security", {})
            ai_str = f" | AI Threat: {ai_info.get('status', 'N/A')} (Score: {ai_info.get('threat_score', 0.0)})"
            
            if host.get("open_ports"):
                for p in host["open_ports"]:
                    log_entry = (
                        f"[{now_readable}] [OPEN] Host: {ip:<15} | MAC: {mac} | "
                        f"Port: {p['port']}/tcp | Service: {p['service']} | Banner: {p['banner']}{ai_str}\n"
                    )
                    txt_file.write(log_entry)
            else:
                txt_file.write(f"[{now_readable}] [CLEAN] Host: {ip:<15} | MAC: {mac} | No open ports{ai_str}\n")

    # 2. JSON Snapshot for AI pipeline & Dashboards
    log_data = {
        "timestamp": now_readable,
        "scanned_hosts": len(results),
        "results": results
    }
    with open(json_log_path, "w") as json_file:
        json.dump(log_data, json_file, indent=2)

    print("\n" + "=" * 60)
    print(f"[+] Scan logs generated successfully:")
    print(f"    - Append Log : {txt_log_path}")
    print(f"    - JSON Record: {json_log_path}")
    print("=" * 60)


# ============================================================
# 6. Main Orchestration & Pipeline Execution
# ============================================================
if __name__ == "__main__":
    # A. Active network info auto-detect or command-line arguments parse
    if len(sys.argv) >= 3:
        arg1, arg2 = sys.argv[1], sys.argv[2]
        if "." in arg1 or "/" in arg1:
            subnet_base, interface = arg1, arg2
        else:
            interface, subnet_base = arg1, arg2
    else:
        interface, subnet_base = get_active_network_info()

    print(f"[*] Active Interface: {interface}")
    print(f"[*] Target Subnet Base: {subnet_base}.1-254")
    print("=" * 60)

    # B. Live active hosts scan with Phase 2 C++ ARP Scanner
    raw_discovered = run_cpp_scanner(interface, subnet_base)

    # Clean duplicates in IP list
    discovered_hosts = deduplicate_hosts(raw_discovered)

    if not discovered_hosts:
        print("[!] No active hosts discovered on the network.")
        sys.exit(0)

    # C. Target selection menu for user
    print(f"[+] Discovered {len(discovered_hosts)} unique live host(s):\n")
    for idx, host in enumerate(discovered_hosts, 1):
        print(f"  [{idx}] IP: {host['ip']:<15} | MAC: {host['mac']}")
    print("  [A] Scan ALL discovered devices\n")

    user_choice = input("Select a target number to scan (e.g. 1, 2) or 'A' for all: ").strip().lower()

    if user_choice.isdigit() and 1 <= int(user_choice) <= len(discovered_hosts):
        selected_index = int(user_choice) - 1
        target_hosts = [discovered_hosts[selected_index]]
        print(f"\n[*] Target selected: {target_hosts[0]['ip']}")
    elif user_choice in ['a', 'all', '']:
        target_hosts = discovered_hosts
        print(f"\n[*] Target selected: ALL ({len(target_hosts)} devices)")
    else:
        print("\n[!] Invalid option entered. Defaulting to scanning ALL devices.")
        target_hosts = discovered_hosts

    # D. Execute Port Scan
    scanner = FullPortScanner(timeout=1.0, max_threads=50)
    results = scanner.scan_network_hosts(target_hosts)

    # E. Initialize AI Threat Predictor
    predictor = ThreatPredictor() if AI_AVAILABLE else None

    # F. Display Results + AI Threat Score
    print("\n" + "=" * 60)
    print("PORT SCAN & AI THREAT DETECTION RESULTS")
    print("=" * 60)

    for host in results:
        ip = host["ip"]
        mac = host["mac"]
        open_ports = host.get("open_ports", [])

        print(f"\nHost: {ip} | MAC: {mac}")
        if open_ports:
            for p in open_ports:
                print(f"  [+] Port {p['port']}/tcp OPEN | Service: {p['service']}")
                print(f"      Banner: {p['banner']}")
        else:
            print("  [-] No open ports found.")

        # --- AI Threat Prediction Engine Integration ---
        ai_verdict = {"status": "Normal", "threat_score": 0.05}
        if predictor:
            try:
                # 6D Feature Vector: [total_ports, syn_ratio, open_ports_count, avg_pkt_size, rst_ratio, duration]
                total_probes = float(len(scanner.ports))
                open_count = float(len(open_ports))
                syn_ratio = 0.85 if open_count >= 3 else 0.15

                feature_vector = [
                    total_probes,  # Total ports tested
                    syn_ratio,     # SYN flag ratio
                    open_count,    # Total open ports found
                    64.0,          # Packet size (standard TCP SYN)
                    0.0,           # RST ratio
                    1.0            # Scan duration window (seconds)
                ]

                # Run prediction and update database/history
                status, score = predictor.analyze_and_update(ip, feature_vector)
                ai_verdict = {"status": status, "threat_score": score}

                # Print visual badge indicator
                badge = "🔴" if score > 0.7 else ("🟡" if score > 0.3 else "🟢")
                print(f"  [{badge} AI Threat Verdict] Status: {status} | Score: {score:.2f}")

            except Exception as e:
                print(f"  [!] AI Prediction error for {ip}: {e}")

        # Store AI Verdict inside the host dict so log files save it
        host["ai_security"] = ai_verdict

    # G. Save logs (Includes AI scores)
    save_scan_logs(results)