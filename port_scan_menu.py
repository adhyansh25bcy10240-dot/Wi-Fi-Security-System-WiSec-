import sys
import socket
import ssl
import subprocess
import concurrent.futures

def get_active_network_info():
    """Dynamically detects active default network interface and C++ subnet prefix."""
    interface = "eth0"
    subnet_prefix = "192.168.1"
    try:
        route_out = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], text=True)
        parts = route_out.split()
        if "dev" in parts:
            interface = parts[parts.index("dev") + 1]
        if "src" in parts:
            local_ip = parts[parts.index("src") + 1]
            subnet_prefix = ".".join(local_ip.split(".")[:3])
    except Exception as e:
        print(f"[!] Auto-detection warning: {e}. Using fallbacks.")
    return interface, subnet_prefix

def run_cpp_scanner(interface: str, subnet_base: str) -> list[dict]:
    """Executes the C++ ARP binary with sanitized arguments."""
    # Sanitize subnet input (e.g., converts '192.168.1.0/24' -> '192.168.1')
    subnet_clean = subnet_base.split('/')[0]
    if subnet_clean.endswith('.0'):
        subnet_clean = subnet_clean[:-2]

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

class FullPortScanner:
    def __init__(self, ports=None, timeout=1.0, max_threads=50):
        self.ports = ports or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 8080, 8443]
        self.timeout = timeout
        self.max_threads = max_threads

    def _get_service_name(self, port: int) -> str:
        """Looks up service name and strips line-break/whitespace corruption."""
        try:
            raw_service = socket.getservbyport(port, "tcp")
            return raw_service.split()[0] if raw_service else "unknown"
        except OSError:
            return "unknown"

    def _grab_banner(self, ip: str, port: int) -> str:
        """Attempts TCP and SSL banner grabbing."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Send HTTP probe for Web ports
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

if __name__ == "__main__":
    # 1. Auto-detect active network interface and subnet
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

    # 2. Run ARP discovery to find live hosts
    discovered_hosts = run_cpp_scanner(interface, subnet_base)

    if not discovered_hosts:
        print("[!] No active hosts discovered on the network.")
        sys.exit(0)

    # 3. Present target selection menu
    print(f"[+] Discovered {len(discovered_hosts)} live host(s):\n")
    for idx, host in enumerate(discovered_hosts, 1):
        print(f"  [{idx}] IP: {host['ip']:<15} | MAC: {host['mac']}")
    print("  [A] Scan ALL discovered devices\n")

    user_choice = input("Select a target number to scan (e.g. 1, 2) or 'A' for all: ").strip().lower()

    # 4. Filter hosts based on user choice
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

    # 5. Run port scanner on selected host(s)
    scanner = FullPortScanner(timeout=1.0, max_threads=50)
    results = scanner.scan_network_hosts(target_hosts)

    # 6. Display results
    print("\n" + "=" * 60)
    print("PORT SCAN & BANNER GRABBING RESULTS")
    print("=" * 60)
    for host in results:
        print(f"\nHost: {host['ip']} | MAC: {host['mac']}")
        if host.get("open_ports"):
            for p in host["open_ports"]:
                print(f"  [+] Port {p['port']}/tcp OPEN | Service: {p['service']}")
                print(f"      Banner: {p['banner']}")
        else:
            print("  [-] No open ports found.")