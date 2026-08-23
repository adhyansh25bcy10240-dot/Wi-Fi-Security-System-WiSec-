#!/usr/bin/env python3
"""
Phase 1: Data Processing & Enrichment Layer
===========================================
Subprocess wrapper for the C++ ARP scanner binary. Captures raw (IP, MAC) 
tuples and enriches them with vendor OUI lookups, reverse DNS hostnames, 
and basic device type classification.

Requirements:
    pip install mac-vendor-lookup

Usage:
    sudo python3 scanner.py <interface> <subnet_base>
    Example: sudo python3 scanner.py eth0 192.168.1
"""

import sys
from mac_vendor_lookup import MacLookup


def run_cpp_scanner(interface: str, subnet_base: str) -> list[tuple[str, str]]:
    """Executes the C++ scanner binary and parses CSV output from stdout."""
    binary_path = "./arp_scanner"

    try:
        result = subprocess.run(
            [binary_path, interface, subnet_base],
            capture_output=True,
            text=True,
            timeout=15
        )
    except FileNotFoundError:
        print(f"ERROR: Binary '{binary_path}' not found. Ensure it is compiled in the working directory.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: Scanner execution timed out.")
        sys.exit(1)

    # Output scanner diagnostic messages sent to stderr
    if result.stderr:
        print(result.stderr.strip())

    devices = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        parts = line.split(",")
        if len(parts) == 2:
            ip, mac = parts
            devices.append((ip.strip(), mac.strip()))

    return devices


def get_vendor(mac: str, mac_lookup: MacLookup) -> str:
    """Performs IEEE OUI vendor lookup using the MAC address prefix."""
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown"


def get_hostname(ip: str) -> str:
    """Performs a reverse DNS lookup for a given IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"


def guess_device_type(hostname: str, vendor: str) -> str:
    """Basic string-matching heuristic to classify device types."""
    text = (hostname + " " + vendor).lower()

    if "iphone" in text or "ipad" in text:
        return "Mobile - iOS"
    if "android" in text:
        return "Mobile - Android"
    if "apple" in text or "macbook" in text:
        return "Computer - Apple"
    if "samsung" in text:
        return "Mobile/TV - Samsung"
    if "raspberry" in text:
        return "IoT - Raspberry Pi"
    if "espressif" in text or "esp32" in text or "esp8266" in text:
        return "IoT Device"
    if "desktop" in text or "laptop" in text or "pc" in text:
        return "Computer"
    if "router" in text or "gateway" in text:
        return "Network - Router"
    if "amazon" in text or "echo" in text or "alexa" in text:
        return "Smart Speaker - Amazon"
    if "xiaomi" in text:
        return "Mobile - Xiaomi"

    return "Unknown"


def main():
    if len(sys.argv) < 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface> <subnet_base>")
        print(f"Example: sudo python3 {sys.argv[0]} eth0 192.168.1")
        sys.exit(1)

    interface = sys.argv[1]
    subnet_base = sys.argv[2]

    print("Initializing OUI vendor database...")
    mac_lookup = MacLookup()
    try:
        mac_lookup.update_vendors()
    except Exception:
        print("Failed to fetch online OUI updates; using local cache.")

    print(f"\nScanning {subnet_base}.0/24 on {interface}...\n")
    raw_devices = run_cpp_scanner(interface, subnet_base)

    if not raw_devices:
        print("No active hosts discovered.")
        return

    enriched = []
    for ip, mac in raw_devices:
        vendor = get_vendor(mac, mac_lookup)
        hostname = get_hostname(ip)
        device_type = guess_device_type(hostname, vendor)
        enriched.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "type": device_type
        })

    # Print formatted summary table
    print(f"{'IP Address':<16} {'MAC Address':<19} {'Vendor':<22} {'Hostname':<25} {'Type'}")
    print("-" * 100)
    for d in enriched:
        print(f"{d['ip']:<16} {d['mac']:<19} {d['vendor'][:20]:<22} {d['hostname'][:23]:<25} {d['type']}")

    print(f"\nTotal devices found: {len(enriched)}")


if __name__ == "__main__":
    main()
