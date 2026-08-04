#!/usr/bin/env python3
"""
Phase 1 (Python side): Data Filtration Layer
==============================================
What this does:
  1. Calls the C++ arp_scanner binary (subprocess)
  2. Reads its clean CSV output (ip,mac)
  3. Enriches each device with:
       - Vendor (from MAC address, using offline OUI database)
       - Hostname (reverse DNS lookup)
       - Device type (basic guess from hostname + vendor)
  4. Prints a clean, readable table

Requirements:
  pip install mac-vendor-lookup --break-system-packages

Usage:
  sudo python3 scanner.py <interface> <subnet_base>
  Example: sudo python3 scanner.py eth1 192.168.1
"""

import subprocess
import socket
import sys
from mac_vendor_lookup import MacLookup


def run_cpp_scanner(interface: str, subnet_base: str) -> list[tuple[str, str]]:
    """Calls the compiled C++ ARP scanner and parses its CSV stdout output."""
    binary_path = "./arp_scanner"

    try:
        result = subprocess.run(
            [binary_path, interface, subnet_base],
            capture_output=True,
            text=True,
            timeout=15
        )
    except FileNotFoundError:
        print(f"ERROR: Could not find '{binary_path}'. "
              f"Make sure you're in the same folder and it's compiled.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: Scanner took too long and timed out.")
        sys.exit(1)

    # The C++ program prints status messages to stderr - we can show those for visibility
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
    """Looks up the manufacturer name from the MAC address's OUI prefix."""
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown"


def get_hostname(ip: str) -> str:
    """Attempts a reverse DNS lookup to find the device's hostname."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"


def guess_device_type(hostname: str, vendor: str) -> str:
    """Very basic heuristic to guess device type from hostname/vendor patterns.
    This will get much better in Phase 3 once we add port scanning."""
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
        print(f"Example: sudo python3 {sys.argv[0]} eth1 192.168.1")
        sys.exit(1)

    interface = sys.argv[1]
    subnet_base = sys.argv[2]

    print("Loading vendor database (first run may download it)...")
    mac_lookup = MacLookup()
    try:
        mac_lookup.update_vendors()  # downloads/refreshes OUI database
    except Exception:
        print("Could not refresh vendor DB (probably no internet) - using cached copy if available.")

    print(f"\nScanning {subnet_base}.0/24 on interface {interface}...\n")
    raw_devices = run_cpp_scanner(interface, subnet_base)

    if not raw_devices:
        print("No devices found.")
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

    # ---- Print clean table ----
    print(f"{'IP Address':<16} {'MAC Address':<19} {'Vendor':<22} {'Hostname':<25} {'Type'}")
    print("-" * 100)
    for d in enriched:
        print(f"{d['ip']:<16} {d['mac']:<19} {d['vendor'][:20]:<22} {d['hostname'][:23]:<25} {d['type']}")

    print(f"\nTotal devices found: {len(enriched)}")


if __name__ == "__main__":
    main()