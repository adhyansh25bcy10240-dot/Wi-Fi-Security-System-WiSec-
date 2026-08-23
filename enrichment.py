#enrichment.py
#!/usr/bin/env python3
"""
enrichment.py
=============
Shared logic used by both scanner.py (one-off scan + print) and
history_tracker.py (SQLite-backed continuous monitoring).

Keeping this in one place means vendor lookup, hostname resolution,
and device-type guessing only need to be improved in ONE file.
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
              f"Make sure you're in the project folder and it's compiled.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: Scanner took too long and timed out.")
        return []

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


def load_vendor_db() -> MacLookup:
    """Loads (and tries to refresh) the offline MAC vendor database."""
    mac_lookup = MacLookup()
    try:
        mac_lookup.update_vendors()
    except Exception:
        print("Could not refresh vendor DB (no internet?) - using cached copy if available.")
    return mac_lookup


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
    """Basic heuristic to guess device type from hostname/vendor patterns.
    This will improve in Phase 3 once port scanning is added."""
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


def enrich_device(ip: str, mac: str, mac_lookup: MacLookup) -> dict:
    """Convenience wrapper: takes a raw (ip, mac) pair and returns the full enriched record."""
    vendor = get_vendor(mac, mac_lookup)
    hostname = get_hostname(ip)
    device_type = guess_device_type(hostname, vendor)
    return {
        "ip": ip,
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "type": device_type
    }
