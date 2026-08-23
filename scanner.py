#!/usr/bin/env python3
"""
scanner.py
==========
One-off scan: runs the C++ ARP scanner, enriches results, prints a table.
Shared enrichment logic now lives in enrichment.py.

Usage:
  sudo python3 scanner.py <interface> <subnet_base>
  Example: sudo python3 scanner.py eth1 192.168.1
"""

import sys
from enrichment import run_cpp_scanner, load_vendor_db, enrich_device


def main():
    if len(sys.argv) < 3:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface> <subnet_base>")
        print(f"Example: sudo python3 {sys.argv[0]} eth1 192.168.1")
        sys.exit(1)

    interface = sys.argv[1]
    subnet_base = sys.argv[2]

    print("Loading vendor database (first run may download it)...")
    mac_lookup = load_vendor_db()

    print(f"\nScanning {subnet_base}.0/24 on interface {interface}...\n")
    raw_devices = run_cpp_scanner(interface, subnet_base)

    if not raw_devices:
        print("No devices found.")
        return

    enriched = [enrich_device(ip, mac, mac_lookup) for ip, mac in raw_devices]

    print(f"{'IP Address':<16} {'MAC Address':<19} {'Vendor':<22} {'Hostname':<25} {'Type'}")
    print("-" * 100)
    for d in enriched:
        print(f"{d['ip']:<16} {d['mac']:<19} {d['vendor'][:20]:<22} {d['hostname'][:23]:<25} {d['type']}")

    print(f"\nTotal devices found: {len(enriched)}")


if __name__ == "__main__":
    main()
