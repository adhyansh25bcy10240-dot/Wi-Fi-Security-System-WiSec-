#!/usr/bin/env python3
"""
history_tracker.py
===================
Phase 2: SQLite-backed continuous monitoring.
Shared enrichment logic now lives in enrichment.py.

Usage:
  Single scan + save:
    sudo python3 history_tracker.py eth1 192.168.1

  Continuous monitoring (scans every N seconds):
    sudo python3 history_tracker.py eth1 192.168.1 --loop 30

  Export current data to CSV:
    python3 history_tracker.py --export devices_export.csv
"""

import sqlite3
import sys
import time
import csv
from datetime import datetime
from enrichment import run_cpp_scanner, load_vendor_db, enrich_device

DB_PATH = "devices.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            vendor TEXT,
            hostname TEXT,
            device_type TEXT,
            is_online INTEGER DEFAULT 1,
            first_seen TEXT,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            connected_at TEXT,
            disconnected_at TEXT
        )
    """)

    conn.commit()
    return conn


def sync_scan_to_db(conn, interface: str, subnet_base: str, mac_lookup):
    now = datetime.now().isoformat(timespec="seconds")
    raw_devices = run_cpp_scanner(interface, subnet_base)
    seen_macs = set()

    cursor = conn.cursor()

    for ip, mac in raw_devices:
        seen_macs.add(mac)
        record = enrich_device(ip, mac, mac_lookup)
        vendor, hostname, device_type = record["vendor"], record["hostname"], record["type"]

        existing = cursor.execute("SELECT mac, is_online FROM devices WHERE mac = ?", (mac,)).fetchone()

        if existing is None:
            cursor.execute("""
                INSERT INTO devices (mac, ip, vendor, hostname, device_type, is_online, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """, (mac, ip, vendor, hostname, device_type, now, now))

            cursor.execute("""
                INSERT INTO connection_history (mac, connected_at, disconnected_at)
                VALUES (?, ?, NULL)
            """, (mac, now))

            print(f"[NEW]     {ip:<16} {mac}  {vendor}")

        else:
            was_online = existing[1]
            cursor.execute("""
                UPDATE devices SET ip=?, vendor=?, hostname=?, device_type=?, is_online=1, last_seen=?
                WHERE mac=?
            """, (ip, vendor, hostname, device_type, now, mac))

            if not was_online:
                cursor.execute("""
                    INSERT INTO connection_history (mac, connected_at, disconnected_at)
                    VALUES (?, ?, NULL)
                """, (mac, now))
                print(f"[BACK]    {ip:<16} {mac}  {vendor}")
            else:
                print(f"[ONLINE]  {ip:<16} {mac}  {vendor}")

    currently_online = cursor.execute("SELECT mac FROM devices WHERE is_online = 1").fetchall()
    for (mac,) in currently_online:
        if mac not in seen_macs:
            cursor.execute("UPDATE devices SET is_online=0, last_seen=? WHERE mac=?", (now, mac))
            cursor.execute("""
                UPDATE connection_history SET disconnected_at=?
                WHERE mac=? AND disconnected_at IS NULL
            """, (now, mac))
            print(f"[OFFLINE] {mac}")

    conn.commit()


def export_to_csv(output_path: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("SELECT * FROM devices")
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([desc[0] for desc in cursor.description])
        writer.writerows(cursor.fetchall())
    print(f"Exported current device data to {output_path}")
    conn.close()


def main():
    args = sys.argv[1:]

    if "--export" in args:
        idx = args.index("--export")
        output_file = args[idx + 1] if idx + 1 < len(args) else "devices_export.csv"
        export_to_csv(output_file)
        return

    if len(args) < 2:
        print("Usage: sudo python3 history_tracker.py <interface> <subnet_base> [--loop <seconds>]")
        print("       python3 history_tracker.py --export <output.csv>")
        sys.exit(1)

    interface = args[0]
    subnet_base = args[1]

    loop_interval = None
    if "--loop" in args:
        idx = args.index("--loop")
        loop_interval = int(args[idx + 1])

    print("Loading vendor database...")
    mac_lookup = load_vendor_db()

    conn = init_db()

    if loop_interval:
        print(f"Starting continuous monitoring every {loop_interval}s. Press Ctrl+C to stop.\n")
        try:
            while True:
                print(f"--- Scan at {datetime.now().strftime('%H:%M:%S')} ---")
                sync_scan_to_db(conn, interface, subnet_base, mac_lookup)
                print()
                time.sleep(loop_interval)
        except KeyboardInterrupt:
            print("\nStopped monitoring.")
    else:
        sync_scan_to_db(conn, interface, subnet_base, mac_lookup)

    conn.close()


if __name__ == "__main__":
    main()
