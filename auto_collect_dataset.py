"""
auto_collect_dataset.py

ONE-COMMAND version of collect_dataset.py. Instead of manually running the
collector + each attack separately per label, this script launches your
combined attack simulator (attacks/simultaneous_attack_test.py, or whatever
you pass) as a subprocess, captures continuously while it runs, and
auto-labels each captured window based on a known timeline of phases -
matching the exact sequence that script prints:

    Normal (6s) -> PortScan (8s) -> DoS_SYN (8s) -> ARP_Spoofing (8s) -> Normal (5s)

If your attack script's phase durations differ, edit DEFAULT_PHASES below
to match (label, seconds) in the same order it actually runs them.

USAGE (run with sudo - same raw-socket requirement as live_ai_sniffer.py;
the attack subprocess inherits root from this process, no extra sudo needed
for it):

    sudo python auto_collect_dataset.py <interface> <path_to_attack_script> [-- <extra args for attack script>]

Example, matching your project layout:

    sudo python auto_collect_dataset.py lo attacks/simultaneous_attack_test.py

Run this from the wifi-scanner/ project root so the models/ relative path
resolves the same way train_cil.py expects.

Run it multiple times (it always APPENDS) to collect more samples - the
more real traffic you capture per class, the better.
"""

import argparse
import csv
import os
import socket
import struct
import subprocess
import sys
import time

# Must match train_cil.py's CLASS_NAMES exactly.
LABEL_TO_INFO = {
    "normal":       {"class_id": 0, "csv": "dataset1.csv"},
    "portscan":     {"class_id": 1, "csv": "dataset1.csv"},
    "dos_syn":      {"class_id": 2, "csv": "dataset2.csv"},
    "arp_spoofing": {"class_id": 3, "csv": "dataset2.csv"},
}

FEATURE_HEADER = ["pps", "syn_ratio", "unique_ports", "avg_len", "arp_rate", "uncommon_ratio", "label"]

# EDIT THIS if your attack script's phase durations are different. Order and
# seconds must match the actual sequence the attack script runs, in order.
DEFAULT_PHASES = [
    ("normal", 6),
    ("portscan", 8),
    ("dos_syn", 8),
    ("arp_spoofing", 8),
    ("normal", 5),
]


def compute_features(stats, duration):
    """Same 6-feature computation as CILFeatureExtractor in live_ai_sniffer.py."""
    total_packets = stats["total_packets"]
    duration = max(duration, 0.001)

    pps = total_packets / duration
    syn_ratio = (stats["syn_count"] / total_packets) if total_packets > 0 else 0.0
    unique_ports = float(len(stats["dst_ports"]))
    avg_len = (stats["total_bytes"] / total_packets) if total_packets > 0 else 0.0
    arp_rate = (stats["arp_count"] / total_packets) if total_packets > 0 else 0.0
    uncommon_ratio = (
        (stats["uncommon_proto_count"] / total_packets) if total_packets > 0 else 0.0
    )

    return [pps, syn_ratio, unique_ports, avg_len, arp_rate, uncommon_ratio]


def capture_one_window(raw_socket, window_size):
    """Captures raw packets for window_size seconds, same parsing logic as
    live_ai_sniffer.py's start_sniffer()."""
    stats = {
        "total_packets": 0,
        "total_bytes": 0,
        "syn_count": 0,
        "arp_count": 0,
        "uncommon_proto_count": 0,
        "dst_ports": set(),
    }

    start_time = time.time()
    raw_socket.settimeout(0.5)

    while time.time() - start_time < window_size:
        try:
            packet_data, _ = raw_socket.recvfrom(65535)
        except socket.timeout:
            continue

        stats["total_packets"] += 1
        stats["total_bytes"] += len(packet_data)

        if len(packet_data) < 14:
            continue

        eth_protocol = socket.ntohs(struct.unpack("!H", packet_data[12:14])[0])

        if eth_protocol == 0x0806:  # ARP
            stats["arp_count"] += 1
            continue

        if eth_protocol == 0x0800:  # IPv4
            if len(packet_data) < 34:
                continue

            ip_header = packet_data[14:34]
            ip_proto = ip_header[9]

            if ip_proto not in [1, 6, 17]:
                stats["uncommon_proto_count"] += 1

            if ip_proto == 6:  # TCP
                ip_header_len = (ip_header[0] & 0x0F) * 4
                tcp_start = 14 + ip_header_len
                tcp_header = packet_data[tcp_start:tcp_start + 20]

                if len(tcp_header) >= 20:
                    src_port, dst_port = struct.unpack("!HH", tcp_header[0:4])
                    tcp_flags = tcp_header[13]

                    stats["dst_ports"].add(dst_port)
                    if tcp_flags & 0x02:
                        stats["syn_count"] += 1

    elapsed = time.time() - start_time
    return stats, elapsed


def append_row(csv_path, feature_row, class_id):
    file_exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(FEATURE_HEADER)
        writer.writerow([*[round(v, 6) for v in feature_row], class_id])


def main():
    parser = argparse.ArgumentParser(
        description="Run the attack simulation and auto-label captured windows by phase, in one command."
    )
    parser.add_argument("interface", help="Network interface to sniff on (e.g. lo, eth0, wlan0)")
    parser.add_argument("attack_script", help="Path to the combined attack simulator script")
    parser.add_argument("--window", type=float, default=1.5, help="Seconds per capture sub-window within each phase (default: 1.5)")
    parser.add_argument("--outdir", default="models", help="Directory containing dataset1.csv/dataset2.csv (default: models)")
    parser.add_argument("attack_args", nargs=argparse.REMAINDER, help="Any extra args to forward to the attack script")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # Open the capture socket BEFORE starting the attack subprocess, so we
    # don't miss early packets while the subprocess is still starting up.
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((args.interface, 0))
    except PermissionError:
        print("[-] Error: Root privileges required for Raw Sockets (run with sudo).")
        sys.exit(1)

    cmd = [sys.executable, args.attack_script] + args.attack_args
    print(f"[+] Launching attack script: {' '.join(cmd)}")
    # Inherits this process's (root) privileges - no separate sudo needed here.
    attack_proc = subprocess.Popen(cmd)

    total_duration = sum(d for _, d in DEFAULT_PHASES)
    print(f"[+] Capturing on '{args.interface}' across {len(DEFAULT_PHASES)} phases "
          f"(~{total_duration}s total, {args.window}s sub-windows)\n")

    saved_counts = {label: 0 for label in LABEL_TO_INFO}

    try:
        for phase_label, phase_duration in DEFAULT_PHASES:
            info = LABEL_TO_INFO[phase_label]
            csv_path = os.path.join(args.outdir, info["csv"])
            class_id = info["class_id"]

            print(f"--- Phase: {phase_label} ({phase_duration}s) ---")
            phase_start = time.time()

            while time.time() - phase_start < phase_duration:
                remaining = phase_duration - (time.time() - phase_start)
                this_window = min(args.window, remaining) if remaining > 0 else 0
                if this_window <= 0:
                    break

                stats, elapsed = capture_one_window(raw_socket, this_window)
                features = compute_features(stats, elapsed)
                append_row(csv_path, features, class_id)
                saved_counts[phase_label] += 1

                rounded = [round(v, 2) for v in features]
                print(f"  pkts={stats['total_packets']:4d} | features={rounded} -> {info['csv']} (class {class_id})")

    except KeyboardInterrupt:
        print("\n[*] Stopped early - samples captured so far are already saved.")

    # Make sure the attack subprocess has finished; don't leave it dangling.
    attack_proc.wait(timeout=10) if attack_proc.poll() is None else None

    print("\n[+] Done. Rows added this run:")
    for label, count in saved_counts.items():
        if count > 0:
            print(f"    {label}: {count} window(s) -> {LABEL_TO_INFO[label]['csv']}")

    print("\n[*] Run again to add more samples, or train now with:")
    print("    python models/train_cil.py")


if __name__ == "__main__":
    main()