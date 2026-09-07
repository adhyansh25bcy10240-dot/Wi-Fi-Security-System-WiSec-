#!/usr/bin/env python3

import os
import glob
import json
import sqlite3
from datetime import datetime

import numpy as np
import matplotlib.pyplot as plt


# ===================== PATHS =====================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "devices.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")


# ===================== LOAD DEVICES =====================

def load_devices():

    if not os.path.exists(DB_PATH):
        print("[!] devices.db not found.")
        print("[!] Run history_tracker.py first.")
        return []

    try:
        conn = sqlite3.connect(DB_PATH)

        rows = conn.execute("""
            SELECT mac, ip, vendor, hostname,
                   device_type, is_online,
                   first_seen, last_seen
            FROM devices
        """).fetchall()

        conn.close()

    except sqlite3.Error as e:
        print("[!] Database error:", e)
        return []

    return [{
        "mac": r[0],
        "ip": r[1],
        "vendor": r[2] or "Unknown",
        "hostname": r[3] or "Unknown",
        "type": r[4] or "Unknown",
        "online": r[5] or 0,
        "first": r[6],
        "last": r[7]
    } for r in rows]


# ===================== DEVICE ANALYSIS =====================

def count_values(devices, key):

    values = np.array([
        d[key] for d in devices
    ])

    names, counts = np.unique(
        values,
        return_counts=True
    )

    return dict(
        zip(names, counts)
    )


def online_status(devices):

    status = np.array([
        d["online"] for d in devices
    ])

    online = np.sum(status == 1)
    offline = np.sum(status == 0)

    return int(online), int(offline)


# ===================== PORT SCAN =====================

def load_latest_scan():

    files = sorted(
        glob.glob(
            os.path.join(
                LOG_DIR,
                "scan_*.json"
            )
        )
    )

    if not files:
        print("[!] No port scan JSON found.")
        return None

    try:

        with open(
            files[-1],
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except (
        OSError,
        json.JSONDecodeError
    ) as e:

        print("[!] Error reading scan:", e)
        return None


def get_ports(scan):

    ports = {}

    if not scan:
        return ports

    for host in scan.get(
        "results",
        []
    ):

        for item in host.get(
            "open_ports",
            []
        ):

            port = str(
                item.get(
                    "port",
                    "Unknown"
                )
            )

            ports[port] = (
                ports.get(port, 0) + 1
            )

    return ports


# ===================== NETWORK ACTIVITY =====================

def get_activity():

    if not os.path.exists(DB_PATH):
        return np.array([]), np.array([])

    try:

        conn = sqlite3.connect(DB_PATH)

        rows = conn.execute("""
            SELECT connected_at,
                   disconnected_at
            FROM connection_history
            ORDER BY connected_at
        """).fetchall()

        conn.close()

    except sqlite3.Error:
        return np.array([]), np.array([])

    events = []

    for connected, disconnected in rows:

        if connected:

            try:
                events.append(
                    (
                        datetime.fromisoformat(
                            connected
                        ),
                        1
                    )
                )
            except ValueError:
                pass

        if disconnected:

            try:
                events.append(
                    (
                        datetime.fromisoformat(
                            disconnected
                        ),
                        -1
                    )
                )
            except ValueError:
                pass

    events.sort()

    if not events:
        return np.array([]), np.array([])

    times = []
    counts = []
    online = 0

    for time, change in events:

        online = max(
            0,
            online + change
        )

        times.append(time)
        counts.append(online)

    return (
        np.array(times),
        np.array(counts)
    )


# ===================== CHARTS =====================

def device_chart(ax, data):

    if not data:
        ax.text(
            .5,
            .5,
            "No data",
            ha="center"
        )
        ax.set_title(
            "Device Type Distribution"
        )
        return

    names = np.array(
        list(data.keys())
    )

    values = np.array(
        list(data.values())
    )

    bars = ax.bar(
        names,
        values
    )

    ax.set_title(
        "Device Type Distribution"
    )

    ax.set_ylabel(
        "Devices"
    )

    ax.tick_params(
        axis="x",
        rotation=30
    )

    for bar, value in zip(
        bars,
        values
    ):

        ax.text(
            bar.get_x()
            + bar.get_width() / 2,
            value,
            str(value),
            ha="center",
            va="bottom"
        )


def vendor_chart(ax, data):

    if not data:
        ax.text(
            .5,
            .5,
            "No data",
            ha="center"
        )
        ax.set_title(
            "Vendor Distribution"
        )
        return

    names = np.array(
        list(data.keys())
    )

    values = np.array(
        list(data.values())
    )

    if len(values) > 8:

        order = np.argsort(values)
        keep = order[-7:]

        other = np.sum(
            values[order[:-7]]
        )

        names = np.append(
            names[keep],
            "Others"
        )

        values = np.append(
            values[keep],
            other
        )

    ax.pie(
        values,
        labels=names,
        autopct="%1.1f%%",
        startangle=90
    )

    ax.set_title(
        "Vendor Distribution"
    )


def port_chart(ax, data):

    if not data:
        ax.text(
            .5,
            .5,
            "No open ports",
            ha="center"
        )
        ax.set_title(
            "Open Ports"
        )
        return

    names = np.array(
        list(data.keys())
    )

    values = np.array(
        list(data.values())
    )

    try:

        order = np.argsort(
            names.astype(int)
        )

        names = names[order]
        values = values[order]

    except ValueError:
        pass

    bars = ax.bar(
        names,
        values
    )

    ax.set_title(
        "Open Ports"
    )

    ax.set_xlabel(
        "Port"
    )

    ax.set_ylabel(
        "Hosts"
    )

    for bar, value in zip(
        bars,
        values
    ):

        ax.text(
            bar.get_x()
            + bar.get_width() / 2,
            value,
            str(value),
            ha="center",
            va="bottom"
        )


def activity_chart(ax):

    times, counts = get_activity()

    if len(times) == 0:

        ax.text(
            .5,
            .5,
            "No connection history",
            ha="center"
        )

        ax.set_title(
            "Network Activity"
        )

        return

    if len(times) > 50:

        times = times[-50:]
        counts = counts[-50:]

    x = np.arange(
        len(times)
    )

    ax.plot(
        x,
        counts,
        marker="o"
    )

    ax.set_title(
        "Network Activity"
    )

    ax.set_xlabel(
        "Connection Events"
    )

    ax.set_ylabel(
        "Online Devices"
    )

    if len(times) <= 12:

        ax.set_xticks(x)

        ax.set_xticklabels(
            [
                t.strftime("%H:%M:%S")
                for t in times
            ],
            rotation=30
        )


# ===================== MAIN =====================

def main():

    print(
        "\n" + "=" * 55
    )

    print(
        "          WiSec - Network Visualization"
    )

    print(
        "=" * 55
    )

    devices = load_devices()

    if not devices:

        print(
            "[!] No devices available."
        )

        return

    # -------- Data --------

    device_types = count_values(
        devices,
        "type"
    )

    vendors = count_values(
        devices,
        "vendor"
    )

    online, offline = online_status(
        devices
    )

    scan = load_latest_scan()

    ports = get_ports(
        scan
    )

    total = len(devices)

    open_ports = sum(
        ports.values()
    )

    # -------- Terminal summary --------

    print(
        f"\n[+] Devices    : {total}"
    )

    print(
        f"[+] Online     : {online}"
    )

    print(
        f"[+] Offline    : {offline}"
    )

    print(
        f"[+] Open ports : {open_ports}"
    )

    # ================= DASHBOARD =================

    fig = plt.figure(
        figsize=(15, 10)
    )

    fig.suptitle(
        "WiSec - Network Security Monitor",
        fontsize=21,
        fontweight="bold"
    )

    # -------- Top summary cards --------

    summary = [
        ("DEVICES", total),
        ("ONLINE", online),
        ("OFFLINE", offline),
        ("OPEN PORTS", open_ports)
    ]

    positions = [
        (0.08, 0.86),
        (0.31, 0.86),
        (0.54, 0.86),
        (0.77, 0.86)
    ]

    for (label, value), (x, y) in zip(
        summary,
        positions
    ):

        fig.text(
            x,
            y,
            str(value),
            ha="center",
            va="center",
            fontsize=22,
            fontweight="bold"
        )

        fig.text(
            x,
            y - 0.035,
            label,
            ha="center",
            va="center",
            fontsize=11
        )

    # -------- Four charts --------

    ax1 = fig.add_axes(
        [0.06, 0.48, 0.40, 0.30]
    )

    ax2 = fig.add_axes(
        [0.54, 0.48, 0.40, 0.30]
    )

    ax3 = fig.add_axes(
        [0.06, 0.08, 0.40, 0.30]
    )

    ax4 = fig.add_axes(
        [0.54, 0.08, 0.40, 0.30]
    )

    device_chart(
        ax1,
        device_types
    )

    vendor_chart(
        ax2,
        vendors
    )

    port_chart(
        ax3,
        ports
    )

    activity_chart(
        ax4
    )

    plt.show()


if __name__ == "__main__":
    main()