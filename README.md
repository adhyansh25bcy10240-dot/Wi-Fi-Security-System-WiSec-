#  WiFi Network Security & Device Monitoring System

A self-contained home network visibility and security tool designed to monitor local network devices. It acts as a friendlier, smarter version of a router's admin page by translating technical network data into a simple, visual dashboard that a non-technical person can understand at a glance.

---

#  Problem Statement

Most home WiFi routers give very limited, technical, and hard-to-read information about who is actually connected to the network.

A regular (non-technical) user has no easy way to know:

- How many devices are connected right now.
- What type of device each one is (e.g., phone, laptop, IoT device).
- When a device joined or left the network and for how long.
- Whether an unknown or suspicious device has connected.

This project aims to build a **simple visual dashboard** that shows all this information in a way a non-technical person can understand at a glance — essentially a friendlier, smarter version of a router's admin page.

---

# Project Goal

To build a **self-contained network monitoring tool** for a home/local WiFi network (`192.168.x.x` range) that:

1. Scans the local network and detects all connected devices.
2. Displays device details in an easy, readable dashboard.
3. Tracks when devices connect/disconnect and for how long.
4. *(Future scope)* Detects suspicious activity and basic intrusion attempts.

> **Important scope note:** This tool is intended to monitor only the user's own home/local network, which they own and administer. No external or third-party networks are involved.

---

#  Why This Project (Learning Value)

This project combines two technical skill areas:

| Skill Area | What I'll Learn |
| :--- | :--- |
| **C++ (Low-level systems)** | Raw socket programming, ARP protocol, network packet handling |
| **Python (Data processing)** | Parsing raw data, building lookups, creating a usable interface |

The idea is that **C++ performs the low-level network work**, while **Python cleans, organizes, stores, and presents that data** in a simple dashboard. This mirrors how many real-world security tools combine a fast low-level core with a flexible scripting/application layer.

---
#  Key Features

- **Local Device Discovery** — Detect devices on the local subnet using ARP.
- **IP & MAC Identification** — Collect network addresses for discovered devices.
- **Vendor Identification** — Identify manufacturers using an offline IEEE OUI database.
- **Hostname Resolution** — Attempt to determine device names.
- **Device Classification** — Estimate whether a device is a phone, laptop, IoT device, or unknown.
- **Connection Tracking** — Record when devices connect and disconnect.
- **Device History** — Store historical device information locally.
- **Visual Dashboard** — Present network information in a format understandable to non-technical users.
- **Future Security Monitoring** — Detect previously unknown devices and other suspicious activity.
The project uses a hybrid architecture combining a low-level C++ network scanner with a Python-based processing and visualization layer.

#  System Architecture

```text
Local WiFi Network
        |
        v
+----------------------+
|   C++ ARP Scanner    |
|  Raw Socket / ARP    |
+----------------------+
        |
        | IP + MAC
        v
+----------------------+
| Python Processing    |
+----------------------+
        |
        +--> Vendor Lookup
        +--> Hostname Resolution
        +--> Device Classification
        |
        v
+----------------------+
|   SQLite Database    |
| Device History       |
+----------------------+
        |
        v
+----------------------+
| Flask Web Dashboard  |
| HTML + JavaScript    |
+----------------------+
        |
        v
      User


#  Expected Outcome

A working local dashboard where a completely non-technical person (for example, a parent checking their home WiFi) can open a webpage and instantly see:

- **"5 devices are connected right now"**
- Simple cards/lists showing each device's name, type, and connection duration.
- A clear log of new devices joining the network.

---

# 🚀 Development Approach & Roadmap

The project will be built incrementally in working milestones so that there is a demonstrable build at every stage.

### Phase 1: Core Device Scanner *(Current Focus)*

- [ ] Scan the local subnet (e.g., `192.168.1.0/24`).
- [ ] List all connected devices with:
  - IP Address
  - MAC Address
  - Vendor (device manufacturer, e.g., Apple, Samsung, Xiaomi)
  - Hostname (device name, if available)
  - Device type guess (phone, laptop, IoT, unknown)

### Phase 2: Live Monitoring Dashboard

- [ ] Build a simple web-based interface using Flask + HTML/JS for non-technical viewing.
- [ ] Track when each device connects and disconnects.
- [ ] Display connection duration and device history.
- [ ] Store device history in SQLite.

### Phase 3: Device Profiling

- [ ] Check common open ports on each device to improve device-type guessing.
- [ ] Example: a device with a camera-streaming port open may be identified as a possible security camera.

### Phase 4: Future Scope / Stretch Goals

> These features will only be attempted after the core system is stable and working.

- [ ] **Intrusion Detection:** Alert when an unrecognized device joins the network.
- [ ] **Traffic Analysis:** Basic bandwidth/usage tracking per device.
- [ ] **Defense Mechanism:** Ability to flag or block a suspicious device directly from the dashboard.

---

#  Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Network Scanning** | C++ (raw sockets / ARP) | Low-level, fast device discovery |
| **Data Processing** | Python | Parse scan data, vendor lookup, hostname resolution |
| **Device Database** | SQLite | Store device history and connect/disconnect times |
| **Dashboard** | Python (Flask) + HTML/JS | Easy-to-read visual interface |
| **Vendor Identification** | Offline IEEE OUI database | Identify device manufacturer from MAC address |

### Design Principles

- No paid tools.
- No external APIs.
- No cloud dependency.
- Everything runs locally on the user's machine and network.

---


##  Protocol Workflow — ARP

Every device connected to a local network can respond to ARP requests.

The scanner sends an ARP request for possible IP addresses and listens for replies. A responding device provides its IP/MAC relationship.

```text
[ C++ Scanner Engine ]
          |
          | Broadcast ARP Request
          | "Who owns IP 192.168.x.N?"
          v
[ All Local Devices (.1 - .254) ]
          |
          | Unicast ARP Reply
          | "I own IP 192.168.x.N"
          | "My MAC is AA:BB:CC:DD:EE:FF"
          v
[ C++ Listening Loop ]
          |
          v
[ Python Data Processing ]
          |
          +--> Vendor Lookup
          +--> Hostname Resolution
          +--> Device-Type Guess
          +--> SQLite Storage
          |
          v
[ Flask Dashboard ]
```


# ⚙️ Dependencies & System Requirements

The Device Discovery module requires a Linux-based environment because the C++ scanner uses raw sockets (`AF_PACKET` / `SOCK_RAW`) for direct access to the network interface.

## System Requirements

| Requirement | Details |
| :--- | :--- |
| **Operating System** | Linux-based environment, such as native Linux or WSL2 with Ubuntu |
| **Windows users** | WSL2 with Ubuntu is required; native Windows is not supported for the raw-socket implementation |
| **Privileges** | Root/sudo privileges are required to create raw sockets and access the NIC directly |
| **Network access** | The scanner must be connected to the local network being monitored |

> **Note:** WSL2 uses a virtualized network adapter by default. For reliable LAN visibility and raw NIC access, WSL2 mirrored networking mode (Windows 11) or native Linux may be required.

## C++ Dependencies

| Dependency | Purpose | Installation |
| :--- | :--- | :--- |
| **g++ (GCC ≥ 9)** | Compile the C++ scanner | `sudo apt install build-essential` |
| **Linux kernel headers** | Required for raw socket / `AF_PACKET` support | Included by default on Ubuntu |
| **`net/if.h`** | Network interface definitions | Included with standard Linux development headers |
| **`netinet/if_ether.h`** | Ethernet/ARP packet structures | Included with standard Linux development headers |
| **`sys/socket.h`** | Socket API and raw socket creation | Included with standard Linux development headers |

The standard Linux networking headers are normally available through `build-essential` / `libc6-dev`.

### Optional: libpcap

If the implementation uses **libpcap** instead of direct `AF_PACKET` raw sockets for packet capture:

```bash
sudo apt install libpcap-dev
```

The C++ program must then be linked with `-lpcap` during compilation.

## Python Dependencies

| Dependency | Purpose | Installation |
| :--- | :--- | :--- |
| **Python ≥ 3.9** | Python runtime | `sudo apt install python3` |
| **pip** | Python package manager | `sudo apt install python3-pip` |
| **pandas** | Structuring and storing discovered IP–MAC data | `pip install pandas` |
| **subprocess** | Communicating with the compiled C++ scanner | Built into Python — no installation required |
| **sqlite3** | Local device-history storage | Built into Python — no installation required |

Additional libraries can be added as the project grows. For example, a MAC/vendor lookup library such as `mac-vendor-lookup` may be used if the implementation requires it.

---

# 🛠️ Installation & Setup

## 1. Install System Dependencies

On Ubuntu or WSL2:

```bash
sudo apt update
sudo apt install build-essential python3 python3-pip
```

Install the Python dependency:

```bash
pip install pandas
```

If using libpcap instead of `AF_PACKET`:

```bash
sudo apt install libpcap-dev
```

## 2. Compile the C++ Scanner

Example:

```bash
g++ -o arp_scanner arp_scanner.cpp -Wall -O2
```

Replace `arp_scanner.cpp` with the actual C++ source filename used by the project.

## 3. Run the C++ Scanner

Raw socket access requires elevated privileges:

```bash
sudo ./arp_scanner
```

## 4. Run the Python Data Management Layer

Example:

```bash
python3 device_manager.py
```

Replace `device_manager.py` with the actual Python script filename.

The Python layer can also launch the C++ scanner automatically using Python's `subprocess` module, allowing the project to have a single entry point.

## 5. Check the Active Network Interface

If the scanner does not detect devices, inspect the available network interfaces:

```bash
ip a
```

Identify the active interface (for example, `eth0`) and make sure the C++ scanner is targeting the correct interface.

---

#  Troubleshooting

### `Permission denied` when creating a raw socket

Run the C++ scanner with `sudo`:

```bash
sudo ./arp_scanner
```

Raw socket creation requires root privileges on Linux.

### No devices are discovered

Check:

1. Your current IP address and subnet:

```bash
ip a
```

2. That the scanner's address range matches the actual local network.
3. That the scanner is using the correct network interface.
4. That you are scanning the network you own or administer.

For example, if the local network is `192.168.1.0/24`, the usable host range is typically:

```text
192.168.1.1 → 192.168.1.254
```

### WSL2 cannot see the physical LAN correctly

WSL2 normally uses a virtualized network adapter. For full LAN visibility, consider:

- WSL2 **mirrored networking mode** on Windows 11.
- Running the scanner from native Linux.
- Using a dual-boot Linux environment when reliable raw NIC access is required.

---

# Scope & Ethics

This project is designed to run **only on a network the user owns or administers**, such as their own home WiFi network.

The project does **not** intend to support:

- Unauthorized scanning of external or third-party networks.
- Monitoring networks without permission.
- Accessing devices or data beyond what is required for local device discovery.

Functionally, the project is similar to information already available through a router's administration page; the main goal is to make that information more accessible, visual, and understandable.
