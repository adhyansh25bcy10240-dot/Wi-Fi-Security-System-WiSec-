## 🏗️ System Architecture & Technical Concept

This project utilizes a **hybrid dual-language architecture** that balances high-performance low-level network probing with high-level data management and user visualization[cite: 1].

---

### 1. Language Stack & Core Responsibilities

| Component | Operating Level | Primary Role | Key Features & Libraries |
| :--- | :--- | :--- | :--- |
| **C++ Engine** | Layer 2 (Data Link)[cite: 1] | Low-Level Network Access | Raw sockets (`AF_PACKET`), byte-level frame construction, socket binding, high-speed ARP broadcasting[cite: 1] |
| **Python Engine** | Application Layer | Data Management & Processing | Output stream parsing, IEEE OUI vendor lookup, SQLite database storage, Flask web dashboard integration[cite: 1] |

* **C++ Engine (Low-Level Network Access):** Interacts directly with the Network Interface Card (NIC) via Layer 2 raw sockets (`AF_PACKET`)[cite: 1]. It constructs frames at the byte level, binds sockets to the selected interface, and rapidly transmits packets across the local subnet (`.1` to `.254`)[cite: 1].
* **Python Engine (Data Management & Processing):** Ingests the parsed stdout stream from the C++ binary[cite: 1]. It handles data normalization, offline IEEE OUI vendor lookups, hostname resolution, SQLite storage, and serves the interactive Flask web dashboard[cite: 1].

---

### 2. OSI Layer Mechanics (Layer 2 & Layer 3 Integration)

The scanner operates directly at the boundary between Layer 2 (Data Link) and Layer 3 (Network) of the OSI model:

* **Layer 3 (IP Addressing):** Iterates sequentially through the logical IPv4 address pool (`192.168.x.1` to `192.168.x.254`)[cite: 1].
* **Layer 2 (Ethernet Framing):** Because delivery over local networks relies on physical addresses, each query is wrapped inside a raw Layer 2 Ethernet frame addressed to the universal broadcast MAC (`FF:FF:FF:FF:FF:FF`).

---

### 3. Protocol Workflow (Address Resolution Protocol - ARP)

```text
[ C++ Scanner Engine ]  == (Broadcast ARP Request) ==>  [ All Local Devices (.1 - .254) ]
   └─ "Who owns IP 192.168.x.N? Here is my IP and MAC address."

[ Target Host Device ]  <== (Unicast ARP Reply) =====  [ C++ Listening Loop ]
   └─ "I own IP 192.168.x.N! My physical MAC is AA:BB:CC:DD:EE:FF."
```

* **Broadcast Transmission:** The C++ scanner broadcasts custom ARP request frames across the entire subnet[cite: 1]. It broadcasts our machine's IP and MAC address while requesting the hardware details of every target host[cite: 1].
* **Device Identification:** Every active host on the Wi-Fi network receives the Layer 2 broadcast frame. The host whose configured IP matches the queried address sends a unicast ARP reply directly back to our MAC address, revealing its physical MAC address[cite: 1].
* **Data Ingestion:** The C++ engine captures responses during a timed capture window, filters out duplicate frames, and streams clean IP-to-MAC pairs to Python for database persistence and dashboard visualization[cite: 1].


+-----------------------------------------------------------------------------------+
|                                 HOME WIFI NETWORK                                 |
|                         (Connected Devices: .1 to .254)                           |
+-----------------------------------------+-----------------------------------------+
                                          ^
              1. Broadcast ARP Request    |    2. Unicast ARP Reply
                 ("Is anyone home?")[cite: 1]|       (IP + MAC Address)[cite: 1]
                                          v
=====================================================================================
                           COMPONENT 1: NETWORK SCANNER ENGINE                       
=====================================================================================
+-----------------------------------------------------------------------------------+
| C++ Network Scanner                                                               |
|  - Creates Layer 2 raw sockets to access Network Interface Card (NIC)             |
|  - Sends ARP requests across the local subnet (.1 to .254)[cite: 1]              |
|  - Collects incoming ARP replies containing IP and MAC addresses[cite: 1]        |
|  - Emits formatted scan data stream[cite: 1]                                     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          | Scan Data Stream (IP, MAC)[cite: 1]
                                          v
=====================================================================================
                       COMPONENT 2: DATA PROCESSING & MANAGEMENT                     
=====================================================================================
+-----------------------------------------------------------------------------------+
| Python Processing Backend                                                         |
|  - Receives IP and MAC address payload from C++ scanner[cite: 1]                 |
|  - Performs Vendor Lookup using Offline IEEE OUI Database[cite: 1]               |
|  - Resolves Hostnames and estimates Device Type (Phone, Laptop, IoT, etc.)[cite: 1]|
|  - Tracks device connection and disconnection history[cite: 1]                    |
+--------------------+------------------------------------+-------------------------+
                     |                                    |
                     v                                    v
        +-------------------------+          +-------------------------+
        | SQLite Database         |          | Offline IEEE OUI        |
        |  - Persists device list |          | Database                |
        |  - Logs connection      |          |  - Matches MAC address  |
        |    history[cite: 1]    |          |    to manufacturer[cite: 1]|
        +-------------------------+          +-------------------------+
                     |
                     v
=====================================================================================
                         COMPONENT 3: PRESENTATION & VISUALIZATION                   
=====================================================================================
+-----------------------------------------------------------------------------------+
| Flask Web Dashboard (Flask + HTML / CSS / JavaScript)                             |
|  - Serves live web dashboard for network monitoring[cite: 1]                     |
|  - Displays connected devices, MACs, hostnames, vendors & device types[cite: 1]   |
|  - Visualizes real-time status and historical log connections[cite: 1]           |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
                              [ END USER WEB DASHBOARD ][cite: 1]
