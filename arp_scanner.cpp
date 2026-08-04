// ============================================================
// Phase 1: Raw Socket ARP Scanner
// ============================================================
// What this does:
//   1. Opens a raw socket (layer 2 - direct Ethernet access)
//   2. Builds a custom ARP request packet byte-by-byte
//   3. Broadcasts it to every IP in the given subnet
//   4. Listens for ARP replies and records IP + MAC of who replied
//
// Requires: root/sudo privileges (raw sockets need elevated access)
// Compile:  g++ arp_scanner.cpp -o arp_scanner
// Run:      sudo ./arp_scanner <interface> <subnet_base>
// Example:  sudo ./arp_scanner eth0 192.168.1
// ============================================================

#include <iostream>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <vector>
#include <string>

// ARP header structure (as defined by the ARP protocol spec)
struct arp_header {
    uint16_t htype;      // Hardware type (1 = Ethernet)
    uint16_t ptype;      // Protocol type (0x0800 = IPv4)
    uint8_t  hlen;        // Hardware address length (6 for MAC)
    uint8_t  plen;        // Protocol address length (4 for IPv4)
    uint16_t opcode;      // 1 = request, 2 = reply
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};

// Full Ethernet frame containing an ARP packet
struct arp_packet {
    struct ether_header eth_hdr;
    struct arp_header arp_hdr;
};

// Utility: convert "192.168.1.5" string into 4 raw bytes
void ip_string_to_bytes(const std::string& ip, uint8_t* out) {
    sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &out[0], &out[1], &out[2], &out[3]);
}

// Utility: print MAC address bytes as human-readable string
std::string mac_to_string(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: sudo " << argv[0] << " <interface> <subnet_base>\n";
        std::cerr << "Example: sudo " << argv[0] << " eth0 192.168.1\n";
        return 1;
    }

    std::string iface_name = argv[1];
    std::string subnet_base = argv[2]; // e.g. "192.168.1" (we scan .1 to .254)

    // ---- Step 1: Create a raw socket ----
    // AF_PACKET + SOCK_RAW gives us direct access to Ethernet frames
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock_fd < 0) {
        perror("socket() failed - are you running with sudo?");
        return 1;
    }

    // ---- Step 2: Get our own interface details (index + MAC + IP) ----
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    // Get interface index (needed to bind socket to this interface)
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX failed - check interface name");
        close(sock_fd);
        return 1;
    }
    int if_index = ifr.ifr_ifindex;

    // Get our own MAC address
    if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR failed");
        close(sock_fd);
        return 1;
    }
    uint8_t my_mac[6];
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Get our own IP address
    if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR failed");
        close(sock_fd);
        return 1;
    }
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    uint8_t my_ip[4];
    memcpy(my_ip, &ipaddr->sin_addr.s_addr, 4);

    // Status/info messages go to stderr so they don't pollute the
    // clean CSV data on stdout (which Python will parse)
    std::cerr << "Using interface: " << iface_name
              << " | My MAC: " << mac_to_string(my_mac)
              << " | My IP: " << (int)my_ip[0] << "." << (int)my_ip[1]
              << "." << (int)my_ip[2] << "." << (int)my_ip[3] << "\n";

    // ---- Step 3: Bind socket to our interface ----
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_protocol = htons(ETH_P_ARP);

    if (bind(sock_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind() failed");
        close(sock_fd);
        return 1;
    }

    // ---- Step 4: Set a read timeout (so we don't wait forever for replies) ----
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 3000; // 3ms non-blocking-ish check between sends
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Broadcast MAC address (FF:FF:FF:FF:FF:FF) - sent to everyone
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};

    std::vector<std::pair<std::string, std::string>> found_devices; // (ip, mac)

    // ---- Step 5: Loop through 1-254 and send ARP request to each ----
    for (int i = 1; i <= 254; i++) {
        std::string target_ip_str = subnet_base + "." + std::to_string(i);
        uint8_t target_ip[4];
        ip_string_to_bytes(target_ip_str, target_ip);

        // Build the packet
        struct arp_packet packet;
        memset(&packet, 0, sizeof(packet));

        // Ethernet header
        memcpy(packet.eth_hdr.ether_dhost, broadcast_mac, 6); // destination: everyone
        memcpy(packet.eth_hdr.ether_shost, my_mac, 6);        // source: us
        packet.eth_hdr.ether_type = htons(ETH_P_ARP);

        // ARP header
        packet.arp_hdr.htype = htons(1);       // Ethernet
        packet.arp_hdr.ptype = htons(0x0800);  // IPv4
        packet.arp_hdr.hlen = 6;
        packet.arp_hdr.plen = 4;
        packet.arp_hdr.opcode = htons(1);      // 1 = ARP request
        memcpy(packet.arp_hdr.sender_mac, my_mac, 6);
        memcpy(packet.arp_hdr.sender_ip, my_ip, 4);
        memcpy(packet.arp_hdr.target_mac, zero_mac, 6); // unknown - that's what we're asking
        memcpy(packet.arp_hdr.target_ip, target_ip, 4);

        // Send it out
        struct sockaddr_ll send_addr = sll;
        memcpy(send_addr.sll_addr, broadcast_mac, 6);
        send_addr.sll_halen = 6;

        sendto(sock_fd, &packet, sizeof(packet), 0,
               (struct sockaddr*)&send_addr, sizeof(send_addr));
    }

    std::cerr << "ARP requests sent to " << subnet_base << ".1-254. Listening for replies...\n";

    // ---- Step 6: Listen for replies for a short window ----
    uint8_t buffer[65536];
    struct timeval start, now;
    gettimeofday(&start, nullptr);

    while (true) {
        gettimeofday(&now, nullptr);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1e6;
        if (elapsed > 3.0) break; // listen for 3 seconds total

        ssize_t len = recvfrom(sock_fd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len < 0) continue; // timeout, keep looping

        struct arp_packet* reply = (struct arp_packet*)buffer;

        // Only interested in ARP replies (opcode 2)
        if (ntohs(reply->arp_hdr.opcode) == 2) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                      reply->arp_hdr.sender_ip[0], reply->arp_hdr.sender_ip[1],
                      reply->arp_hdr.sender_ip[2], reply->arp_hdr.sender_ip[3]);

            std::string mac_str = mac_to_string(reply->arp_hdr.sender_mac);

            // Avoid duplicate entries
            bool already_found = false;
            for (auto& d : found_devices) {
                if (d.first == ip_str) { already_found = true; break; }
            }
            if (!already_found) {
                found_devices.push_back({ip_str, mac_str});
            }
        }
    }

    // ---- Step 7: Print results ----
    // Clean CSV output on stdout: ip,mac  (one device per line)
    // This is the ONLY thing printed to stdout - Python will read this directly.
    std::cerr << "\nDevices Found: " << found_devices.size() << "\n";
    for (auto& d : found_devices) {
        std::cout << d.first << "," << d.second << "\n";
    }

    close(sock_fd);
    return 0;
}