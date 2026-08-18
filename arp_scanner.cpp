// ============================================================
// Phase 1: Raw Socket ARP Scanner
// ============================================================
// A lightweight ARP scanner utilizing Layer 2 raw sockets.
// It iterates through a /24 subnet, broadcasts custom ARP 
// requests, and listens for replies to map IPs to MAC addresses.
//
// Requires: root/sudo privileges (for AF_PACKET/SOCK_RAW)
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

using namespace std;

// Standard ARP header structure (RFC 826)
// Defines the exact byte layout required for an ARP packet.
struct arp_header {
    uint16_t htype;      // Hardware type (1 = Ethernet)
    uint16_t ptype;      // Protocol type (0x0800 = IPv4)
    uint8_t  hlen;       // Hardware length (6 for MAC)
    uint8_t  plen;       // Protocol length (4 for IPv4)
    uint16_t opcode;     // Operation (1 = Request, 2 = Reply)
    uint8_t  sender_mac[6]; 
    uint8_t  sender_ip[4];  
    uint8_t  target_mac[6]; 
    uint8_t  target_ip[4];  
};

// Full Ethernet frame containing an ARP payload
struct arp_packet {
    struct ether_header eth_hdr; 
    struct arp_header arp_hdr;
};

// ------------------------------------------------------------
// Utility Functions
// ------------------------------------------------------------

// Converts a string IP (e.g., "192.168.1.5") into 4 raw bytes
void ip_string_to_bytes(const string& ip, uint8_t* out) {
    sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu", &out[0], &out[1], &out[2], &out[3]);
}

// Formats 6 raw MAC bytes into a readable string (e.g., 00:1A:2B:3C:4D:5E)
string mac_to_string(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(buf);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: sudo " << argv[0] << " <interface> <subnet_base>\n";
        cerr << "Example: sudo " << argv[0] << " eth0 192.168.1\n";
        return 1;
    }

    string iface_name = argv[1]; 
    string subnet_base = argv[2]; 

    // Open a raw socket to send/receive custom Layer 2 frames
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock_fd < 0) {
        perror("socket() failed - ensure you are running with sudo");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    // Get the internal index of the network interface
    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX failed");
        close(sock_fd);
        return 1;
    }
    int if_index = ifr.ifr_ifindex;

    // Grab our own MAC address (needed for the sender field)
    if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR failed");
        close(sock_fd);
        return 1;
    }
    uint8_t my_mac[6];
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    // Grab our own IP address
    if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR failed");
        close(sock_fd);
        return 1;
    }
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    uint8_t my_ip[4];
    memcpy(my_ip, &ipaddr->sin_addr.s_addr, 4);

    // Output setup info to stderr to keep stdout clean for data piping
    cerr << "Using interface: " << iface_name
              << " | My MAC: " << mac_to_string(my_mac)
              << " | My IP: " << (int)my_ip[0] << "." << (int)my_ip[1]
              << "." << (int)my_ip[2] << "." << (int)my_ip[3] << "\n";

    // Bind the socket to the specific interface
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

    // Set a short socket timeout so recvfrom() doesn't block forever
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 3000; 
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Target addresses for the outgoing packet
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};

    vector<pair<string, string>> found_devices; 

    // Loop through IPs .1 to .254 and broadcast an ARP request for each
    for (int i = 1; i <= 254; i++) {
        string target_ip_str = subnet_base + "." + to_string(i);
        uint8_t target_ip[4];
        ip_string_to_bytes(target_ip_str, target_ip);

        struct arp_packet packet;
        memset(&packet, 0, sizeof(packet));

        // Construct Ethernet Header
        memcpy(packet.eth_hdr.ether_dhost, broadcast_mac, 6);
        memcpy(packet.eth_hdr.ether_shost, my_mac, 6);        
        packet.eth_hdr.ether_type = htons(ETH_P_ARP);         

        // Construct ARP Header
        packet.arp_hdr.htype = htons(1);       
        packet.arp_hdr.ptype = htons(0x0800);  
        packet.arp_hdr.hlen = 6;               
        packet.arp_hdr.plen = 4;               
        packet.arp_hdr.opcode = htons(1);      // 1 = Request
        
        memcpy(packet.arp_hdr.sender_mac, my_mac, 6);   
        memcpy(packet.arp_hdr.sender_ip, my_ip, 4);     
        
        memcpy(packet.arp_hdr.target_mac, zero_mac, 6); // Target MAC unknown
        memcpy(packet.arp_hdr.target_ip, target_ip, 4); 

        // Send the raw frame
        struct sockaddr_ll send_addr = sll;
        memcpy(send_addr.sll_addr, broadcast_mac, 6);
        send_addr.sll_halen = 6;

        sendto(sock_fd, &packet, sizeof(packet), 0,
               (struct sockaddr*)&send_addr, sizeof(send_addr));
    }

    cerr << "ARP requests sent to " << subnet_base << ".1 to .254. Listening for replies...\n";

    // Listen for incoming ARP replies for exactly 3 seconds
    uint8_t buffer[65536];
    struct timeval start, now;
    gettimeofday(&start, nullptr);

    while (true) {
        gettimeofday(&now, nullptr);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1e6;
        if (elapsed > 3.0) break; 

        ssize_t len = recvfrom(sock_fd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len < 0) continue; 

        struct arp_packet* reply = (struct arp_packet*)buffer;

        // Only process valid ARP replies (opcode == 2)
        if (ntohs(reply->arp_hdr.opcode) == 2) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                      reply->arp_hdr.sender_ip[0], reply->arp_hdr.sender_ip[1],
                      reply->arp_hdr.sender_ip[2], reply->arp_hdr.sender_ip[3]);

            string mac_str = mac_to_string(reply->arp_hdr.sender_mac);

            // Prevent duplicate entries
            bool already_found = false;
            for (auto& d : found_devices) {
                if (d.first == ip_str) { already_found = true; break; }
            }
            
            if (!already_found) {
                found_devices.push_back({ip_str, mac_str});
            }
        }
    }

    // Output results to stdout in CSV format (IP,MAC)
    // Using cerr for the summary ensures stdout remains easily parsable
    cerr << "\nTotal Active Devices Discovered: " << found_devices.size() << "\n";
    for (auto& d : found_devices) {
        cout << d.first << "," << d.second << "\n";
    }

    close(sock_fd);
    return 0;
}
