#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <iomanip>

class PacketScanner {
private:
    pcap_t *handle;
    struct bpf_program fp;
    std::vector<std::string> captured_packets;
    int packet_count;
    int captured;
    
public:
    PacketScanner();
    ~PacketScanner();
    
    bool initialize_capture(const std::string &interface);
    void start_capture(int num_packets, const std::string &filter = "");
    static void packet_callback(unsigned char *user, const struct pcap_pkthdr *pkthdr, 
                                const unsigned char *packet);
    void process_packet(const unsigned char *packet, int length);
    void display_packet_info();
    std::vector<std::string> get_packets() const;
};

PacketScanner::PacketScanner() : handle(nullptr), packet_count(0), captured(0) {}

PacketScanner::~PacketScanner() {
    if (handle) {
        pcap_close(handle);
    }
}

bool PacketScanner::initialize_capture(const std::string &interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return false;
    }
    std::cout << "Successfully initialized capture on interface: " << interface << std::endl;
    return true;
}

void PacketScanner::process_packet(const unsigned char *packet, int length) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    std::string packet_info;
    
    // Ethernet frame info
    packet_info += "=== Packet #" + std::to_string(captured + 1) + " ===\n";
    packet_info += "Source MAC: ";
    for (int i = 0; i < 6; i++) {
        char buf[3];
        sprintf(buf, "%02x", eth_header->ether_shost[i]);
        packet_info += buf;
        if (i < 5) packet_info += ":";
    }
    packet_info += "\n";
    
    packet_info += "Dest MAC: ";
    for (int i = 0; i < 6; i++) {
        char buf[3];
        sprintf(buf, "%02x", eth_header->ether_dhost[i]);
        packet_info += buf;
        if (i < 5) packet_info += ":";
    }
    packet_info += "\n";
    
    // IP packet processing
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        struct in_addr source_ip, dest_ip;
        source_ip.s_addr = ip_header->ip_src.s_addr;
        dest_ip.s_addr = ip_header->ip_dst.s_addr;
        
        packet_info += "Protocol: IP\n";
        packet_info += "Source IP: " + std::string(inet_ntoa(source_ip)) + "\n";
        packet_info += "Dest IP: " + std::string(inet_ntoa(dest_ip)) + "\n";
        packet_info += "TTL: " + std::to_string(ip_header->ip_ttl) + "\n";
        
        // TCP packet processing
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + 
                                                         (ip_header->ip_hl * 4));
            packet_info += "Transport: TCP\n";
            packet_info += "Source Port: " + std::to_string(ntohs(tcp_header->th_sport)) + "\n";
            packet_info += "Dest Port: " + std::to_string(ntohs(tcp_header->th_dport)) + "\n";
            packet_info += "Flags: ";
            if (tcp_header->th_flags & TH_SYN) packet_info += "SYN ";
            if (tcp_header->th_flags & TH_ACK) packet_info += "ACK ";
            if (tcp_header->th_flags & TH_FIN) packet_info += "FIN ";
            if (tcp_header->th_flags & TH_RST) packet_info += "RST ";
            packet_info += "\n";
        }
        // UDP packet processing
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + 
                                                         (ip_header->ip_hl * 4));
            packet_info += "Transport: UDP\n";
            packet_info += "Source Port: " + std::to_string(ntohs(udp_header->uh_sport)) + "\n";
            packet_info += "Dest Port: " + std::to_string(ntohs(udp_header->uh_dport)) + "\n";
        }
        // ICMP packet processing
        else if (ip_header->ip_p == IPPROTO_ICMP) {
            packet_info += "Transport: ICMP\n";
        }
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        packet_info += "Protocol: ARP\n";
    }
    
    packet_info += "Packet Length: " + std::to_string(length) + " bytes\n";
    packet_info += "---\n";
    
    captured_packets.push_back(packet_info);
    captured++;
}

void PacketScanner::packet_callback(unsigned char *user, const struct pcap_pkthdr *pkthdr, 
                                    const unsigned char *packet) {
    PacketScanner *scanner = (PacketScanner *)user;
    scanner->process_packet(packet, pkthdr->len);
}

void PacketScanner::start_capture(int num_packets, const std::string &filter) {
    if (!handle) {
        std::cerr << "Packet capture not initialized" << std::endl;
        return;
    }
    
    packet_count = num_packets;
    captured = 0;
    
    std::cout << "Starting packet capture for " << num_packets << " packets..." << std::endl;
    
    if (!filter.empty()) {
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
            return;
        }
        std::cout << "Filter applied: " << filter << std::endl;
    }
    
    pcap_loop(handle, num_packets, packet_callback, (unsigned char *)this);
    std::cout << "Captured " << captured << " packets" << std::endl;
}

void PacketScanner::display_packet_info() {
    if (captured_packets.empty()) {
        std::cout << "No packets captured" << std::endl;
        return;
    }
    
    std::cout << "\n========== CAPTURED PACKETS ==========" << std::endl;
    for (const auto &packet : captured_packets) {
        std::cout << packet << std::endl;
    }
    std::cout << "========== END OF PACKETS ==========" << std::endl;
}

std::vector<std::string> PacketScanner::get_packets() const {
    return captured_packets;
}

// Function to display usage
void print_usage(const char *program_name) {
    std::cout << "\n===== WiFi Packet Scanner =====" << std::endl;
    std::cout << "Usage: " << program_name << " <interface> <packet_count> [filter]" << std::endl;
    std::cout << "\nArguments:" << std::endl;
    std::cout << "  <interface>    - Network interface (e.g., eth0, wlan0, ens0)" << std::endl;
    std::cout << "  <packet_count> - Number of packets to capture (1-10000)" << std::endl;
    std::cout << "  [filter]       - Optional BPF filter (e.g., 'tcp port 80', 'udp', 'arp')" << std::endl;
    std::cout << "\nExamples:" << std::endl;
    std::cout << "  " << program_name << " wlan0 10" << std::endl;
    std::cout << "  " << program_name << " eth0 50 'tcp port 443'" << std::endl;
    std::cout << "  " << program_name << " wlan0 20 'arp'" << std::endl;
    std::cout << "\nNote: Run with sudo for network interfaces other than localhost" << std::endl;
    std::cout << "================================\n" << std::endl;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string interface = argv[1];
    int packet_count;
    
    try {
        packet_count = std::stoi(argv[2]);
        if (packet_count <= 0 || packet_count > 10000) {
            std::cerr << "Error: Packet count must be between 1 and 10000" << std::endl;
            return 1;
        }
    } catch (const std::exception &e) {
        std::cerr << "Error: Invalid packet count. Must be a number." << std::endl;
        return 1;
    }
    
    std::string filter = "";
    if (argc > 3) {
        filter = argv[3];
    }
    
    PacketScanner scanner;
    
    if (!scanner.initialize_capture(interface)) {
        std::cerr << "Failed to initialize packet capture" << std::endl;
        return 1;
    }
    
    scanner.start_capture(packet_count, filter);
    scanner.display_packet_info();
    
    return 0;
}
