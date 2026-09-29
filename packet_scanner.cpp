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

class PacketScanner {
private:
    pcap_t *handle;
    struct bpf_program fp;
    int captured;

public:
    PacketScanner() : handle(nullptr), captured(0) {}
    ~PacketScanner() { if (handle) pcap_close(handle); }

    bool initialize_capture(const std::string &interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        return handle != nullptr;
    }

    void process_packet(const unsigned char *packet, int length) {
        struct ether_header *eth_header = (struct ether_header *)packet;

        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
            std::string src_ip = inet_ntoa(ip_header->ip_src);
            std::string dst_ip = inet_ntoa(ip_header->ip_dst);

            int is_syn = 0, dport = 0, sport = 0;
            std::string proto = "OTHER";

            if (ip_header->ip_p == IPPROTO_TCP) {
                proto = "TCP";
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
                sport = ntohs(tcp_header->th_sport);
                dport = ntohs(tcp_header->th_dport);
                if (tcp_header->th_flags & TH_SYN) is_syn = 1;
            } 
            else if (ip_header->ip_p == IPPROTO_UDP) {
                proto = "UDP";
                struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
                sport = ntohs(udp_header->uh_sport);
                dport = ntohs(udp_header->uh_dport);
            } 
            else if (ip_header->ip_p == IPPROTO_ICMP) {
                proto = "ICMP";
            }

            // Output JSON line for Python to parse
            std::cout << "{\"src_ip\":\"" << src_ip << "\",\"dst_ip\":\"" << dst_ip 
                      << "\",\"proto\":\"" << proto << "\",\"sport\":" << sport 
                      << ",\"dport\":" << dport << ",\"syn\":" << is_syn 
                      << ",\"len\":" << length << "}" << std::endl;
        } 
        else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
            std::cout << "{\"proto\":\"ARP\",\"len\":" << length << "}" << std::endl;
        }
        captured++;
    }

    static void packet_callback(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
        PacketScanner *scanner = (PacketScanner *)user;
        scanner->process_packet(packet, pkthdr->len);
    }

    void start_capture(int num_packets, const std::string &filter = "") {
        if (!handle) return;
        if (!filter.empty()) {
            pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN);
            pcap_setfilter(handle, &fp);
        }
        pcap_loop(handle, num_packets, packet_callback, (unsigned char *)this);
    }
};

int main(int argc, char *argv[]) {
    if (argc < 3) return 1;
    std::string interface = argv[1];
    int packet_count = std::stoi(argv[2]);
    std::string filter = (argc > 3) ? argv[3] : "";

    PacketScanner scanner;
    if (scanner.initialize_capture(interface)) {
        scanner.start_capture(packet_count, filter);
    }
    return 0;
}