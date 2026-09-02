// ============================================================
// Phase 3: TCP Connect Port Scanner (Object-Oriented)
// ============================================================
// Compile:  g++ port_scanner.cpp -o port_scanner
// Run:      ./port_scanner <target_ip>
// ============================================================

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/select.h>

using namespace std;

// Represents a network port with its associated service label
struct PortInfo {
    int port;
    string label;
};

// Class responsible for storing scan results
class ScanResult {
public:
    int port;
    string label;
    bool isOpen;

    ScanResult(int p, const string& lbl, bool status) 
        : port(p), label(lbl), isOpen(status) {}
};

// Class responsible for managing and executing TCP port scans
class PortScanner {
private:
    string targetIp;
    int timeoutMs;
    vector<PortInfo> targetPorts;

    // Encapsulated low-level socket logic
    bool connectToPort(int port) const {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;

        // Set non-blocking mode
        fcntl(sock, F_SETFL, O_NONBLOCK);

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, targetIp.c_str(), &addr.sin_addr);

        connect(sock, (struct sockaddr*)&addr, sizeof(addr));

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        bool open = false;
        if (select(sock + 1, nullptr, &fdset, nullptr, &tv) > 0) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                open = true;
            }
        }

        close(sock);
        return open;
    }

public:
    // Constructor initializes target IP, timeout, and default common ports
    explicit PortScanner(string ip, int timeout_ms = 300) 
        : targetIp(move(ip)), timeoutMs(timeout_ms) {
        
        // Initialize default common ports database
        targetPorts = {
            {21,   "FTP"},       {22,   "SSH"},
            {23,   "Telnet"},    {53,   "DNS"},
            {80,   "HTTP (web)"},{135,  "MS-RPC"},
            {139,  "NetBIOS"},   {143,  "IMAP"},
            {443,  "HTTPS (web)"},{445,  "SMB (file sharing)"},
            {554,  "RTSP (camera/streaming)"},
            {631,  "IPP (printer)"},
            {3389, "RDP (remote desktop)"},
            {8080, "HTTP-alt (web)"},
            {8443, "HTTPS-alt (web)"},
            {9100, "JetDirect (printer)"}
        };
    }

    // Allow adding custom ports dynamically
    void addPort(int port, const string& label) {
        targetPorts.push_back({port, label});
    }

    // Execute the scan across all configured ports
    vector<ScanResult> scan() {
        vector<ScanResult> results;
        cerr << "Scanning " << targetIp << " for " << targetPorts.size() << " ports...\n";

        for (const auto& p : targetPorts) {
            bool open = connectToPort(p.port);
            if (open) {
                results.emplace_back(p.port, p.label, true);
                cerr << "  Port " << p.port << " (" << p.label << ") - OPEN\n";
            }
        }
        return results;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <target_ip>\n";
        return 1;
    }

    string target_ip = argv[1];

    // Create a scanner object
    PortScanner scanner(target_ip);

    // Run the scan
    vector<ScanResult> open_ports = scanner.scan();

    // Print CSV output to stdout for Python parsing
    for (const auto& res : open_ports) {
        cout << target_ip << "," << res.port << "," << res.label << "\n";
    }

    return 0;
}