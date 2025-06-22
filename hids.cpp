#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <ctime>
#include <cstring>
#include <sqlite3.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <filesystem>

// Attack detection thresholds
#define TCP_FLOOD_THRESHOLD 1000 // TCP packets per minute from same IP
#define UDP_FLOOD_THRESHOLD 300
#define ICMP_FLOOD_THRESHOLD 50
#define SYN_FLOOD_THRESHOLD 100
#define PORT_SCAN_THRESHOLD 100
#define TIME_WINDOW 60 // Time window in seconds for tracking

sqlite3 *db;
std::ofstream alert_log("hids_project/alerts.txt", std::ios::app);
std::unordered_map<std::string, std::pair<int, time_t>> tcp_count;
std::unordered_map<std::string, std::pair<int, time_t>> udp_count;
std::unordered_map<std::string, std::pair<int, time_t>> icmp_count;
std::unordered_map<std::string, std::pair<int, time_t>> syn_count;
std::unordered_map<std::string, std::vector<int>> port_scan_tracker;
std::unordered_map<std::string, time_t> port_scan_time;
bool alert_triggered = false;
int normal_counter = 0;

int init_database()
{
    int rc = sqlite3_open("/home/haera_here/Desktop/hids_project/signature.db", &db);
    if (rc)
    {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        std::cerr << "Make sure signature.db exists with proper table structure!" << std::endl;
        return rc;
    }

    std::cout << "[+] Connected to signature.db successfully" << std::endl;
    return SQLITE_OK;
}

void log_attack(const std::string &attack_type, const std::string &src_ip,
                const std::string &dst_ip, int dst_port, int packet_count,
                const std::string &severity)
{

    const char *sql = "INSERT INTO attacks (timestamp, attack_type, source_ip, target_ip, target_port, packet_count, severity, description) "
                      "VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK)
    {
        std::string description = attack_type + " detected from " + src_ip;

        sqlite3_bind_text(stmt, 1, attack_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, src_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, dst_ip.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, dst_port);
        sqlite3_bind_int(stmt, 5, packet_count);
        sqlite3_bind_text(stmt, 6, severity.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 7, description.c_str(), -1, SQLITE_STATIC);

        sqlite3_step(stmt);
    }
    else
    {
        std::cerr << "Failed to prepare SQL statement: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
}

void log_to_file(const std::string &message)
{
    if (alert_log.is_open())
    {
        time_t now = time(nullptr);
        char timebuf[64];
        std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

        alert_log << "[" << timebuf << "] " << message << std::endl;
    }
}

void clean_expired_entries(std::unordered_map<std::string, std::pair<int, time_t>> &counter, time_t current_time)
{
    auto it = counter.begin();
    while (it != counter.end())
    {
        if (current_time - it->second.second > TIME_WINDOW)
        {
            it = counter.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void detect_attacks(const std::string &protocol, const std::string &src_ip,
                    const std::string &dst_ip, int dst_port, const struct tcphdr *tcp_hdr = nullptr)
{

    time_t current_time = time(nullptr);
    if (src_ip.find("192.168.") == 0 || src_ip.find("10.") == 0 || src_ip.find("172.") == 0)
    {
        return; // Ignore internal IPs
    }
    // TCP Flood Detection
    if (protocol == "TCP")
    {
        clean_expired_entries(tcp_count, current_time);

        if (tcp_count.find(src_ip) == tcp_count.end())
        {
            tcp_count[src_ip] = {1, current_time};
        }
        else
        {
            tcp_count[src_ip].first++;
        }

        if (tcp_count[src_ip].first > TCP_FLOOD_THRESHOLD)
        {
            std::string alert_msg = "🚨 [ALERT] TCP FLOOD detected from " + src_ip +
                                    " (" + std::to_string(tcp_count[src_ip].first) +
                                    " packets in " + std::to_string(TIME_WINDOW) + " seconds)";

            std::cout << "\n"
                      << alert_msg << std::endl; // Console
            log_to_file(alert_msg);              // Log file

            log_attack("TCP_FLOOD", src_ip, dst_ip, dst_port, tcp_count[src_ip].first, "HIGH"); // DB
            tcp_count[src_ip].first = 0;
            alert_triggered = true;
        }
    }

    // SYN Flood Detection
    if (tcp_hdr && (tcp_hdr->th_flags & TH_SYN) && !(tcp_hdr->th_flags & TH_ACK))
    {
        clean_expired_entries(syn_count, current_time);

        if (syn_count.find(src_ip) == syn_count.end())
        {
            syn_count[src_ip] = {1, current_time};
        }
        else
        {
            syn_count[src_ip].first++;
        }

        if (syn_count[src_ip].first > SYN_FLOOD_THRESHOLD)
        {
            std::string alert_msg = "🚨 [ALERT] SYN FLOOD detected from " + src_ip +
                                    " (" + std::to_string(syn_count[src_ip].first) +
                                    " SYN packets in " + std::to_string(TIME_WINDOW) + " seconds)";

            std::cout << "\n"
                      << alert_msg << std::endl; // Console
            log_to_file(alert_msg);              // File

            log_attack("SYN_FLOOD", src_ip, dst_ip, dst_port, syn_count[src_ip].first, "CRITICAL"); // DB
            syn_count[src_ip].first = 0;
            alert_triggered = true;
        }
    }

    // Port Scan Detection
    if (dst_port > 0)
    {

        if (port_scan_time.find(src_ip) != port_scan_time.end() &&
            current_time - port_scan_time[src_ip] > TIME_WINDOW)
        {
            port_scan_tracker[src_ip].clear();
        }
        port_scan_time[src_ip] = current_time;

        auto &ports = port_scan_tracker[src_ip];
        if (std::find(ports.begin(), ports.end(), dst_port) == ports.end())
        {
            ports.push_back(dst_port);
        }

        if (ports.size() > PORT_SCAN_THRESHOLD)
        {
            std::string alert_msg = "🚨 [ALERT] PORT SCAN detected from " + src_ip +
                                    " (scanning " + std::to_string(ports.size()) +
                                    " different ports in " + std::to_string(TIME_WINDOW) + " seconds)";

            std::cout << "\n"
                      << alert_msg << std::endl; // Console
            log_to_file(alert_msg);              // Log file

            log_attack("PORT_SCAN", src_ip, dst_ip, 0, ports.size(), "MEDIUM"); // DB
            ports.clear();
            alert_triggered = true;
        }
    }

    // UDP Flood Detection
    else if (protocol == "UDP")
    {
        clean_expired_entries(udp_count, current_time);

        if (udp_count.find(src_ip) == udp_count.end())
        {
            udp_count[src_ip] = {1, current_time};
        }
        else
        {
            udp_count[src_ip].first++;
        }

        if (udp_count[src_ip].first > UDP_FLOOD_THRESHOLD)
        {
            std::string alert_msg = "🚨 [ALERT] UDP FLOOD detected from " + src_ip +
                                    " (" + std::to_string(udp_count[src_ip].first) +
                                    " packets in " + std::to_string(TIME_WINDOW) + " seconds)";

            std::cout << "\n"
                      << alert_msg << std::endl; // Console
            log_to_file(alert_msg);              // Log file

            log_attack("UDP_FLOOD", src_ip, dst_ip, dst_port, udp_count[src_ip].first, "HIGH"); // DB
            udp_count[src_ip].first = 0;
            alert_triggered = true;
        }
    }

    // ICMP Flood Detection
    else if (protocol == "ICMP")
    {
        clean_expired_entries(icmp_count, current_time);

        if (icmp_count.find(src_ip) == icmp_count.end())
        {
            icmp_count[src_ip] = {1, current_time};
        }
        else
        {
            icmp_count[src_ip].first++;
        }

        if (icmp_count[src_ip].first > ICMP_FLOOD_THRESHOLD)
        {
            std::string alert_msg = "🚨 [ALERT] ICMP FLOOD (Ping Flood) detected from " + src_ip +
                                    " (" + std::to_string(icmp_count[src_ip].first) +
                                    " packets in " + std::to_string(TIME_WINDOW) + " seconds)";

            std::cout << "\n"
                      << alert_msg << std::endl; // Console
            log_to_file(alert_msg);              // Log file

            log_attack("ICMP_FLOOD", src_ip, dst_ip, 0, icmp_count[src_ip].first, "MEDIUM"); // DB
            icmp_count[src_ip].first = 0;                                                    // Reset to avoid spam
            alert_triggered = true;
        }
    }
}

void packet_handler(u_char *, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (header->len < 34)
        return;

    const struct ip *ipHeader = (struct ip *)(packet + 14);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dst_ip, INET_ADDRSTRLEN);

    std::string protocol;
    int src_port = 0, dst_port = 0;
    const struct tcphdr *tcpHeader = nullptr;

    switch (ipHeader->ip_p)
    {
    case IPPROTO_TCP:
    {
        protocol = "TCP";
        if (header->len >= 14 + (ipHeader->ip_hl * 4) + 20)
        {
            tcpHeader = (struct tcphdr *)(packet + 14 + (ipHeader->ip_hl * 4));
            src_port = ntohs(tcpHeader->th_sport);
            dst_port = ntohs(tcpHeader->th_dport);
        }
        break;
    }
    case IPPROTO_UDP:
    {
        protocol = "UDP";
        if (header->len >= 14 + (ipHeader->ip_hl * 4) + 8)
        {
            const struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + (ipHeader->ip_hl * 4));
            src_port = ntohs(udpHeader->uh_sport);
            dst_port = ntohs(udpHeader->uh_dport);
        }
        break;
    }
    case IPPROTO_ICMP:
        protocol = "ICMP";
        break;
    default:
        protocol = "OTHER";
        break;
    }

    detect_attacks(protocol, std::string(src_ip), std::string(dst_ip), dst_port, tcpHeader);

    static int packet_counter = 0;
    packet_counter++;

    std::time_t rawtime = header->ts.tv_sec;
    char timebuf[64];
    std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&rawtime));

    if (!alert_triggered)
    {
        if (++normal_counter % 100 == 0)
        { // Show message every 100 packets
            std::cout << "[" << timebuf << "] Normal packet capturing..." << std::endl;
        }
    }
    else
    {
        if (src_port > 0 && dst_port > 0)
        {
            std::cout << "[" << timebuf << "] "
                      << "Protocol: " << protocol
                      << " | Src: " << src_ip << ":" << src_port
                      << " -> Dst: " << dst_ip << ":" << dst_port
                      << " | Length: " << header->len << " bytes" << std::endl;
        }
        else
        {
            std::cout << "[" << timebuf << "] "
                      << "Protocol: " << protocol
                      << " | Src: " << src_ip
                      << " -> Dst: " << dst_ip
                      << " | Length: " << header->len << " bytes" << std::endl;
        }
    }
}

void start_capture()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    char *device = pcap_lookupdev(errbuf);
    if (device == nullptr)
    {
        std::cerr << "Error finding default device: " << errbuf << std::endl;
        return;
    }

    std::cout << "[+] Using device: " << device << std::endl;

    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        std::cerr << "Could not open device " << device << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "[+] Starting packet capture..." << std::endl;
    std::cout << "[+] Press Ctrl+C to stop" << std::endl;
    std::cout << "------------------------------------------------------" << std::endl;

    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);
}

int main()
{
    std::cout << "[+] Network Intrusion Detection System Starting..." << std::endl;

    if (init_database() != SQLITE_OK)
    {
        std::cerr << "Failed to connect to signature.db!" << std::endl;
        std::cerr << "Please create the database and table first." << std::endl;
        return 1;
    }

    start_capture();

    sqlite3_close(db);

    if (alert_log.is_open())
    {
        alert_log.close();
    }
    return 0;
}
