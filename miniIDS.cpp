#include <pcap.h>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <unordered_map>
#include <set>
#include <fstream>
#include <ctime>
#include <thread>
#include <chrono>
#include <sstream>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;
//NETWORK HEADERS


struct ethernet_header {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

struct tcp_header {
    u_short source_port;
    u_short dest_port;
};

//GLOBAL DATA


unordered_map<string, set<int>> portScanTracker;
unordered_map<string, int> failedLoginAttempts;
set<string> blacklist;
ofstream alertFile("alerts.txt", ios::app);
 //UTILITY FUNCTION

string currentTime()
{
    time_t now = time(0);
    char* dt = ctime(&now);
    return string(dt);
}

void generateAlert(string message)
{
    cout << "[ALERT] " << message << endl;
    alertFile << currentTime() << " [ALERT] " << message << endl;
}

void loadBlacklist()
{
    ifstream file("blacklist.txt");
    string ip;
    while (file >> ip)
        blacklist.insert(ip);
}

// INCIDENT REPORT GENERATOR


void generateIncidentReport()
{
    ifstream alerts("alerts.txt");
    ofstream report("incident_report.txt");

    report << "===== MINI IDS INCIDENT REPORT =====\n\n";
    report << "Generated: " << currentTime() << "\n";
    report << "Detected Security Alerts:\n\n";

    string line;
    while (getline(alerts, line))
        report << line << endl;

    report.close();
}


// BRUTE FORCE LOG ANALYZER

void analyzeLogs()
{
    while (true)
    {
        ifstream logfile("auth.log");
        string line;

        while (getline(logfile, line))
        {
            if (line.find("Failed password") != string::npos)
            {
                stringstream ss(line);
                string word, ip;

                while (ss >> word)
                    ip = word;

                failedLoginAttempts[ip]++;

                if (failedLoginAttempts[ip] == 5)
                    generateAlert("BRUTE FORCE detected from " + ip);
            }
        }

        logfile.close();
        this_thread::sleep_for(chrono::seconds(10));
    }
}

// PACKET HANDLER (CORE IDS)


void packetHandler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    ethernet_header *eth = (ethernet_header*)pkt_data;
    iphdr *ipHeader = (iphdr*)(pkt_data + sizeof(ethernet_header));

    struct in_addr src, dst;
    src.s_addr = ipHeader->saddr;
    dst.s_addr = ipHeader->daddr;

    string srcIP = inet_ntoa(src);
    string dstIP = inet_ntoa(dst);

    cout << "Packet: " << srcIP << " -> " << dstIP << endl;

    // BLACKLIST DETECTION
    if (blacklist.count(srcIP))
        generateAlert("BLACKLISTED IP detected: " + srcIP);

    // TCP ONLY
    if (ipHeader->protocol == IPPROTO_TCP)
    {
        tcp_header *tcp = (tcp_header*)(pkt_data + sizeof(ethernet_header) + sizeof(iphdr));
        int destPort = ntohs(tcp->dest_port);

        portScanTracker[srcIP].insert(destPort);

        if (portScanTracker[srcIP].size() > 20)
        {
            generateAlert("PORT SCAN detected from " + srcIP);
            portScanTracker[srcIP].clear();
        }
    }
}

// MAIN FUNCTION


int main()
{
    loadBlacklist();

    // start log analyzer thread
    thread logThread(analyzeLogs);
    logThread.detach();

    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cout << "Error finding devices: " << errbuf << endl;
        return -1;
    }

    int i = 0;
    for (device = alldevs; device != NULL; device = device->next)
        cout << ++i << ". " << device->name << endl;

    cout << "Select device number: ";
    int choice;
    cin >> choice;

    device = alldevs;
    for (i = 1; i < choice; i++)
        device = device->next;

    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);

    if (handle == NULL)
    {
        cout << "Unable to open adapter." << endl;
        return -1;
    }

    cout << "\nMiniIDS Running... Monitoring Network & Logs...\n";
    cout << "Press CTRL+C to stop and generate report.\n\n";

    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
    alertFile.close();

    generateIncidentReport();

    return 0;
}
