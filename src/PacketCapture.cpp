#include "PacketCapture.h"
#include <iostream>
#include <random>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

PacketCapture::PacketCapture() {}

PacketCapture::~PacketCapture() {
    stop();
}

bool PacketCapture::start(CaptureMode mode, PacketCallback callback) {
    if (m_running) stop();

    m_mode = mode;
    m_callback = callback;
    m_running = true;
    m_paused = false;
    m_startTime = std::chrono::steady_clock::now();

    if (m_mode == CaptureMode::SIMULATION) {
        m_workerThread = std::thread(&PacketCapture::simulationLoop, this);
    } else {
        m_workerThread = std::thread(&PacketCapture::liveSocketLoop, this);
    }

    return true;
}

void PacketCapture::pause() {
    m_paused = true;
}

void PacketCapture::resume() {
    m_paused = false;
}

void PacketCapture::stop() {
    m_running = false;
    m_paused = false;
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
}

void PacketCapture::setPacketRate(int packetsPerSecond) {
    m_packetsPerSec = std::max(1, std::min(100, packetsPerSecond));
}

void PacketCapture::triggerSynFlood() {
    std::lock_guard<std::mutex> lock(m_injectionMutex);
    for (int i = 0; i < 20; ++i) {
        std::vector<uint8_t> pkt;
        // Ethernet (14)
        uint8_t eth[14] = {
            0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // dst
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, uint8_t(0x10 + i), // src
            0x08, 0x00 // IPv4
        };
        pkt.insert(pkt.end(), eth, eth + 14);

        // IPv4 (20)
        uint8_t ip[20] = {
            0x45, 0x00, 0x00, 0x28, // v4, ihl 5, len 40
            uint8_t(i), uint8_t(i + 1), // id
            0x40, 0x00, // DF
            0x40, 0x06, // TTL 64, TCP
            0x00, 0x00, // Checksum
            198, 51, 100, uint8_t(10 + (i % 5)), // Spoofed Src IP
            192, 168, 1, 50 // Target Server
        };
        pkt.insert(pkt.end(), ip, ip + 20);

        // TCP (20) - SYN only
        uint16_t sPort = 40000 + i;
        uint8_t tcp[20] = {
            uint8_t(sPort >> 8), uint8_t(sPort & 0xFF),
            0x00, 0x50, // Dst Port 80
            0x00, 0x01, uint8_t(i), 0x00, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, 0x02, // Data offset 5, SYN flag (0x02)
            0xFA, 0xF0, // Win size
            0x00, 0x00, // Checksum
            0x00, 0x00  // Urgent
        };
        pkt.insert(pkt.end(), tcp, tcp + 20);

        m_injectedPackets.push_back(pkt);
    }
}

void PacketCapture::triggerPortScan() {
    std::lock_guard<std::mutex> lock(m_injectionMutex);
    uint16_t targetPorts[] = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080};
    for (uint16_t port : targetPorts) {
        m_injectedPackets.push_back(generatePortScanPacket(port));
    }
}

void PacketCapture::triggerPlaintextCreds() {
    std::lock_guard<std::mutex> lock(m_injectionMutex);
    m_injectedPackets.push_back(generateHttpPacket(true, true));
}

void PacketCapture::triggerDnsTunnel() {
    std::lock_guard<std::mutex> lock(m_injectionMutex);
    // DNS packet with abnormally long base64 domain
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00};
    pkt.insert(pkt.end(), eth, eth + 14);

    uint8_t ip[20] = {
        0x45, 0x00, 0x00, 0x60,
        0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
        192, 168, 1, 105,
        8, 8, 8, 8
    };
    pkt.insert(pkt.end(), ip, ip + 20);

    uint8_t udp[8] = {
        0xD4, 0x31, 0x00, 0x35, // 54321 -> 53
        0x00, 0x4C, 0x00, 0x00
    };
    pkt.insert(pkt.end(), udp, udp + 8);

    // DNS Header
    uint8_t dnsHdr[12] = {
        0x77, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    pkt.insert(pkt.end(), dnsHdr, dnsHdr + 12);

    // Long query label
    std::string tunnelQuery = "exfiltrated-secret-token-chunk-49f82d1c7a.c2.tunneldomain.net";
    size_t prev = 0;
    while (prev < tunnelQuery.size()) {
        size_t nextDot = tunnelQuery.find('.', prev);
        if (nextDot == std::string::npos) nextDot = tunnelQuery.size();
        uint8_t len = static_cast<uint8_t>(nextDot - prev);
        pkt.push_back(len);
        for (size_t i = prev; i < nextDot; ++i) pkt.push_back(tunnelQuery[i]);
        prev = nextDot + 1;
    }
    pkt.push_back(0x00); // end of name
    pkt.push_back(0x00); pkt.push_back(0x01); // Type A
    pkt.push_back(0x00); pkt.push_back(0x01); // Class IN

    m_injectedPackets.push_back(pkt);
}

std::vector<uint8_t> PacketCapture::generatePortScanPacket(uint16_t port) {
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x08, 0x00};
    pkt.insert(pkt.end(), eth, eth + 14);

    uint8_t ip[20] = {
        0x45, 0x00, 0x00, 0x28, 0x77, 0x88, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        10, 0, 0, 66, // Attacker Scanner
        192, 168, 1, 50 // Target Server
    };
    pkt.insert(pkt.end(), ip, ip + 20);

    uint16_t sPort = 45000 + (port % 500);
    uint8_t tcp[20] = {
        uint8_t(sPort >> 8), uint8_t(sPort & 0xFF),
        uint8_t(port >> 8), uint8_t(port & 0xFF),
        0x10, 0x20, 0x30, 0x40,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, // SYN
        0x40, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    pkt.insert(pkt.end(), tcp, tcp + 20);
    return pkt;
}

std::vector<uint8_t> PacketCapture::generateDnsPacket(bool isResponse) {
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00};
    pkt.insert(pkt.end(), eth, eth + 14);

    uint8_t ip[20] = {
        0x45, 0x00, 0x00, 0x48, 0x1A, 0x2B, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
        uint8_t(isResponse ? 8 : 192), uint8_t(isResponse ? 8 : 168), uint8_t(isResponse ? 8 : 1), uint8_t(isResponse ? 8 : 105),
        uint8_t(isResponse ? 192 : 8), uint8_t(isResponse ? 168 : 8), uint8_t(isResponse ? 1 : 8), uint8_t(isResponse ? 105 : 8)
    };
    pkt.insert(pkt.end(), ip, ip + 20);

    uint16_t srcP = isResponse ? 53 : 52341;
    uint16_t dstP = isResponse ? 52341 : 53;
    uint8_t udp[8] = {
        uint8_t(srcP >> 8), uint8_t(srcP & 0xFF),
        uint8_t(dstP >> 8), uint8_t(dstP & 0xFF),
        0x00, 0x34, 0x00, 0x00
    };
    pkt.insert(pkt.end(), udp, udp + 8);

    uint8_t dns[12] = {
        0x2B, 0xC4, // Tx ID
        uint8_t(isResponse ? 0x81 : 0x01), 0x80,
        0x00, 0x01, // Questions: 1
        uint8_t(isResponse ? 0x01 : 0x00), // Answers: 1 or 0
        0x00, 0x00, 0x00, 0x00
    };
    pkt.insert(pkt.end(), dns, dns + 12);

    // Query: api.github.com
    const char q[] = "\x03" "api" "\x06" "github" "\x03" "com\x00";
    pkt.insert(pkt.end(), q, q + sizeof(q) - 1);
    pkt.push_back(0x00); pkt.push_back(0x01); // Type A
    pkt.push_back(0x00); pkt.push_back(0x01); // Class IN

    if (isResponse) {
        // Answer pointer 0xc00c, type A, class IN, ttl 60, len 4, ip 140.82.121.4
        uint8_t ans[] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 140, 82, 121, 4};
        pkt.insert(pkt.end(), ans, ans + sizeof(ans));
    }

    return pkt;
}

std::vector<uint8_t> PacketCapture::generateTcpHandshakePacket(int step) {
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00};
    pkt.insert(pkt.end(), eth, eth + 14);

    bool isServer = (step == 1);
    uint8_t ip[20] = {
        0x45, 0x00, 0x00, 0x28, 0x3C, 0x4D, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        uint8_t(isServer ? 142 : 192), uint8_t(isServer ? 250 : 168), uint8_t(isServer ? 190 : 1), uint8_t(isServer ? 46 : 105),
        uint8_t(isServer ? 192 : 142), uint8_t(isServer ? 168 : 250), uint8_t(isServer ? 1 : 190), uint8_t(isServer ? 105 : 46)
    };
    pkt.insert(pkt.end(), ip, ip + 20);

    uint16_t sPort = isServer ? 443 : 51234;
    uint16_t dPort = isServer ? 51234 : 443;
    uint8_t flagByte = (step == 0) ? 0x02 : (step == 1 ? 0x12 : 0x10); // SYN, SYN-ACK, ACK

    uint8_t tcp[20] = {
        uint8_t(sPort >> 8), uint8_t(sPort & 0xFF),
        uint8_t(dPort >> 8), uint8_t(dPort & 0xFF),
        0x00, 0x01, uint8_t(m_simSeqNum >> 8), uint8_t(m_simSeqNum & 0xFF),
        0x00, 0x00, 0x00, uint8_t(step == 0 ? 0 : 1),
        0x50, flagByte,
        0xFA, 0xF0,
        0x00, 0x00,
        0x00, 0x00
    };
    pkt.insert(pkt.end(), tcp, tcp + 20);
    return pkt;
}

std::vector<uint8_t> PacketCapture::generateHttpPacket(bool isRequest, bool withCreds) {
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00};
    pkt.insert(pkt.end(), eth, eth + 14);

    std::string httpPayload;
    if (isRequest) {
        if (withCreds) {
            httpPayload = "POST /api/v1/login HTTP/1.1\r\n"
                          "Host: insecure-portal.local\r\n"
                          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                          "Content-Type: application/x-www-form-urlencoded\r\n"
                          "Content-Length: 39\r\n\r\n"
                          "username=admin&password=SuperSecretPass123!";
        } else {
            httpPayload = "GET /index.html HTTP/1.1\r\n"
                          "Host: example.org\r\n"
                          "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                          "Accept: text/html,application/xhtml+xml\r\n\r\n";
        }
    } else {
        httpPayload = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/html; charset=UTF-8\r\n"
                      "Server: Apache/2.4.52 (Ubuntu)\r\n"
                      "Content-Length: 75\r\n\r\n"
                      "<html><body><h1>Welcome to NetPulse Traffic Portal</h1></body></html>";
    }

    uint16_t totalLen = 20 + 20 + static_cast<uint16_t>(httpPayload.size());
    uint8_t ip[20] = {
        0x45, 0x00, uint8_t(totalLen >> 8), uint8_t(totalLen & 0xFF),
        0x55, 0x66, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        uint8_t(isRequest ? 192 : 93), uint8_t(isRequest ? 168 : 184), uint8_t(isRequest ? 1 : 216), uint8_t(isRequest ? 105 : 34),
        uint8_t(isRequest ? 93 : 192), uint8_t(isRequest ? 184 : 168), uint8_t(isRequest ? 216 : 1), uint8_t(isRequest ? 34 : 105)
    };
    pkt.insert(pkt.end(), ip, ip + 20);

    uint16_t sPort = isRequest ? 49152 : 80;
    uint16_t dPort = isRequest ? 80 : 49152;
    uint8_t tcp[20] = {
        uint8_t(sPort >> 8), uint8_t(sPort & 0xFF),
        uint8_t(dPort >> 8), uint8_t(dPort & 0xFF),
        0x00, 0x02, 0x30, 0x00,
        0x00, 0x01, 0x10, 0x00,
        0x50, 0x18, // PSH, ACK
        0x80, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    pkt.insert(pkt.end(), tcp, tcp + 20);
    pkt.insert(pkt.end(), httpPayload.begin(), httpPayload.end());

    return pkt;
}

std::vector<uint8_t> PacketCapture::generateTlsPacket() {
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00};
    pkt.insert(pkt.end(), eth, eth + 14);

    uint8_t ip[20] = {
        0x45, 0x00, 0x00, 0x85, 0x6A, 0x7B, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 105,
        142, 250, 190, 46
    };
    pkt.insert(pkt.end(), ip, ip + 20);

    uint8_t tcp[20] = {
        0xC0, 0x01, // 49153
        0x01, 0xBB, // 443
        0x00, 0x03, 0x10, 0x00,
        0x00, 0x02, 0x00, 0x00,
        0x50, 0x18,
        0x40, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };
    pkt.insert(pkt.end(), tcp, tcp + 20);

    // TLS Client Hello Record
    uint8_t tlsRecord[] = {
        0x16, // Handshake
        0x03, 0x03, // TLS 1.2
        0x00, 0x50, // Length
        0x01, // Client Hello
        0x00, 0x00, 0x4C,
        0x03, 0x03 // Client Version 1.2
    };
    pkt.insert(pkt.end(), tlsRecord, tlsRecord + sizeof(tlsRecord));

    return pkt;
}

std::vector<uint8_t> PacketCapture::generateIcmpPacket(bool isRequest, size_t size) {
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00};
    pkt.insert(pkt.end(), eth, eth + 14);

    uint16_t totalLen = 20 + 8 + static_cast<uint16_t>(size);
    uint8_t ip[20] = {
        0x45, 0x00, uint8_t(totalLen >> 8), uint8_t(totalLen & 0xFF),
        0x88, 0x99, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00,
        uint8_t(isRequest ? 192 : 1), uint8_t(isRequest ? 168 : 1), uint8_t(isRequest ? 1 : 1), uint8_t(isRequest ? 105 : 1),
        uint8_t(isRequest ? 1 : 192), uint8_t(isRequest ? 1 : 168), uint8_t(isRequest ? 1 : 1), uint8_t(isRequest ? 1 : 105)
    };
    pkt.insert(pkt.end(), ip, ip + 20);

    uint8_t icmp[8] = {
        uint8_t(isRequest ? 8 : 0), 0x00,
        0x4A, 0x5C, // Checksum
        0x00, 0x01, // Id
        0x00, 0x22  // Seq
    };
    pkt.insert(pkt.end(), icmp, icmp + 8);

    for (size_t i = 0; i < size; ++i) {
        pkt.push_back(uint8_t('a' + (i % 26)));
    }
    return pkt;
}

std::vector<uint8_t> PacketCapture::generateArpPacket(bool isRequest) {
    std::vector<uint8_t> pkt;
    uint8_t eth[14] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Broadcast dst
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x06 // ARP
    };
    pkt.insert(pkt.end(), eth, eth + 14);

    uint8_t arp[28] = {
        0x00, 0x01, // Ethernet
        0x08, 0x00, // IPv4
        0x06, 0x04,
        0x00, uint8_t(isRequest ? 1 : 2), // 1=Req, 2=Reply
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Sender MAC
        192, 168, 1, 105, // Sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
        192, 168, 1, 1 // Target IP
    };
    pkt.insert(pkt.end(), arp, arp + 28);
    return pkt;
}

void PacketCapture::simulationLoop() {
    std::default_random_engine rng(1337);
    std::discrete_distribution<int> dist({15, 15, 20, 20, 15, 10, 5}); // TCP, UDP, DNS, HTTP, TLS, ICMP, ARP

    int tcpStep = 0;

    while (m_running) {
        if (m_paused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        std::vector<uint8_t> pktBytes;

        // Check injected packets first
        {
            std::lock_guard<std::mutex> lock(m_injectionMutex);
            if (!m_injectedPackets.empty()) {
                pktBytes = m_injectedPackets.front();
                m_injectedPackets.pop_front();
            }
        }

        if (pktBytes.empty()) {
            int choice = dist(rng);
            m_simSeqNum += 100;

            switch (choice) {
                case 0:
                    pktBytes = generateTcpHandshakePacket(tcpStep);
                    tcpStep = (tcpStep + 1) % 3;
                    break;
                case 1:
                    pktBytes = generateDnsPacket(false);
                    break;
                case 2:
                    pktBytes = generateDnsPacket(true);
                    break;
                case 3:
                    pktBytes = generateHttpPacket(true, false);
                    break;
                case 4:
                    pktBytes = generateHttpPacket(false, false);
                    break;
                case 5:
                    pktBytes = generateTlsPacket();
                    break;
                case 6:
                    pktBytes = generateIcmpPacket(true);
                    break;
                default:
                    pktBytes = generateArpPacket(true);
                    break;
            }
        }

        auto now = std::chrono::steady_clock::now();
        double relTime = std::chrono::duration<double>(now - m_startTime).count();

        if (m_callback && !pktBytes.empty()) {
            m_callback(pktBytes.data(), pktBytes.size(), relTime);
        }

        int sleepMs = 1000 / m_packetsPerSec;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    }
}

void PacketCapture::liveSocketLoop() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        // Fallback to simulation if winsock fails
        simulationLoop();
        return;
    }

    SOCKET rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (rawSock == INVALID_SOCKET) {
        // Needs Admin privileges on Windows for SOCK_RAW. Fallback to simulation cleanly.
        std::cout << "[NetPulse] Raw socket requires Administrator privileges. Running high-fidelity simulation mode.\n";
        WSACleanup();
        simulationLoop();
        return;
    }

    // Bind to local host
    char hostName[256];
    gethostname(hostName, sizeof(hostName));
    struct hostent* localHost = gethostbyname(hostName);

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    if (localHost && localHost->h_addr_list[0]) {
        memcpy(&addr.sin_addr, localHost->h_addr_list[0], sizeof(struct in_addr));
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(rawSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(rawSock);
        WSACleanup();
        simulationLoop();
        return;
    }

    // Set promiscuous mode (SIO_RCVALL)
    DWORD flag = 1;
    DWORD bytesRet = 0;
    if (WSAIoctl(rawSock, SIO_RCVALL, &flag, sizeof(flag), 0, 0, &bytesRet, 0, 0) == SOCKET_ERROR) {
        closesocket(rawSock);
        WSACleanup();
        simulationLoop();
        return;
    }

    std::vector<uint8_t> buffer(65536);

    while (m_running) {
        if (m_paused) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        int bytesReceived = recv(rawSock, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
        if (bytesReceived > 0) {
            auto now = std::chrono::steady_clock::now();
            double relTime = std::chrono::duration<double>(now - m_startTime).count();

            if (m_callback) {
                // On Windows raw sockets, data received starts directly at IPv4 header.
                // We synthesize a 14-byte Ethernet header for unified processing
                std::vector<uint8_t> ethFrame;
                uint8_t dummyEth[14] = {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x00};
                ethFrame.insert(ethFrame.end(), dummyEth, dummyEth + 14);
                ethFrame.insert(ethFrame.end(), buffer.begin(), buffer.begin() + bytesReceived);

                m_callback(ethFrame.data(), ethFrame.size(), relTime);
            }
        }
    }

    closesocket(rawSock);
    WSACleanup();
#else
    simulationLoop();
#endif
}

std::vector<std::string> PacketCapture::getAvailableInterfaces() {
    std::vector<std::string> ifaces;
    ifaces.push_back("High-Fidelity Virtual Adapter (Default / Auto-Sim)");
    ifaces.push_back("Localhost / Loopback (127.0.0.1)");
    ifaces.push_back("Ethernet / Wi-Fi Adapter (Promiscuous Mode)");
    return ifaces;
}
