#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>

enum class LinkType {
    ETHERNET,
    RAW_IP,
    LOOPBACK
};

enum class NetProto {
    NONE,
    IPV4,
    IPV6,
    ARP
};

enum class TransProto {
    NONE,
    TCP,
    UDP,
    ICMP,
    IGMP,
    OTHER
};

enum class AppProto {
    NONE,
    DNS,
    HTTP,
    TLS,
    SSH,
    DHCP,
    NTP,
    RAW_DATA
};

struct EthernetHeader {
    std::string srcMac;
    std::string dstMac;
    uint16_t etherType = 0;
};

struct ArpHeader {
    uint16_t hwType = 0;
    uint16_t protoType = 0;
    uint8_t hwSize = 0;
    uint8_t protoSize = 0;
    uint16_t opcode = 0; // 1 = Request, 2 = Reply
    std::string senderMac;
    std::string senderIp;
    std::string targetMac;
    std::string targetIp;
};

struct IPv4Header {
    uint8_t version = 4;
    uint8_t ihl = 5;
    uint8_t tos = 0;
    uint16_t totalLength = 0;
    uint16_t id = 0;
    bool flagReserved = false;
    bool flagDF = false;
    bool flagMF = false;
    uint16_t fragmentOffset = 0;
    uint8_t ttl = 64;
    uint8_t protocol = 0;
    uint16_t checksum = 0;
    std::string srcIp;
    std::string dstIp;
};

struct IPv6Header {
    uint8_t version = 6;
    uint8_t trafficClass = 0;
    uint32_t flowLabel = 0;
    uint16_t payloadLength = 0;
    uint8_t nextHeader = 0;
    uint8_t hopLimit = 64;
    std::string srcIp;
    std::string dstIp;
};

struct TcpHeader {
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint32_t seqNum = 0;
    uint32_t ackNum = 0;
    uint8_t dataOffset = 5; // header length in 32-bit words
    bool flagURG = false;
    bool flagACK = false;
    bool flagPSH = false;
    bool flagRST = false;
    bool flagSYN = false;
    bool flagFIN = false;
    bool flagECE = false;
    bool flagCWR = false;
    uint16_t windowSize = 0;
    uint16_t checksum = 0;
    uint16_t urgentPointer = 0;
    std::string flagsString() const;
};

struct UdpHeader {
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint16_t length = 0;
    uint16_t checksum = 0;
};

struct IcmpHeader {
    uint8_t type = 0;
    uint8_t code = 0;
    uint16_t checksum = 0;
    std::string typeDescription() const;
};

struct DnsRecord {
    std::string name;
    uint16_t type = 1; // 1 = A, 28 = AAAA, 15 = MX, 5 = CNAME
    std::string value;
};

struct DnsInfo {
    uint16_t txId = 0;
    bool isResponse = false;
    uint8_t opCode = 0;
    bool authoritative = false;
    bool truncated = false;
    bool recursionDesired = false;
    bool recursionAvailable = false;
    uint8_t rcode = 0;
    std::vector<DnsRecord> queries;
    std::vector<DnsRecord> answers;
};

struct HttpInfo {
    bool isRequest = false;
    std::string method;
    std::string uri;
    std::string version;
    int statusCode = 0;
    std::string statusMessage;
    std::string host;
    std::string contentType;
    std::string userAgent;
    size_t contentLength = 0;
    std::string bodyPreview;
};

struct TlsInfo {
    uint8_t contentType = 0; // 22 = Handshake
    uint16_t version = 0;
    uint8_t handshakeType = 0; // 1 = ClientHello, 2 = ServerHello
    std::string sni; // Server Name Indication
};

struct FieldItem {
    std::string label;
    std::string value;
};

struct ProtocolNode {
    std::string title;
    std::vector<FieldItem> fields;
    std::vector<ProtocolNode> children;
};

struct ParsedPacket {
    uint64_t id = 0;
    double timestampRel = 0.0; // Seconds since capture began
    std::string timestampStr;
    
    LinkType linkType = LinkType::ETHERNET;
    NetProto netProto = NetProto::NONE;
    TransProto transProto = TransProto::NONE;
    AppProto appProto = AppProto::NONE;

    EthernetHeader eth;
    ArpHeader arp;
    IPv4Header ip4;
    IPv6Header ip6;
    TcpHeader tcp;
    UdpHeader udp;
    IcmpHeader icmp;
    DnsInfo dns;
    HttpInfo http;
    TlsInfo tls;

    std::string srcStr;
    std::string dstStr;
    std::string protocolStr;
    std::string summaryInfo;

    // Visual color tags (RGBA)
    uint32_t colorTag = 0xFFFFFFFF;

    // Security flags
    bool isSuspicious = false;
    std::string suspiciousReason;

    // Raw payload bytes
    std::vector<uint8_t> rawBytes;
    size_t payloadOffset = 0;
    size_t payloadLength = 0;

    std::vector<ProtocolNode> getDissectionTree() const;
};
