#include "ProtocolParser.h"
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>

static uint16_t readBE16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

static uint32_t readBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

std::string ProtocolParser::formatMac(const uint8_t* bytes) {
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    return ss.str();
}

std::string ProtocolParser::formatIPv4(const uint8_t* bytes) {
    return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
           std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
}

std::string ProtocolParser::formatIPv6(const uint8_t* bytes) {
    std::stringstream ss;
    for (int i = 0; i < 16; i += 2) {
        if (i > 0) ss << ":";
        ss << std::hex << readBE16(&bytes[i]);
    }
    return ss.str();
}

std::string ProtocolParser::readDnsName(const uint8_t* buffer, size_t length, size_t& offset) {
    std::string name;
    size_t curr = offset;
    bool jumped = false;
    size_t jumpCount = 0;

    while (curr < length && jumpCount < 10) {
        uint8_t len = buffer[curr];
        if (len == 0) {
            if (!jumped) offset = curr + 1;
            break;
        }

        // Pointer / compression
        if ((len & 0xC0) == 0xC0) {
            if (curr + 1 >= length) break;
            if (!jumped) {
                offset = curr + 2;
                jumped = true;
            }
            curr = ((len & 0x3F) << 8) | buffer[curr + 1];
            jumpCount++;
            continue;
        }

        curr++;
        if (curr + len > length) break;
        if (!name.empty()) name += ".";
        name.append(reinterpret_cast<const char*>(&buffer[curr]), len);
        curr += len;

        if (!jumped) offset = curr;
    }
    return name;
}

ParsedPacket ProtocolParser::parse(const uint8_t* buffer, size_t length, uint64_t id, double timestampRel, const std::string& timeStr, LinkType linkType) {
    ParsedPacket pkt;
    pkt.id = id;
    pkt.timestampRel = timestampRel;
    pkt.timestampStr = timeStr;
    pkt.linkType = linkType;
    pkt.rawBytes.assign(buffer, buffer + length);

    size_t offset = 0;

    if (linkType == LinkType::ETHERNET) {
        parseEthernet(buffer, length, pkt, offset);
    } else {
        // Assume Raw IPv4 if start with 0x45
        if (length > 0 && (buffer[0] >> 4) == 4) {
            pkt.netProto = NetProto::IPV4;
            parseIPv4(buffer, length, pkt, offset);
        }
    }

    assignColorAndSummary(pkt);
    return pkt;
}

void ProtocolParser::parseEthernet(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset) {
    if (length < 14) return;
    pkt.eth.dstMac = formatMac(&buffer[0]);
    pkt.eth.srcMac = formatMac(&buffer[6]);
    pkt.eth.etherType = readBE16(&buffer[12]);
    offset = 14;

    if (pkt.eth.etherType == 0x0800) {
        pkt.netProto = NetProto::IPV4;
        parseIPv4(buffer, length, pkt, offset);
    } else if (pkt.eth.etherType == 0x86DD) {
        pkt.netProto = NetProto::IPV6;
        parseIPv6(buffer, length, pkt, offset);
    } else if (pkt.eth.etherType == 0x0806) {
        pkt.netProto = NetProto::ARP;
        parseArp(buffer, length, pkt, offset);
    }
}

void ProtocolParser::parseArp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset) {
    if (offset + 28 > length) return;
    const uint8_t* p = &buffer[offset];
    pkt.arp.hwType = readBE16(&p[0]);
    pkt.arp.protoType = readBE16(&p[2]);
    pkt.arp.hwSize = p[4];
    pkt.arp.protoSize = p[5];
    pkt.arp.opcode = readBE16(&p[6]);
    pkt.arp.senderMac = formatMac(&p[8]);
    pkt.arp.senderIp = formatIPv4(&p[14]);
    pkt.arp.targetMac = formatMac(&p[18]);
    pkt.arp.targetIp = formatIPv4(&p[24]);

    pkt.srcStr = pkt.arp.senderIp;
    pkt.dstStr = pkt.arp.targetIp;
    pkt.protocolStr = "ARP";
}

void ProtocolParser::parseIPv4(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset) {
    if (offset + 20 > length) return;
    const uint8_t* p = &buffer[offset];
    pkt.ip4.version = (p[0] >> 4) & 0x0F;
    pkt.ip4.ihl = p[0] & 0x0F;
    if (pkt.ip4.ihl < 5) return;

    size_t ipHeaderLen = pkt.ip4.ihl * 4;
    if (offset + ipHeaderLen > length) return;

    pkt.ip4.tos = p[1];
    pkt.ip4.totalLength = readBE16(&p[2]);
    pkt.ip4.id = readBE16(&p[4]);

    uint16_t flagsAndFrag = readBE16(&p[6]);
    pkt.ip4.flagReserved = (flagsAndFrag & 0x8000) != 0;
    pkt.ip4.flagDF = (flagsAndFrag & 0x4000) != 0;
    pkt.ip4.flagMF = (flagsAndFrag & 0x2000) != 0;
    pkt.ip4.fragmentOffset = (flagsAndFrag & 0x1FFF);

    pkt.ip4.ttl = p[8];
    pkt.ip4.protocol = p[9];
    pkt.ip4.checksum = readBE16(&p[10]);
    pkt.ip4.srcIp = formatIPv4(&p[12]);
    pkt.ip4.dstIp = formatIPv4(&p[16]);

    pkt.srcStr = pkt.ip4.srcIp;
    pkt.dstStr = pkt.ip4.dstIp;

    offset += ipHeaderLen;

    if (pkt.ip4.protocol == 6) {
        pkt.transProto = TransProto::TCP;
        parseTcp(buffer, length, pkt, offset);
    } else if (pkt.ip4.protocol == 17) {
        pkt.transProto = TransProto::UDP;
        parseUdp(buffer, length, pkt, offset);
    } else if (pkt.ip4.protocol == 1) {
        pkt.transProto = TransProto::ICMP;
        parseIcmp(buffer, length, pkt, offset);
    } else {
        pkt.transProto = TransProto::OTHER;
        pkt.protocolStr = "IPv4 (Proto " + std::to_string(pkt.ip4.protocol) + ")";
    }
}

void ProtocolParser::parseIPv6(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset) {
    if (offset + 40 > length) return;
    const uint8_t* p = &buffer[offset];
    pkt.ip6.version = 6;
    pkt.ip6.payloadLength = readBE16(&p[4]);
    pkt.ip6.nextHeader = p[6];
    pkt.ip6.hopLimit = p[7];
    pkt.ip6.srcIp = formatIPv6(&p[8]);
    pkt.ip6.dstIp = formatIPv6(&p[24]);

    pkt.srcStr = pkt.ip6.srcIp;
    pkt.dstStr = pkt.ip6.dstIp;

    offset += 40;

    if (pkt.ip6.nextHeader == 6) {
        pkt.transProto = TransProto::TCP;
        parseTcp(buffer, length, pkt, offset);
    } else if (pkt.ip6.nextHeader == 17) {
        pkt.transProto = TransProto::UDP;
        parseUdp(buffer, length, pkt, offset);
    } else {
        pkt.transProto = TransProto::OTHER;
        pkt.protocolStr = "IPv6";
    }
}

void ProtocolParser::parseTcp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset) {
    if (offset + 20 > length) return;
    const uint8_t* p = &buffer[offset];
    pkt.tcp.srcPort = readBE16(&p[0]);
    pkt.tcp.dstPort = readBE16(&p[2]);
    pkt.tcp.seqNum = readBE32(&p[4]);
    pkt.tcp.ackNum = readBE32(&p[8]);
    pkt.tcp.dataOffset = (p[12] >> 4) & 0x0F;

    uint8_t flags = p[13];
    pkt.tcp.flagFIN = (flags & 0x01) != 0;
    pkt.tcp.flagSYN = (flags & 0x02) != 0;
    pkt.tcp.flagRST = (flags & 0x04) != 0;
    pkt.tcp.flagPSH = (flags & 0x08) != 0;
    pkt.tcp.flagACK = (flags & 0x10) != 0;
    pkt.tcp.flagURG = (flags & 0x20) != 0;
    pkt.tcp.flagECE = (flags & 0x40) != 0;
    pkt.tcp.flagCWR = (flags & 0x80) != 0;

    pkt.tcp.windowSize = readBE16(&p[14]);
    pkt.tcp.checksum = readBE16(&p[16]);
    pkt.tcp.urgentPointer = readBE16(&p[18]);

    size_t tcpHeaderLen = pkt.tcp.dataOffset * 4;
    offset += tcpHeaderLen;

    pkt.payloadOffset = offset;
    if (length > offset) {
        pkt.payloadLength = length - offset;
    }

    pkt.protocolStr = "TCP";

    // Application Layer Check
    if (pkt.tcp.srcPort == 80 || pkt.tcp.dstPort == 80 ||
        pkt.tcp.srcPort == 8080 || pkt.tcp.dstPort == 8080) {
        parseHttp(buffer, length, pkt, offset);
    } else if (pkt.tcp.srcPort == 443 || pkt.tcp.dstPort == 443) {
        parseTls(buffer, length, pkt, offset);
    } else if (pkt.payloadLength > 4) {
        // Quick check for HTTP headers
        const char* payload = reinterpret_cast<const char*>(&buffer[offset]);
        if (strncmp(payload, "GET ", 4) == 0 || strncmp(payload, "POST ", 5) == 0 ||
            strncmp(payload, "HTTP/", 5) == 0) {
            parseHttp(buffer, length, pkt, offset);
        }
    }
}

void ProtocolParser::parseUdp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset) {
    if (offset + 8 > length) return;
    const uint8_t* p = &buffer[offset];
    pkt.udp.srcPort = readBE16(&p[0]);
    pkt.udp.dstPort = readBE16(&p[2]);
    pkt.udp.length = readBE16(&p[4]);
    pkt.udp.checksum = readBE16(&p[6]);

    offset += 8;
    pkt.payloadOffset = offset;
    if (length > offset) {
        pkt.payloadLength = length - offset;
    }

    pkt.protocolStr = "UDP";

    if (pkt.udp.srcPort == 53 || pkt.udp.dstPort == 53) {
        parseDns(buffer, length, pkt, offset);
    } else if (pkt.udp.srcPort == 67 || pkt.udp.dstPort == 68 ||
               pkt.udp.srcPort == 68 || pkt.udp.dstPort == 67) {
        pkt.appProto = AppProto::DHCP;
        pkt.protocolStr = "DHCP";
    } else if (pkt.udp.srcPort == 123 || pkt.udp.dstPort == 123) {
        pkt.appProto = AppProto::NTP;
        pkt.protocolStr = "NTP";
    }
}

void ProtocolParser::parseIcmp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset) {
    if (offset + 4 > length) return;
    const uint8_t* p = &buffer[offset];
    pkt.icmp.type = p[0];
    pkt.icmp.code = p[1];
    pkt.icmp.checksum = readBE16(&p[2]);
    pkt.protocolStr = "ICMP";

    pkt.payloadOffset = offset + 4;
    if (length > pkt.payloadOffset) {
        pkt.payloadLength = length - pkt.payloadOffset;
    }
}

void ProtocolParser::parseDns(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset) {
    if (offset + 12 > length) return;
    pkt.appProto = AppProto::DNS;
    pkt.protocolStr = "DNS";

    const uint8_t* p = &buffer[offset];
    pkt.dns.txId = readBE16(&p[0]);
    uint16_t flags = readBE16(&p[2]);
    pkt.dns.isResponse = (flags & 0x8000) != 0;
    pkt.dns.opCode = (flags >> 11) & 0x0F;
    pkt.dns.rcode = flags & 0x0F;

    uint16_t qdCount = readBE16(&p[4]);
    uint16_t anCount = readBE16(&p[6]);

    size_t curr = offset + 12;
    for (uint16_t i = 0; i < qdCount && curr < length; ++i) {
        std::string name = readDnsName(buffer, length, curr);
        if (curr + 4 <= length) {
            uint16_t qType = readBE16(&buffer[curr]);
            curr += 4; // qType + qClass
            pkt.dns.queries.push_back({name, qType, ""});
        }
    }

    for (uint16_t i = 0; i < anCount && curr < length; ++i) {
        std::string name = readDnsName(buffer, length, curr);
        if (curr + 10 <= length) {
            uint16_t aType = readBE16(&buffer[curr]);
            curr += 8; // type (2), class (2), ttl (4)
            uint16_t dataLen = readBE16(&buffer[curr]);
            curr += 2;
            std::string val;
            if (aType == 1 && dataLen == 4 && curr + 4 <= length) {
                val = formatIPv4(&buffer[curr]);
            } else {
                val = "<Data>";
            }
            curr += dataLen;
            pkt.dns.answers.push_back({name, aType, val});
        }
    }
}

void ProtocolParser::parseHttp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset) {
    if (offset >= length) return;
    pkt.appProto = AppProto::HTTP;
    pkt.protocolStr = "HTTP";

    std::string text(reinterpret_cast<const char*>(&buffer[offset]), std::min(size_t(2048), length - offset));
    std::stringstream ss(text);
    std::string firstLine;
    if (std::getline(ss, firstLine)) {
        if (!firstLine.empty() && firstLine.back() == '\r') firstLine.pop_back();

        if (firstLine.rfind("HTTP/", 0) == 0) {
            // Response
            pkt.http.isRequest = false;
            std::stringstream lineSs(firstLine);
            lineSs >> pkt.http.version >> pkt.http.statusCode;
            std::getline(lineSs, pkt.http.statusMessage);
            if (!pkt.http.statusMessage.empty() && pkt.http.statusMessage[0] == ' ') {
                pkt.http.statusMessage.erase(0, 1);
            }
        } else {
            // Request
            pkt.http.isRequest = true;
            std::stringstream lineSs(firstLine);
            lineSs >> pkt.http.method >> pkt.http.uri >> pkt.http.version;
        }

        // Parse key headers
        std::string headerLine;
        while (std::getline(ss, headerLine)) {
            if (headerLine == "\r" || headerLine.empty()) break;
            if (headerLine.rfind("Host: ", 0) == 0) {
                pkt.http.host = headerLine.substr(6);
                if (!pkt.http.host.empty() && pkt.http.host.back() == '\r') pkt.http.host.pop_back();
            } else if (headerLine.rfind("Content-Type: ", 0) == 0) {
                pkt.http.contentType = headerLine.substr(14);
                if (!pkt.http.contentType.empty() && pkt.http.contentType.back() == '\r') pkt.http.contentType.pop_back();
            } else if (headerLine.rfind("User-Agent: ", 0) == 0) {
                pkt.http.userAgent = headerLine.substr(12);
                if (!pkt.http.userAgent.empty() && pkt.http.userAgent.back() == '\r') pkt.http.userAgent.pop_back();
            }
        }
    }
}

void ProtocolParser::parseTls(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset) {
    if (offset + 5 > length) {
        pkt.protocolStr = "TLS";
        return;
    }

    const uint8_t* p = &buffer[offset];
    pkt.tls.contentType = p[0];
    pkt.tls.version = readBE16(&p[1]);

    if (pkt.tls.contentType == 22 && offset + 6 < length) {
        // Handshake
        pkt.appProto = AppProto::TLS;
        pkt.protocolStr = "TLS";
        pkt.tls.handshakeType = p[5];
    } else {
        pkt.protocolStr = "TLS";
    }
}

void ProtocolParser::assignColorAndSummary(ParsedPacket& pkt) {
    // Generate Wireshark-like Summary Info & Colors
    if (pkt.netProto == NetProto::ARP) {
        pkt.colorTag = 0xFFD2EAFD; // Pale orange
        if (pkt.arp.opcode == 1) {
            pkt.summaryInfo = "Who has " + pkt.arp.targetIp + "? Tell " + pkt.arp.senderIp;
        } else {
            pkt.summaryInfo = pkt.arp.senderIp + " is at " + pkt.arp.senderMac;
        }
    } else if (pkt.appProto == AppProto::DNS) {
        pkt.colorTag = 0xFFFEE8CC; // Soft Cyan
        if (pkt.dns.isResponse) {
            pkt.summaryInfo = "Standard query response 0x" + std::to_string(pkt.dns.txId);
            if (!pkt.dns.answers.empty()) {
                pkt.summaryInfo += " " + pkt.dns.answers[0].name + " " + pkt.dns.answers[0].value;
            }
        } else {
            pkt.summaryInfo = "Standard query 0x" + std::to_string(pkt.dns.txId);
            if (!pkt.dns.queries.empty()) {
                pkt.summaryInfo += " " + pkt.dns.queries[0].name;
            }
        }
    } else if (pkt.appProto == AppProto::HTTP) {
        pkt.colorTag = 0xFFE0FCE0; // Soft Mint Green
        if (pkt.http.isRequest) {
            pkt.summaryInfo = pkt.http.method + " " + pkt.http.uri + " " + pkt.http.version;
        } else {
            pkt.summaryInfo = "HTTP/1.1 " + std::to_string(pkt.http.statusCode) + " " + pkt.http.statusMessage;
        }
    } else if (pkt.appProto == AppProto::TLS || pkt.protocolStr == "TLS") {
        pkt.colorTag = 0xFFF5E0F0; // Soft Purple
        if (pkt.tls.handshakeType == 1) pkt.summaryInfo = "Client Hello";
        else if (pkt.tls.handshakeType == 2) pkt.summaryInfo = "Server Hello";
        else pkt.summaryInfo = "Application Data / TLS record";
    } else if (pkt.transProto == TransProto::TCP) {
        pkt.colorTag = 0xFFEBEBF5; // Soft Slate
        pkt.summaryInfo = std::to_string(pkt.tcp.srcPort) + " -> " + std::to_string(pkt.tcp.dstPort) + 
                          " " + pkt.tcp.flagsString() + 
                          " Seq=" + std::to_string(pkt.tcp.seqNum) + 
                          " Ack=" + std::to_string(pkt.tcp.ackNum) + 
                          " Win=" + std::to_string(pkt.tcp.windowSize) + 
                          " Len=" + std::to_string(pkt.payloadLength);
    } else if (pkt.transProto == TransProto::UDP) {
        pkt.colorTag = 0xFFF9EFE0; // Soft Blue
        pkt.summaryInfo = std::to_string(pkt.udp.srcPort) + " -> " + std::to_string(pkt.udp.dstPort) + 
                          " Len=" + std::to_string(pkt.udp.length);
    } else if (pkt.transProto == TransProto::ICMP) {
        pkt.colorTag = 0xFFE8E0FC; // Soft Salmon
        pkt.summaryInfo = pkt.icmp.typeDescription();
    } else {
        pkt.colorTag = 0xFFF0F0F0;
        pkt.summaryInfo = "Protocol packet (" + std::to_string(pkt.rawBytes.size()) + " bytes)";
    }
}
