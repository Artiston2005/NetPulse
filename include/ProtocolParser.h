#pragma once

#include "Packet.h"
#include <cstdint>
#include <cstddef>

class ProtocolParser {
public:
    static ParsedPacket parse(const uint8_t* buffer, size_t length, uint64_t id, double timestampRel, const std::string& timeStr, LinkType linkType = LinkType::ETHERNET);

private:
    static void parseEthernet(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset);
    static void parseArp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset);
    static void parseIPv4(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset);
    static void parseIPv6(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset);
    static void parseTcp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset);
    static void parseUdp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t& offset);
    static void parseIcmp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset);
    static void parseDns(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset);
    static void parseHttp(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset);
    static void parseTls(const uint8_t* buffer, size_t length, ParsedPacket& pkt, size_t offset);
    
    static std::string formatMac(const uint8_t* bytes);
    static std::string formatIPv4(const uint8_t* bytes);
    static std::string formatIPv6(const uint8_t* bytes);
    static std::string readDnsName(const uint8_t* buffer, size_t length, size_t& offset);
    static void assignColorAndSummary(ParsedPacket& pkt);
};
