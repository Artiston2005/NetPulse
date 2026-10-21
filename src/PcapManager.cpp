#include "PcapManager.h"
#include "ProtocolParser.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <chrono>

#pragma pack(push, 1)
struct PcapGlobalHdr {
    uint32_t magic_number;  // 0xa1b2c3d4
    uint16_t version_major; // 2
    uint16_t version_minor; // 4
    int32_t  thiszone;      // GMT to local correction
    uint32_t sigfigs;       // accuracy of timestamps
    uint32_t snaplen;       // max length of captured packets, in octets
    uint32_t network;       // data link type (1 = Ethernet)
};

struct PcapPktHdr {
    uint32_t ts_sec;   // timestamp seconds
    uint32_t ts_usec;  // timestamp microseconds
    uint32_t incl_len; // number of octets of packet saved in file
    uint32_t orig_len; // actual length of packet
};
#pragma pack(pop)

static uint32_t swap32(uint32_t val) {
    return ((val & 0xFF000000) >> 24) |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x000000FF) << 24);
}

static uint16_t swap16(uint16_t val) {
    return ((val & 0xFF00) >> 8) | ((val & 0x00FF) << 8);
}

bool PcapManager::saveToPcap(const std::string& filePath, const std::vector<ParsedPacket>& packets) {
    std::ofstream out(filePath, std::ios::binary);
    if (!out.is_open()) return false;

    PcapGlobalHdr gh;
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1; // LINKTYPE_ETHERNET

    out.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

    for (const auto& pkt : packets) {
        PcapPktHdr ph;
        uint32_t sec = static_cast<uint32_t>(pkt.timestampRel);
        uint32_t usec = static_cast<uint32_t>((pkt.timestampRel - sec) * 1000000.0);
        ph.ts_sec = sec;
        ph.ts_usec = usec;
        ph.incl_len = static_cast<uint32_t>(pkt.rawBytes.size());
        ph.orig_len = static_cast<uint32_t>(pkt.rawBytes.size());

        out.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
        if (!pkt.rawBytes.empty()) {
            out.write(reinterpret_cast<const char*>(pkt.rawBytes.data()), pkt.rawBytes.size());
        }
    }

    return true;
}

bool PcapManager::loadFromPcap(const std::string& filePath, std::vector<ParsedPacket>& outPackets) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in.is_open()) return false;

    PcapGlobalHdr gh;
    in.read(reinterpret_cast<char*>(&gh), sizeof(gh));
    if (!in) return false;

    bool needsSwap = false;
    if (gh.magic_number == 0xd4c3b2a1) {
        needsSwap = true;
    } else if (gh.magic_number != 0xa1b2c3d4) {
        return false; // Invalid PCAP magic
    }

    outPackets.clear();
    uint64_t nextId = 1;
    double firstTimestamp = -1.0;

    std::vector<uint8_t> buffer;

    while (in) {
        PcapPktHdr ph;
        in.read(reinterpret_cast<char*>(&ph), sizeof(ph));
        if (!in || in.gcount() < (std::streamsize)sizeof(ph)) break;

        if (needsSwap) {
            ph.ts_sec = swap32(ph.ts_sec);
            ph.ts_usec = swap32(ph.ts_usec);
            ph.incl_len = swap32(ph.incl_len);
            ph.orig_len = swap32(ph.orig_len);
        }

        if (ph.incl_len > 65535) break; // Sanity check

        buffer.resize(ph.incl_len);
        in.read(reinterpret_cast<char*>(buffer.data()), ph.incl_len);
        if (in.gcount() < (std::streamsize)ph.incl_len) break;

        double pktTime = ph.ts_sec + (ph.ts_usec / 1000000.0);
        if (firstTimestamp < 0.0) firstTimestamp = pktTime;
        double relTime = pktTime - firstTimestamp;

        char timeBuf[32];
        snprintf(timeBuf, sizeof(timeBuf), "+%.4fs", relTime);

        ParsedPacket pkt = ProtocolParser::parse(buffer.data(), buffer.size(), nextId++, relTime, timeBuf, LinkType::ETHERNET);
        outPackets.push_back(pkt);
    }

    return !outPackets.empty();
}

bool PcapManager::exportToCsv(const std::string& filePath, const std::vector<ParsedPacket>& packets) {
    std::ofstream out(filePath);
    if (!out.is_open()) return false;

    out << "No.,Time,Source,Destination,Protocol,Length,Info,Suspicious\n";
    for (const auto& pkt : packets) {
        out << pkt.id << ","
            << "\"" << pkt.timestampStr << "\","
            << "\"" << pkt.srcStr << "\","
            << "\"" << pkt.dstStr << "\","
            << "\"" << pkt.protocolStr << "\","
            << pkt.rawBytes.size() << ","
            << "\"" << pkt.summaryInfo << "\","
            << (pkt.isSuspicious ? "YES" : "NO") << "\n";
    }

    return true;
}
