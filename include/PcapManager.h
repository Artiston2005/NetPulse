#pragma once

#include "Packet.h"
#include <string>
#include <vector>

class PcapManager {
public:
    static bool saveToPcap(const std::string& filePath, const std::vector<ParsedPacket>& packets);
    static bool loadFromPcap(const std::string& filePath, std::vector<ParsedPacket>& outPackets);
    static bool exportToCsv(const std::string& filePath, const std::vector<ParsedPacket>& packets);
};
