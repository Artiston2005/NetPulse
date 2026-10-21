#pragma once

#include "Packet.h"
#include <string>

class FilterEngine {
public:
    static bool matches(const ParsedPacket& pkt, const std::string& query);

private:
    static std::string toLower(const std::string& s);
    static bool matchesCondition(const ParsedPacket& pkt, const std::string& key, const std::string& op, const std::string& val);
};
