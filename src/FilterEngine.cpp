#include "FilterEngine.h"
#include <algorithm>
#include <cctype>
#include <sstream>

std::string FilterEngine::toLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

bool FilterEngine::matches(const ParsedPacket& pkt, const std::string& query) {
    std::string q = toLower(query);
    // Trim leading/trailing whitespace
    q.erase(0, q.find_first_not_of(" \t\r\n"));
    q.erase(q.find_last_not_of(" \t\r\n") + 1);

    if (q.empty()) return true;

    // Check simple protocol keywords
    if (q == "tcp") return pkt.transProto == TransProto::TCP;
    if (q == "udp") return pkt.transProto == TransProto::UDP;
    if (q == "icmp") return pkt.transProto == TransProto::ICMP;
    if (q == "arp") return pkt.netProto == NetProto::ARP;
    if (q == "ipv4" || q == "ip") return pkt.netProto == NetProto::IPV4;
    if (q == "ipv6") return pkt.netProto == NetProto::IPV6;
    if (q == "dns") return pkt.appProto == AppProto::DNS;
    if (q == "http") return pkt.appProto == AppProto::HTTP;
    if (q == "tls") return pkt.appProto == AppProto::TLS || pkt.protocolStr == "TLS";
    if (q == "alert" || q == "suspicious") return pkt.isSuspicious;

    // Key == Value check
    size_t eqPos = q.find("==");
    if (eqPos != std::string::npos) {
        std::string key = q.substr(0, eqPos);
        std::string val = q.substr(eqPos + 2);
        // Trim
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        val.erase(0, val.find_first_not_of(" \t"));
        val.erase(val.find_last_not_of(" \t") + 1);
        return matchesCondition(pkt, key, "==", val);
    }

    size_t neqPos = q.find("!=");
    if (neqPos != std::string::npos) {
        std::string key = q.substr(0, neqPos);
        std::string val = q.substr(neqPos + 2);
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        val.erase(0, val.find_first_not_of(" \t"));
        val.erase(val.find_last_not_of(" \t") + 1);
        return matchesCondition(pkt, key, "!=", val);
    }

    // Fallback: substring search across all summary, protocol, endpoints, and reasons
    std::string sSrc = toLower(pkt.srcStr);
    std::string sDst = toLower(pkt.dstStr);
    std::string sProto = toLower(pkt.protocolStr);
    std::string sInfo = toLower(pkt.summaryInfo);
    std::string sReason = toLower(pkt.suspiciousReason);

    return (sSrc.find(q) != std::string::npos ||
            sDst.find(q) != std::string::npos ||
            sProto.find(q) != std::string::npos ||
            sInfo.find(q) != std::string::npos ||
            sReason.find(q) != std::string::npos);
}

bool FilterEngine::matchesCondition(const ParsedPacket& pkt, const std::string& key, const std::string& op, const std::string& val) {
    bool isEq = (op == "==");

    if (key == "ip.src") {
        return (pkt.srcStr == val) == isEq;
    }
    if (key == "ip.dst") {
        return (pkt.dstStr == val) == isEq;
    }
    if (key == "ip.addr") {
        return (pkt.srcStr == val || pkt.dstStr == val) == isEq;
    }
    if (key == "tcp.port" || key == "udp.port" || key == "port") {
        try {
            int port = std::stoi(val);
            bool match = false;
            if (pkt.transProto == TransProto::TCP) {
                match = (pkt.tcp.srcPort == port || pkt.tcp.dstPort == port);
            } else if (pkt.transProto == TransProto::UDP) {
                match = (pkt.udp.srcPort == port || pkt.udp.dstPort == port);
            }
            return match == isEq;
        } catch (...) {
            return false;
        }
    }
    if (key == "http.response.code" || key == "http.code") {
        try {
            int code = std::stoi(val);
            return (pkt.http.statusCode == code) == isEq;
        } catch (...) {
            return false;
        }
    }
    if (key == "http.request.method" || key == "http.method") {
        return (toLower(pkt.http.method) == val) == isEq;
    }
    if (key == "dns.qry.name" || key == "dns.name") {
        for (const auto& q : pkt.dns.queries) {
            if (toLower(q.name).find(val) != std::string::npos) return isEq;
        }
        return !isEq;
    }

    return false;
}
