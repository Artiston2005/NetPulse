#include "AnomalyDetector.h"
#include <algorithm>
#include <cctype>

AnomalyDetector::AnomalyDetector() {
    reset();
}

void AnomalyDetector::reset() {
    m_alerts.clear();
    m_nextAlertId = 1;
    m_criticalCount = 0;
    m_warningCount = 0;
    m_ipPortHistory.clear();
    m_synHistory.clear();
    m_lastAlertTime.clear();
}

void AnomalyDetector::addAlert(AlertSeverity severity, const std::string& rule, const std::string& desc,
                              const std::string& src, const std::string& dst, uint64_t pktId, double time, const std::string& timeStr) {
    // Throttle alert if triggered within last 1.5s for same rule and src
    std::string key = rule + "_" + src;
    if (m_lastAlertTime.find(key) != m_lastAlertTime.end()) {
        if (time - m_lastAlertTime[key] < 1.5) return;
    }
    m_lastAlertTime[key] = time;

    SecurityAlert alert;
    alert.alertId = m_nextAlertId++;
    alert.timestamp = time;
    alert.timestampStr = timeStr;
    alert.severity = severity;
    alert.ruleName = rule;
    alert.description = desc;
    alert.sourceIp = src;
    alert.targetIp = dst;
    alert.packetId = pktId;

    if (severity == AlertSeverity::CRITICAL) m_criticalCount++;
    else if (severity == AlertSeverity::WARNING) m_warningCount++;

    m_alerts.push_back(alert);
}

void AnomalyDetector::inspectPacket(ParsedPacket& pkt, double currentTime) {
    std::string src = pkt.srcStr;
    std::string dst = pkt.dstStr;

    // 1. TCP SYN Flood Detection
    if (pkt.transProto == TransProto::TCP && pkt.tcp.flagSYN && !pkt.tcp.flagACK) {
        auto& history = m_synHistory[src];
        history.push_back(currentTime);

        // Keep last 3 seconds
        while (!history.empty() && currentTime - history.front() > 3.0) {
            history.pop_front();
        }

        if (history.size() > 15) {
            pkt.isSuspicious = true;
            pkt.suspiciousReason = "Possible TCP SYN Flood (" + std::to_string(history.size()) + " SYNs in 3s)";
            pkt.colorTag = 0xFF9999FF; // Soft Crimson
            addAlert(AlertSeverity::CRITICAL, "TCP SYN Flood",
                     "Rapid SYN packets (" + std::to_string(history.size()) + " in 3s) from source",
                     src, dst, pkt.id, currentTime, pkt.timestampStr);
        }
    }

    // 2. Port Scan Detection (multiple distinct ports probed in short time)
    if (pkt.transProto == TransProto::TCP || pkt.transProto == TransProto::UDP) {
        uint16_t dPort = (pkt.transProto == TransProto::TCP) ? pkt.tcp.dstPort : pkt.udp.dstPort;
        auto& pHistory = m_ipPortHistory[src];
        pHistory.push_back({currentTime, dPort});

        while (!pHistory.empty() && currentTime - pHistory.front().time > 4.0) {
            pHistory.pop_front();
        }

        // Count unique ports
        std::vector<uint16_t> uniquePorts;
        for (const auto& item : pHistory) {
            if (std::find(uniquePorts.begin(), uniquePorts.end(), item.port) == uniquePorts.end()) {
                uniquePorts.push_back(item.port);
            }
        }

        if (uniquePorts.size() >= 8) {
            pkt.isSuspicious = true;
            pkt.suspiciousReason = "Port Scan Detected (" + std::to_string(uniquePorts.size()) + " ports probed)";
            pkt.colorTag = 0xFF9999FF;
            addAlert(AlertSeverity::WARNING, "Port Scanning Activity",
                     "Host probed " + std::to_string(uniquePorts.size()) + " distinct ports in 4s",
                     src, dst, pkt.id, currentTime, pkt.timestampStr);
        }
    }

    // 3. Cleartext Credentials / Passwords in unencrypted HTTP
    if (pkt.appProto == AppProto::HTTP && pkt.http.isRequest) {
        std::string payload(reinterpret_cast<const char*>(pkt.rawBytes.data() + pkt.payloadOffset),
                            std::min(size_t(1024), pkt.payloadLength));
        
        std::string lowerPayload = payload;
        std::transform(lowerPayload.begin(), lowerPayload.end(), lowerPayload.begin(), ::tolower);

        if (lowerPayload.find("password=") != std::string::npos ||
            lowerPayload.find("passwd=") != std::string::npos ||
            lowerPayload.find("authorization: basic") != std::string::npos) {
            pkt.isSuspicious = true;
            pkt.suspiciousReason = "Unencrypted Sensitive Credentials Transmitted";
            pkt.colorTag = 0xFF8888FF;
            addAlert(AlertSeverity::CRITICAL, "Cleartext Credential Exposure",
                     "Plaintext password or HTTP Basic Auth header observed in cleartext HTTP traffic",
                     src, dst, pkt.id, currentTime, pkt.timestampStr);
        }
    }

    // 4. DNS Tunneling / Oversized DNS Query
    if (pkt.appProto == AppProto::DNS && !pkt.dns.queries.empty()) {
        for (const auto& q : pkt.dns.queries) {
            if (q.name.length() > 45) {
                pkt.isSuspicious = true;
                pkt.suspiciousReason = "Oversized DNS Query (Possible DNS Tunneling: " + std::to_string(q.name.length()) + " chars)";
                pkt.colorTag = 0xFF88A0FF;
                addAlert(AlertSeverity::WARNING, "Suspected DNS Tunneling",
                         "Abnormally long DNS query name (" + q.name.substr(0, 30) + "...) with high entropy",
                         src, dst, pkt.id, currentTime, pkt.timestampStr);
                break;
            }
        }
    }

    // 5. ICMP Ping of Death / Large ICMP
    if (pkt.transProto == TransProto::ICMP && pkt.rawBytes.size() > 800) {
        pkt.isSuspicious = true;
        pkt.suspiciousReason = "Oversized ICMP packet (" + std::to_string(pkt.rawBytes.size()) + " bytes)";
        addAlert(AlertSeverity::WARNING, "Oversized ICMP Frame",
                 "Unusual ICMP packet length exceeding 800 bytes",
                 src, dst, pkt.id, currentTime, pkt.timestampStr);
    }
}
