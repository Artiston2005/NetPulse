#pragma once

#include "Packet.h"
#include <vector>
#include <string>
#include <unordered_map>
#include <deque>

enum class AlertSeverity {
    INFO,
    WARNING,
    CRITICAL
};

struct SecurityAlert {
    uint64_t alertId = 0;
    double timestamp = 0.0;
    std::string timestampStr;
    AlertSeverity severity = AlertSeverity::WARNING;
    std::string ruleName;
    std::string description;
    std::string sourceIp;
    std::string targetIp;
    uint64_t packetId = 0;
};

class AnomalyDetector {
public:
    AnomalyDetector();
    void reset();
    void inspectPacket(ParsedPacket& pkt, double currentTime);
    const std::vector<SecurityAlert>& getAlerts() const { return m_alerts; }
    size_t getCriticalCount() const { return m_criticalCount; }
    size_t getWarningCount() const { return m_warningCount; }

private:
    std::vector<SecurityAlert> m_alerts;
    uint64_t m_nextAlertId = 1;
    size_t m_criticalCount = 0;
    size_t m_warningCount = 0;

    // Trackers for port scanning: IP -> deque of (timestamp, dstPort)
    struct PortScanRecord {
        double time;
        uint16_t port;
    };
    std::unordered_map<std::string, std::deque<PortScanRecord>> m_ipPortHistory;

    // Trackers for SYN flood: IP -> deque of timestamp
    std::unordered_map<std::string, std::deque<double>> m_synHistory;

    // Last alert timestamps to throttle repeat spamming
    std::unordered_map<std::string, double> m_lastAlertTime;

    void addAlert(AlertSeverity severity, const std::string& rule, const std::string& desc,
                  const std::string& src, const std::string& dst, uint64_t pktId, double time, const std::string& timeStr);
};
