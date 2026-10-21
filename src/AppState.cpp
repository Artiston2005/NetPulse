#include "AppState.h"
#include "ProtocolParser.h"
#include <iomanip>
#include <sstream>

AppState::AppState() {}

AppState::~AppState() {
    captureEngine.stop();
}

void AppState::init() {
    clearAll();
    // Default capture engine starts in simulation mode with 6 packets/sec
    captureEngine.setPacketRate(6);
    captureEngine.start(CaptureMode::SIMULATION, [this](const uint8_t* data, size_t len, double relTime) {
        this->onNewPacket(data, len, relTime);
    });
}

void AppState::clearAll() {
    std::lock_guard<std::mutex> lock(packetsMutex);
    packets.clear();
    filteredIndices.clear();
    selectedPacketIndex = -1;
    filterDirty = true;

    totalBytes = 0;
    tcpCount = 0;
    udpCount = 0;
    icmpCount = 0;
    dnsCount = 0;
    httpCount = 0;
    tlsCount = 0;
    arpCount = 0;
    otherCount = 0;

    topSrcIps.clear();
    topDstIps.clear();
    topPorts.clear();

    throughputHistory.clear();
    anomalyDetector.reset();
}

void AppState::showToast(const std::string& msg, float duration) {
    toastMessage = msg;
    toastTimer = duration;
}

void AppState::update(float dt) {
    appTime += dt;
    secondTimer += dt;

    if (toastTimer > 0.0f) {
        toastTimer -= dt;
        if (toastTimer <= 0.0f) toastMessage.clear();
    }

    if (secondTimer >= 1.0f) {
        currentKbps = (bytesInLastSecond * 8.0f) / 1024.0f; // Kbps
        currentPps = static_cast<float>(packetsInLastSecond);

        RollingStatPoint pt;
        pt.time = appTime;
        pt.kbps = currentKbps;
        pt.pps = currentPps;

        throughputHistory.push_back(pt);
        if (throughputHistory.size() > 60) {
            throughputHistory.pop_front();
        }

        bytesInLastSecond = 0;
        packetsInLastSecond = 0;
        secondTimer = 0.0f;
    }

    if (filterDirty) {
        applyFilter();
    }
}

void AppState::onNewPacket(const uint8_t* data, size_t len, double relTime) {
    std::lock_guard<std::mutex> lock(packetsMutex);

    uint64_t id = packets.size() + 1;
    char timeBuf[32];
    snprintf(timeBuf, sizeof(timeBuf), "+%.4fs", relTime);

    ParsedPacket pkt = ProtocolParser::parse(data, len, id, relTime, timeBuf, LinkType::ETHERNET);

    // Pass through security & anomaly detection
    anomalyDetector.inspectPacket(pkt, relTime);

    totalBytes += len;
    bytesInLastSecond += len;
    packetsInLastSecond++;

    // Protocol metrics
    if (pkt.netProto == NetProto::ARP) arpCount++;
    else if (pkt.appProto == AppProto::DNS) dnsCount++;
    else if (pkt.appProto == AppProto::HTTP) httpCount++;
    else if (pkt.appProto == AppProto::TLS || pkt.protocolStr == "TLS") tlsCount++;
    else if (pkt.transProto == TransProto::TCP) tcpCount++;
    else if (pkt.transProto == TransProto::UDP) udpCount++;
    else if (pkt.transProto == TransProto::ICMP) icmpCount++;
    else otherCount++;

    // Endpoint metrics
    if (!pkt.srcStr.empty()) topSrcIps[pkt.srcStr]++;
    if (!pkt.dstStr.empty()) topDstIps[pkt.dstStr]++;
    if (pkt.transProto == TransProto::TCP) topPorts[pkt.tcp.dstPort]++;
    else if (pkt.transProto == TransProto::UDP) topPorts[pkt.udp.dstPort]++;

    size_t newIdx = packets.size();
    packets.push_back(pkt);

    // If matches current filter, add to filtered list
    if (FilterEngine::matches(pkt, filterQuery)) {
        filteredIndices.push_back(newIdx);
    }
}

void AppState::applyFilter() {
    filterDirty = false;
    filteredIndices.clear();
    for (size_t i = 0; i < packets.size(); ++i) {
        if (FilterEngine::matches(packets[i], filterQuery)) {
            filteredIndices.push_back(i);
        }
    }
}
