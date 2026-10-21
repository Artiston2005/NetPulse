#pragma once

#include "Packet.h"
#include "PacketCapture.h"
#include "AnomalyDetector.h"
#include "FilterEngine.h"
#include <vector>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <chrono>

enum class AppNavPage {
    LIVE_CAPTURE = 0,
    PACKET_INSPECTOR,
    ANALYTICS,
    SECURITY_ALERTS,
    PCAP_EXPORT
};

struct RollingStatPoint {
    float time;
    float kbps;
    float pps;
};

class AppState {
public:
    AppState();
    ~AppState();

    void init();
    void update(float dt);

    void onNewPacket(const uint8_t* data, size_t len, double relTime);
    void clearAll();

    // Navigation
    AppNavPage currentPage = AppNavPage::LIVE_CAPTURE;

    // Packets storage
    std::mutex packetsMutex;
    std::vector<ParsedPacket> packets;
    std::vector<size_t> filteredIndices;
    int selectedPacketIndex = -1;
    bool filterDirty = true;
    std::string filterQuery;

    bool autoScroll = true;

    // Statistics
    size_t totalBytes = 0;
    size_t tcpCount = 0;
    size_t udpCount = 0;
    size_t icmpCount = 0;
    size_t dnsCount = 0;
    size_t httpCount = 0;
    size_t tlsCount = 0;
    size_t arpCount = 0;
    size_t otherCount = 0;

    std::unordered_map<std::string, size_t> topSrcIps;
    std::unordered_map<std::string, size_t> topDstIps;
    std::unordered_map<uint16_t, size_t> topPorts;

    // Rolling time-series for plots (last 60 seconds)
    std::deque<RollingStatPoint> throughputHistory;
    float currentKbps = 0.0f;
    float currentPps = 0.0f;
    size_t bytesInLastSecond = 0;
    size_t packetsInLastSecond = 0;
    float secondTimer = 0.0f;
    float appTime = 0.0f;

    // Core engines
    PacketCapture captureEngine;
    AnomalyDetector anomalyDetector;

    // Toast notifications
    std::string toastMessage;
    float toastTimer = 0.0f;
    void showToast(const std::string& msg, float duration = 3.0f);

    void applyFilter();
};
