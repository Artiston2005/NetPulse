#pragma once

#include "Packet.h"
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <deque>

enum class CaptureMode {
    SIMULATION,
    LIVE_RAW_SOCKET
};

class PacketCapture {
public:
    using PacketCallback = std::function<void(const uint8_t* data, size_t len, double relTime)>;

    PacketCapture();
    ~PacketCapture();

    bool start(CaptureMode mode, PacketCallback callback);
    void pause();
    void resume();
    void stop();

    bool isRunning() const { return m_running; }
    bool isPaused() const { return m_paused; }
    CaptureMode getMode() const { return m_mode; }

    void setPacketRate(int packetsPerSecond); // Simulation speed
    int getPacketRate() const { return m_packetsPerSec; }

    // Manual Attack / Scenario Injections for Simulation Demo
    void triggerSynFlood();
    void triggerPortScan();
    void triggerPlaintextCreds();
    void triggerDnsTunnel();

    std::vector<std::string> getAvailableInterfaces();

private:
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_paused{false};
    CaptureMode m_mode = CaptureMode::SIMULATION;
    PacketCallback m_callback;
    std::thread m_workerThread;

    int m_packetsPerSec = 5;
    std::chrono::steady_clock::time_point m_startTime;

    // Simulation generation methods
    void simulationLoop();
    void liveSocketLoop();

    std::vector<uint8_t> generateDnsPacket(bool isResponse);
    std::vector<uint8_t> generateTcpHandshakePacket(int step);
    std::vector<uint8_t> generateHttpPacket(bool isRequest, bool withCreds = false);
    std::vector<uint8_t> generateTlsPacket();
    std::vector<uint8_t> generateIcmpPacket(bool isRequest, size_t size = 64);
    std::vector<uint8_t> generateArpPacket(bool isRequest);
    std::vector<uint8_t> generatePortScanPacket(uint16_t port);

    std::mutex m_injectionMutex;
    std::deque<std::vector<uint8_t>> m_injectedPackets;

    uint32_t m_simSeqNum = 10000;
};
