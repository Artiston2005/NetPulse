#pragma once

#include "AppState.h"
#include "imgui.h"
#include <vector>
#include <algorithm>

class PageAnalytics {
public:
    static void render(AppState& state, float xOffset, float yOffset, float width, float height) {
        ImGui::SetNextWindowPos(ImVec2(xOffset, yOffset));
        ImGui::SetNextWindowSize(ImVec2(width, height));

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                                 ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoCollapse;

        ImGui::Begin("##AnalyticsPage", nullptr, flags);

        ImGui::TextColored(ImVec4(0.0f, 0.8f, 1.0f, 1.0f), "[ REAL-TIME TRAFFIC ANALYTICS & TELEMETRY ]");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 1. KPI Cards Row
        float cardWidth = (width - 48) / 4.0f;
        float cardHeight = 70.0f;

        auto renderKpiCard = [&](const char* title, const std::string& value, ImVec4 accentColor) {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.15f, 0.20f, 1.0f));
            ImGui::BeginChild(title, ImVec2(cardWidth, cardHeight), true);
            ImGui::TextColored(ImVec4(0.6f, 0.65f, 0.7f, 1.0f), "%s", title);
            ImGui::Spacing();
            ImGui::TextColored(accentColor, "%s", value.c_str());
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::SameLine();
        };

        renderKpiCard("TOTAL PACKETS", std::to_string(state.packets.size()), ImVec4(0.0f, 0.8f, 1.0f, 1.0f));
        
        char volStr[32];
        if (state.totalBytes < 1024 * 1024) snprintf(volStr, sizeof(volStr), "%.2f KB", state.totalBytes / 1024.0f);
        else snprintf(volStr, sizeof(volStr), "%.2f MB", state.totalBytes / (1024.0f * 1024.0f));
        renderKpiCard("TOTAL VOLUME", volStr, ImVec4(0.2f, 0.9f, 0.4f, 1.0f));

        char speedStr[32];
        snprintf(speedStr, sizeof(speedStr), "%.1f Kbps / %.0f pps", state.currentKbps, state.currentPps);
        renderKpiCard("LIVE BANDWIDTH", speedStr, ImVec4(1.0f, 0.8f, 0.2f, 1.0f));

        size_t alerts = state.anomalyDetector.getAlerts().size();
        renderKpiCard("THREATS FLAGGED", std::to_string(alerts), alerts > 0 ? ImVec4(1.0f, 0.3f, 0.3f, 1.0f) : ImVec4(0.5f, 0.9f, 0.5f, 1.0f));

        ImGui::NewLine();
        ImGui::Spacing();

        // 2. Real-Time Throughput Graph
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "REAL-TIME BANDWIDTH (Kbps) OVER LAST 60 SECONDS");
        
        std::vector<float> values;
        for (const auto& pt : state.throughputHistory) {
            values.push_back(pt.kbps);
        }
        while (values.size() < 60) {
            values.insert(values.begin(), 0.0f);
        }

        char overlayText[64];
        snprintf(overlayText, sizeof(overlayText), "Current: %.1f Kbps", state.currentKbps);
        ImGui::PushStyleColor(ImGuiCol_PlotLines, ImVec4(0.0f, 0.8f, 1.0f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.12f, 0.14f, 0.18f, 1.0f));
        ImGui::PlotLines("##ThroughputPlot", values.data(), (int)values.size(), 0, overlayText, 0.0f, 100.0f, ImVec2(width - 40, 110));
        ImGui::PopStyleColor(2);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 3. Lower Section: Protocol Distribution (Left) & Top Talkers (Right)
        float colWidth = (width - 48) * 0.48f;
        float bottomHeight = height - 330;

        // Protocol Breakdown
        ImGui::BeginChild("ProtocolBreakdown", ImVec2(colWidth, bottomHeight), true);
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "PROTOCOL DISTRIBUTION");
        ImGui::Separator();
        ImGui::Spacing();

        size_t totalPkts = std::max(size_t(1), state.packets.size());

        auto renderProtoBar = [&](const char* name, size_t count, ImVec4 color) {
            float ratio = (float)count / (float)totalPkts;
            ImGui::Text("%-6s %zu pkts (%.1f%%)", name, count, ratio * 100.0f);
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
            char overlay[32];
            snprintf(overlay, sizeof(overlay), "%zu", count);
            ImGui::ProgressBar(ratio, ImVec2(colWidth - 30, 18), overlay);
            ImGui::PopStyleColor();
            ImGui::Spacing();
        };

        renderProtoBar("TCP",  state.tcpCount,  ImVec4(0.4f, 0.6f, 0.9f, 1.0f));
        renderProtoBar("UDP",  state.udpCount,  ImVec4(0.2f, 0.7f, 0.9f, 1.0f));
        renderProtoBar("DNS",  state.dnsCount,  ImVec4(0.1f, 0.8f, 0.8f, 1.0f));
        renderProtoBar("HTTP", state.httpCount, ImVec4(0.2f, 0.85f, 0.3f, 1.0f));
        renderProtoBar("TLS",  state.tlsCount,  ImVec4(0.8f, 0.4f, 0.9f, 1.0f));
        renderProtoBar("ICMP", state.icmpCount, ImVec4(0.95f, 0.5f, 0.4f, 1.0f));
        renderProtoBar("ARP",  state.arpCount,  ImVec4(0.95f, 0.7f, 0.2f, 1.0f));

        ImGui::EndChild();

        ImGui::SameLine();

        // Top Talkers & Ports
        ImGui::BeginChild("TopTalkers", ImVec2(colWidth, bottomHeight), true);
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "TOP COMMUNICATING ENDPOINTS");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextColored(ImVec4(0.6f, 0.7f, 0.8f, 1.0f), "Top Source IP Addresses:");
        std::vector<std::pair<std::string, size_t>> srcVec(state.topSrcIps.begin(), state.topSrcIps.end());
        std::sort(srcVec.begin(), srcVec.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

        for (size_t i = 0; i < std::min(size_t(5), srcVec.size()); ++i) {
            float pct = (float)srcVec[i].second / (float)totalPkts * 100.0f;
            ImGui::Bullet();
            ImGui::Text("%-16s : %zu pkts (%.1f%%)", srcVec[i].first.c_str(), srcVec[i].second, pct);
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextColored(ImVec4(0.6f, 0.7f, 0.8f, 1.0f), "Top Target Services / Ports:");
        std::vector<std::pair<uint16_t, size_t>> portVec(state.topPorts.begin(), state.topPorts.end());
        std::sort(portVec.begin(), portVec.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

        for (size_t i = 0; i < std::min(size_t(5), portVec.size()); ++i) {
            uint16_t port = portVec[i].first;
            std::string serviceName = "Custom";
            if (port == 80) serviceName = "HTTP";
            else if (port == 443) serviceName = "HTTPS/TLS";
            else if (port == 53) serviceName = "DNS";
            else if (port == 22) serviceName = "SSH";
            else if (port == 21) serviceName = "FTP";
            else if (port == 3306) serviceName = "MySQL";

            ImGui::Bullet();
            ImGui::Text("Port %-5u (%s) : %zu hits", port, serviceName.c_str(), portVec[i].second);
        }

        ImGui::EndChild();

        ImGui::End();
    }
};
