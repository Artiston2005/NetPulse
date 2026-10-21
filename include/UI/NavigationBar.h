#pragma once

#include "AppState.h"
#include "imgui.h"

class NavigationBar {
public:
    static void render(AppState& state, float width, float height) {
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(width, height));

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                                 ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoCollapse |
                                 ImGuiWindowFlags_NoScrollbar;

        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.06f, 0.07f, 0.09f, 1.0f));
        ImGui::Begin("##SidebarNavigation", nullptr, flags);

        // App Brand Header
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.0f, 0.8f, 1.0f, 1.0f), "  [ NETPULSE ]");
        ImGui::TextColored(ImVec4(0.5f, 0.55f, 0.6f, 1.0f), "  Traffic & Packet Suite");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Status pill
        bool isRunning = state.captureEngine.isRunning();
        bool isPaused = state.captureEngine.isPaused();
        if (isRunning && !isPaused) {
            ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.4f, 1.0f), "  * STATUS: CAPTURING");
        } else if (isRunning && isPaused) {
            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "  || STATUS: PAUSED");
        } else {
            ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "  [ ] STATUS: STOPPED");
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        auto renderNavButton = [&](AppNavPage page, const char* label, const char* badge, ImVec4 badgeColor) {
            bool isActive = (state.currentPage == page);
            if (isActive) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.45f, 0.75f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.55f, 0.85f, 1.0f));
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.10f, 0.12f, 0.16f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.16f, 0.20f, 0.28f, 1.0f));
            }

            std::string btnText = std::string(label);
            if (badge && strlen(badge) > 0) {
                btnText += "  (" + std::string(badge) + ")";
            }

            if (ImGui::Button(btnText.c_str(), ImVec2(width - 24, 40))) {
                state.currentPage = page;
            }

            ImGui::PopStyleColor(2);
            ImGui::Spacing();
        };

        // Navigation Items
        std::string pktBadge = std::to_string(state.packets.size());
        renderNavButton(AppNavPage::LIVE_CAPTURE, "1. Live Capture", pktBadge.c_str(), ImVec4(0.0f, 0.75f, 1.0f, 1.0f));

        std::string inspectBadge = (state.selectedPacketIndex >= 0) ? "#" + std::to_string(state.selectedPacketIndex + 1) : "";
        renderNavButton(AppNavPage::PACKET_INSPECTOR, "2. Inspector", inspectBadge.c_str(), ImVec4(0.8f, 0.8f, 0.8f, 1.0f));

        char rateBuf[32];
        snprintf(rateBuf, sizeof(rateBuf), "%.1f k", state.currentKbps);
        renderNavButton(AppNavPage::ANALYTICS, "3. Analytics", rateBuf, ImVec4(0.2f, 0.9f, 0.5f, 1.0f));

        size_t alertCount = state.anomalyDetector.getAlerts().size();
        std::string alertBadge = (alertCount > 0) ? std::to_string(alertCount) : "";
        ImVec4 alertColor = (state.anomalyDetector.getCriticalCount() > 0) ? ImVec4(1.0f, 0.25f, 0.25f, 1.0f) : ImVec4(1.0f, 0.8f, 0.2f, 1.0f);
        renderNavButton(AppNavPage::SECURITY_ALERTS, "4. Security Alerts", alertBadge.c_str(), alertColor);

        renderNavButton(AppNavPage::PCAP_EXPORT, "5. PCAP & Session", "", ImVec4(0.6f, 0.6f, 0.6f, 1.0f));

        // Quick Telemetry in bottom corner of sidebar
        float footerY = height - 160;
        if (footerY > ImGui::GetCursorPosY() + 20) {
            ImGui::SetCursorPosY(footerY);
        }
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.6f, 0.7f, 0.8f, 1.0f), "SESSION TELEMETRY");
        ImGui::Text("Packets: %zu", state.packets.size());
        if (state.totalBytes < 1024 * 1024) {
            ImGui::Text("Volume:  %.2f KB", state.totalBytes / 1024.0f);
        } else {
            ImGui::Text("Volume:  %.2f MB", state.totalBytes / (1024.0f * 1024.0f));
        }
        ImGui::Text("Rate:    %.0f pkts/s", state.currentPps);

        ImGui::End();
        ImGui::PopStyleColor();
    }
};
