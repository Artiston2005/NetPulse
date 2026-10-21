#pragma once

#include "AppState.h"
#include "imgui.h"

class PageSecurity {
public:
    static void render(AppState& state, float xOffset, float yOffset, float width, float height) {
        ImGui::SetNextWindowPos(ImVec2(xOffset, yOffset));
        ImGui::SetNextWindowSize(ImVec2(width, height));

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                                 ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoCollapse;

        ImGui::Begin("##SecurityPage", nullptr, flags);

        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "[ INTRUSION DETECTION & SECURITY ANOMALY ENGINE ]");
        ImGui::SameLine();
        ImGui::SetCursorPosX(width - 200);
        if (ImGui::Button("Clear All Alerts", ImVec2(160, 26))) {
            state.anomalyDetector.reset();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 1. Alert Summary Badges
        size_t totalAlerts = state.anomalyDetector.getAlerts().size();
        size_t criticals = state.anomalyDetector.getCriticalCount();
        size_t warnings = state.anomalyDetector.getWarningCount();

        ImGui::TextColored(ImVec4(0.8f, 0.85f, 0.9f, 1.0f), "Heuristic Detection Status: ");
        ImGui::SameLine();
        if (criticals > 0) {
            ImGui::TextColored(ImVec4(1.0f, 0.25f, 0.25f, 1.0f), "[!] %zu CRITICAL THREATS", criticals);
        } else {
            ImGui::TextColored(ImVec4(0.3f, 0.9f, 0.4f, 1.0f), "[OK] No Critical Threats");
        }
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), " |  %zu Warnings", warnings);
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.7f, 0.8f, 1.0f), " |  Total Events: %zu", totalAlerts);

        ImGui::Spacing();

        // 2. Alerts Table
        float tableHeight = (height - 240);
        ImGuiTableFlags tableFlags = ImGuiTableFlags_RowBg |
                                     ImGuiTableFlags_Borders |
                                     ImGuiTableFlags_Resizable |
                                     ImGuiTableFlags_ScrollY;

        if (ImGui::BeginTable("AlertsGrid", 7, tableFlags, ImVec2(0, tableHeight))) {
            ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed, 45.0f);
            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 85.0f);
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("Rule / Attack Type", ImGuiTableColumnFlags_WidthFixed, 180.0f);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("Details & Evidence", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            const auto& alerts = state.anomalyDetector.getAlerts();
            for (int i = (int)alerts.size() - 1; i >= 0; --i) {
                const auto& a = alerts[i];
                ImGui::TableNextRow();

                // Col 0: ID
                ImGui::TableSetColumnIndex(0);
                std::string idStr = std::to_string(a.alertId);
                if (ImGui::Selectable(idStr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    // Jump to that packet in inspector
                    if (a.packetId > 0 && a.packetId <= state.packets.size()) {
                        state.selectedPacketIndex = (int)(a.packetId - 1);
                        state.currentPage = AppNavPage::PACKET_INSPECTOR;
                    }
                }

                // Col 1: Time
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(a.timestampStr.c_str());

                // Col 2: Severity
                ImGui::TableSetColumnIndex(2);
                if (a.severity == AlertSeverity::CRITICAL) {
                    ImGui::TextColored(ImVec4(1.0f, 0.25f, 0.25f, 1.0f), "[CRITICAL]");
                } else {
                    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "[WARNING]");
                }

                // Col 3: Rule
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(a.ruleName.c_str());

                // Col 4: Source
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(a.sourceIp.c_str());

                // Col 5: Target
                ImGui::TableSetColumnIndex(5);
                ImGui::TextUnformatted(a.targetIp.c_str());

                // Col 6: Description
                ImGui::TableSetColumnIndex(6);
                ImGui::TextUnformatted(a.description.c_str());
            }

            ImGui::EndTable();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 3. Security Heuristic Engine Rules Documentation
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "ACTIVE INTRUSION DETECTION SYSTEM (IDS) RULES:");
        ImGui::Bullet(); ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.9f, 1.0f), "Rule #1 (SYN Flood): Detects >15 TCP SYN packets in 3s without established handshakes.");
        ImGui::Bullet(); ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.9f, 1.0f), "Rule #2 (Port Scan): Detects probes across 8 or more unique destination ports in <4s.");
        ImGui::Bullet(); ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.9f, 1.0f), "Rule #3 (Credential Leak): Inspects unencrypted HTTP payloads for plaintext passwords and Basic Auth.");
        ImGui::Bullet(); ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.9f, 1.0f), "Rule #4 (DNS Tunneling): Detects oversized (>45 char) DNS queries often used for C2 data exfiltration.");

        ImGui::End();
    }
};
