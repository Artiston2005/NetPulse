#pragma once

#include "AppState.h"
#include "imgui.h"
#include <string>

class PageLiveCapture {
public:
    static void render(AppState& state, float xOffset, float yOffset, float width, float height) {
        ImGui::SetNextWindowPos(ImVec2(xOffset, yOffset));
        ImGui::SetNextWindowSize(ImVec2(width, height));

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                                 ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoCollapse;

        ImGui::Begin("##LiveCapturePage", nullptr, flags);

        // 1. Control Toolbar
        bool isRunning = state.captureEngine.isRunning();
        bool isPaused = state.captureEngine.isPaused();

        if (!isRunning || isPaused) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.55f, 0.25f, 1.0f));
            if (ImGui::Button(isPaused ? "Resume Capture" : "Start Capture", ImVec2(120, 32))) {
                if (isPaused) {
                    state.captureEngine.resume();
                } else {
                    state.captureEngine.start(state.captureEngine.getMode(), [&state](const uint8_t* data, size_t len, double relTime) {
                        state.onNewPacket(data, len, relTime);
                    });
                }
            }
            ImGui::PopStyleColor();
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.85f, 0.55f, 0.10f, 1.0f));
            if (ImGui::Button("Pause Capture", ImVec2(120, 32))) {
                state.captureEngine.pause();
            }
            ImGui::PopStyleColor();
        }

        ImGui::SameLine();
        if (ImGui::Button("Stop", ImVec2(70, 32))) {
            state.captureEngine.stop();
        }

        ImGui::SameLine();
        if (ImGui::Button("Clear All", ImVec2(80, 32))) {
            state.clearAll();
        }

        ImGui::SameLine();
        ImGui::SetNextItemWidth(130);
        int simSpeed = state.captureEngine.getPacketRate();
        if (ImGui::SliderInt("Speed (pkts/s)", &simSpeed, 1, 30)) {
            state.captureEngine.setPacketRate(simSpeed);
        }

        ImGui::SameLine();
        ImGui::Checkbox("Auto-Scroll", &state.autoScroll);

        ImGui::SameLine(ImGui::GetWindowWidth() - 390);
        ImGui::TextColored(ImVec4(0.7f, 0.75f, 0.8f, 1.0f), "Inject Threat:");
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.40f, 0.18f, 0.22f, 1.0f));
        if (ImGui::Button("SYN Flood")) {
            state.captureEngine.triggerSynFlood();
            state.showToast("Injected TCP SYN Flood scenario (20 packets)");
        }
        ImGui::SameLine();
        if (ImGui::Button("Port Scan")) {
            state.captureEngine.triggerPortScan();
            state.showToast("Injected Reconnaissance Port Scan (15 ports)");
        }
        ImGui::SameLine();
        if (ImGui::Button("Cred Leak")) {
            state.captureEngine.triggerPlaintextCreds();
            state.showToast("Injected Plaintext HTTP Credential Leak");
        }
        ImGui::SameLine();
        if (ImGui::Button("DNS Tunnel")) {
            state.captureEngine.triggerDnsTunnel();
            state.showToast("Injected Oversized DNS Tunneling query");
        }
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // 2. Wireshark-style Filter Bar
        ImGui::TextColored(ImVec4(0.0f, 0.75f, 1.0f, 1.0f), "Filter:");
        ImGui::SameLine();
        static char filterBuf[256] = "";
        ImGui::SetNextItemWidth(340);
        if (ImGui::InputTextWithHint("##DisplayFilter", "e.g. tcp, udp, dns, ip.src == 192.168.1.105, alert", filterBuf, sizeof(filterBuf))) {
            state.filterQuery = filterBuf;
            state.filterDirty = true;
        }

        ImGui::SameLine();
        if (ImGui::Button("Apply")) {
            state.filterQuery = filterBuf;
            state.filterDirty = true;
        }

        ImGui::SameLine();
        if (ImGui::Button("Reset Filter")) {
            filterBuf[0] = '\0';
            state.filterQuery = "";
            state.filterDirty = true;
        }

        // Quick Preset Filter Buttons
        ImGui::SameLine();
        auto quickFilter = [&](const char* label, const char* rule) {
            if (ImGui::SmallButton(label)) {
                snprintf(filterBuf, sizeof(filterBuf), "%s", rule);
                state.filterQuery = filterBuf;
                state.filterDirty = true;
            }
            ImGui::SameLine();
        };

        quickFilter("TCP", "tcp");
        quickFilter("UDP", "udp");
        quickFilter("DNS", "dns");
        quickFilter("HTTP", "http");
        quickFilter("TLS", "tls");
        quickFilter("ICMP", "icmp");
        quickFilter("ARP", "arp");
        quickFilter("Threats", "alert");

        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.6f, 0.65f, 0.7f, 1.0f), "Showing %zu / %zu",
                           state.filteredIndices.size(), state.packets.size());

        if (state.selectedPacketIndex >= 0) {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.5f, 0.8f, 1.0f));
            std::string inspectBtnText = "Inspect Selected (#" + std::to_string(state.selectedPacketIndex + 1) + ")";
            if (ImGui::Button(inspectBtnText.c_str())) {
                state.currentPage = AppNavPage::PACKET_INSPECTOR;
            }
            ImGui::PopStyleColor();
        }

        ImGui::Spacing();

        // 3. Main Packet Table
        ImGuiTableFlags tableFlags = ImGuiTableFlags_RowBg |
                                     ImGuiTableFlags_Borders |
                                     ImGuiTableFlags_Resizable |
                                     ImGuiTableFlags_ScrollY |
                                     ImGuiTableFlags_Reorderable |
                                     ImGuiTableFlags_Hideable;

        float tableHeight = height - 120;
        if (ImGui::BeginTable("PacketGridTable", 7, tableFlags, ImVec2(0, tableHeight))) {
            ImGui::TableSetupColumn("No.", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Destination", ImGuiTableColumnFlags_WidthFixed, 150.0f);
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            std::lock_guard<std::mutex> lock(state.packetsMutex);

            for (size_t rowIdx = 0; rowIdx < state.filteredIndices.size(); ++rowIdx) {
                size_t pktIdx = state.filteredIndices[rowIdx];
                const auto& pkt = state.packets[pktIdx];

                ImGui::TableNextRow();

                bool isSelected = (state.selectedPacketIndex == (int)pktIdx);

                // Row Color Tint based on protocol or alert
                if (pkt.isSuspicious) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, 0x44222288); // Red tint
                } else if (pkt.appProto == AppProto::HTTP) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, 0x2244AA44); // Green tint
                } else if (pkt.appProto == AppProto::DNS) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, 0x22888822); // Cyan tint
                } else if (pkt.appProto == AppProto::TLS) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, 0x22882288); // Purple tint
                } else if (pkt.netProto == NetProto::ARP) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, 0x222288AA); // Orange tint
                }

                // Column 0: No. (Selectable row click)
                ImGui::TableSetColumnIndex(0);
                std::string idStr = std::to_string(pkt.id);
                if (ImGui::Selectable(idStr.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    state.selectedPacketIndex = (int)pktIdx;
                    if (ImGui::IsMouseDoubleClicked(0)) {
                        state.currentPage = AppNavPage::PACKET_INSPECTOR;
                    }
                }

                // Column 1: Time
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(pkt.timestampStr.c_str());

                // Column 2: Source
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(pkt.srcStr.c_str());

                // Column 3: Destination
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(pkt.dstStr.c_str());

                // Column 4: Protocol
                ImGui::TableSetColumnIndex(4);
                if (pkt.isSuspicious) {
                    ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "! %s", pkt.protocolStr.c_str());
                } else {
                    ImGui::TextUnformatted(pkt.protocolStr.c_str());
                }

                // Column 5: Length
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%zu", pkt.rawBytes.size());

                // Column 6: Info
                ImGui::TableSetColumnIndex(6);
                ImGui::TextUnformatted(pkt.summaryInfo.c_str());
            }

            if (state.autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                ImGui::SetScrollHereY(1.0f);
            }

            ImGui::EndTable();
        }

        ImGui::End();
    }
};
