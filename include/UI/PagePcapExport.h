#pragma once

#include "AppState.h"
#include "PcapManager.h"
#include "imgui.h"

class PagePcapExport {
public:
    static void render(AppState& state, float xOffset, float yOffset, float width, float height) {
        ImGui::SetNextWindowPos(ImVec2(xOffset, yOffset));
        ImGui::SetNextWindowSize(ImVec2(width, height));

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                                 ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoCollapse;

        ImGui::Begin("##PcapExportPage", nullptr, flags);

        ImGui::TextColored(ImVec4(0.0f, 0.8f, 1.0f, 1.0f), "[ PCAP MANAGEMENT & SESSION ARCHIVING ]");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        float cardWidth = (width - 48) * 0.48f;
        float cardHeight = 220.0f;

        // Card 1: Save PCAP
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.11f, 0.13f, 0.18f, 1.0f));
        ImGui::BeginChild("SavePcapBox", ImVec2(cardWidth, cardHeight), true);
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "EXPORT TO STANDARD PCAP (WIRESHARK)");
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextWrapped("Saves all captured packets to a standard .pcap binary file compatible with official Wireshark, tcpdump, and Zeek.");
        ImGui::Spacing();

        static char savePath[256] = "capture_export.pcap";
        ImGui::Text("File Name / Path:");
        ImGui::SetNextItemWidth(cardWidth - 30);
        ImGui::InputText("##SavePath", savePath, sizeof(savePath));
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.55f, 0.35f, 1.0f));
        if (ImGui::Button("Save .PCAP File", ImVec2(160, 32))) {
            std::lock_guard<std::mutex> lock(state.packetsMutex);
            if (PcapManager::saveToPcap(savePath, state.packets)) {
                state.showToast("Successfully exported " + std::to_string(state.packets.size()) + " packets to " + savePath);
            } else {
                state.showToast("Failed to write PCAP file.");
            }
        }
        ImGui::PopStyleColor();

        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::SameLine();

        // Card 2: Load PCAP
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.11f, 0.13f, 0.18f, 1.0f));
        ImGui::BeginChild("LoadPcapBox", ImVec2(cardWidth, cardHeight), true);
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "IMPORT EXISTING PCAP FILE");
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextWrapped("Open and inspect existing packet capture traces recorded from external tools or past NetPulse sessions.");
        ImGui::Spacing();

        static char loadPath[256] = "capture_export.pcap";
        ImGui::Text("File Name / Path:");
        ImGui::SetNextItemWidth(cardWidth - 30);
        ImGui::InputText("##LoadPath", loadPath, sizeof(loadPath));
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.5f, 0.8f, 1.0f));
        if (ImGui::Button("Load & Dissect PCAP", ImVec2(180, 32))) {
            state.captureEngine.pause();
            std::vector<ParsedPacket> loadedPkts;
            if (PcapManager::loadFromPcap(loadPath, loadedPkts)) {
                state.clearAll();
                {
                    std::lock_guard<std::mutex> lock(state.packetsMutex);
                    for (auto& p : loadedPkts) {
                        state.anomalyDetector.inspectPacket(p, p.timestampRel);
                        state.totalBytes += p.rawBytes.size();
                        if (p.netProto == NetProto::ARP) state.arpCount++;
                        else if (p.appProto == AppProto::DNS) state.dnsCount++;
                        else if (p.appProto == AppProto::HTTP) state.httpCount++;
                        else if (p.appProto == AppProto::TLS || p.protocolStr == "TLS") state.tlsCount++;
                        else if (p.transProto == TransProto::TCP) state.tcpCount++;
                        else if (p.transProto == TransProto::UDP) state.udpCount++;
                        else if (p.transProto == TransProto::ICMP) state.icmpCount++;
                        else state.otherCount++;

                        if (!p.srcStr.empty()) state.topSrcIps[p.srcStr]++;
                        if (!p.dstStr.empty()) state.topDstIps[p.dstStr]++;
                        if (p.transProto == TransProto::TCP) state.topPorts[p.tcp.dstPort]++;
                        else if (p.transProto == TransProto::UDP) state.topPorts[p.udp.dstPort]++;

                        state.packets.push_back(p);
                    }
                }
                state.applyFilter();
                state.showToast("Loaded " + std::to_string(loadedPkts.size()) + " packets from PCAP file.");
            } else {
                state.showToast("Error: Could not open or parse PCAP file: " + std::string(loadPath));
            }
        }
        ImGui::PopStyleColor();

        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Card 3: Export CSV
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.11f, 0.13f, 0.18f, 1.0f));
        ImGui::BeginChild("ExportCsvBox", ImVec2(width - 48, 140), true);
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "EXPORT SPREADSHEET (CSV AUDIT REPORT)");
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextWrapped("Generates a structured CSV log with packet IDs, timestamps, IP endpoints, protocol classifications, wire length, and threat detection flags.");
        ImGui::Spacing();

        static char csvPath[256] = "netpulse_audit_report.csv";
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##CsvPath", csvPath, sizeof(csvPath));
        ImGui::SameLine();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.4f, 0.1f, 1.0f));
        if (ImGui::Button("Export CSV", ImVec2(120, 26))) {
            std::lock_guard<std::mutex> lock(state.packetsMutex);
            if (PcapManager::exportToCsv(csvPath, state.packets)) {
                state.showToast("Exported CSV report to " + std::string(csvPath));
            } else {
                state.showToast("Failed to write CSV file.");
            }
        }
        ImGui::PopStyleColor();

        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::End();
    }
};
