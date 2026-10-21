#pragma once

#include "AppState.h"
#include "imgui.h"
#include <iomanip>
#include <sstream>
#include <cctype>

class PageInspector {
public:
    static void render(AppState& state, float xOffset, float yOffset, float width, float height) {
        ImGui::SetNextWindowPos(ImVec2(xOffset, yOffset));
        ImGui::SetNextWindowSize(ImVec2(width, height));

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
                                 ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoMove |
                                 ImGuiWindowFlags_NoCollapse;

        ImGui::Begin("##PacketInspectorPage", nullptr, flags);

        // Header controls
        ImGui::TextColored(ImVec4(0.0f, 0.8f, 1.0f, 1.0f), "[ DEEP PACKET DISSECTOR & HEX INSPECTOR ]");
        ImGui::SameLine();

        size_t total = state.packets.size();
        if (state.selectedPacketIndex < 0 && total > 0) {
            state.selectedPacketIndex = 0;
        }

        if (state.selectedPacketIndex >= 0 && state.selectedPacketIndex < (int)total) {
            ImGui::SameLine(width - 450);
            if (ImGui::Button("< Prev Packet") && state.selectedPacketIndex > 0) {
                state.selectedPacketIndex--;
            }
            ImGui::SameLine();
            ImGui::Text("Packet #%d of %zu", state.selectedPacketIndex + 1, total);
            ImGui::SameLine();
            if (ImGui::Button("Next Packet >") && state.selectedPacketIndex < (int)total - 1) {
                state.selectedPacketIndex++;
            }
            ImGui::SameLine();
            if (ImGui::Button("Back to Capture")) {
                state.currentPage = AppNavPage::LIVE_CAPTURE;
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (state.selectedPacketIndex < 0 || state.selectedPacketIndex >= (int)total) {
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "No packets captured yet. Start capture or load a PCAP session.");
            ImGui::End();
            return;
        }

        const ParsedPacket& pkt = state.packets[state.selectedPacketIndex];

        // Security Alert Banner if packet is suspicious
        if (pkt.isSuspicious) {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.35f, 0.10f, 0.12f, 1.0f));
            ImGui::BeginChild("SuspiciousBanner", ImVec2(0, 36), true);
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "  [!] SECURITY WARNING: %s", pkt.suspiciousReason.c_str());
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::Spacing();
        }

        // Split View: Top is Protocol Hierarchy Tree, Bottom is Hex Dump
        float topHalfHeight = (height - 130) * 0.52f;
        float bottomHalfHeight = (height - 130) * 0.45f;

        // --- TOP PANE: PROTOCOL TREE ---
        ImGui::BeginChild("ProtocolTreePane", ImVec2(0, topHalfHeight), true);
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "PROTOCOL LAYERS & DISSECTION");
        ImGui::Separator();
        ImGui::Spacing();

        auto tree = pkt.getDissectionTree();
        for (size_t i = 0; i < tree.size(); ++i) {
            const auto& node = tree[i];
            ImGuiTreeNodeFlags nodeFlags = ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_OpenOnArrow;

            if (ImGui::TreeNodeEx((void*)(intptr_t)i, nodeFlags, "%s", node.title.c_str())) {
                for (const auto& field : node.fields) {
                    ImGui::Bullet();
                    ImGui::TextColored(ImVec4(0.7f, 0.75f, 0.8f, 1.0f), "%s: ", field.label.c_str());
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "%s", field.value.c_str());
                }
                ImGui::TreePop();
            }
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // --- BOTTOM PANE: HEX & ASCII DUMP ---
        ImGui::BeginChild("HexDumpPane", ImVec2(0, bottomHalfHeight), true);
        ImGui::TextColored(ImVec4(0.2f, 0.85f, 0.95f, 1.0f), "RAW FRAME BYTES (HEX & ASCII DUMP) - %zu Bytes", pkt.rawBytes.size());
        ImGui::Separator();
        ImGui::Spacing();

        const auto& bytes = pkt.rawBytes;
        for (size_t row = 0; row < bytes.size(); row += 16) {
            // Offset (0000)
            std::stringstream ssOffset;
            ssOffset << std::hex << std::setw(4) << std::setfill('0') << row << "  ";
            ImGui::TextColored(ImVec4(0.45f, 0.55f, 0.65f, 1.0f), "%s", ssOffset.str().c_str());
            ImGui::SameLine();

            // Hex Bytes (00 11 22 ...)
            std::stringstream ssHex;
            for (size_t col = 0; col < 16; ++col) {
                if (col == 8) ssHex << " ";
                if (row + col < bytes.size()) {
                    ssHex << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[row + col] << " ";
                } else {
                    ssHex << "   ";
                }
            }
            ImGui::TextColored(ImVec4(0.85f, 0.88f, 0.92f, 1.0f), "%s", ssHex.str().c_str());
            ImGui::SameLine();

            // ASCII printable chars
            std::string asciiStr = " |";
            for (size_t col = 0; col < 16; ++col) {
                if (row + col < bytes.size()) {
                    uint8_t b = bytes[row + col];
                    asciiStr += (std::isprint(b) ? char(b) : '.');
                } else {
                    asciiStr += " ";
                }
            }
            asciiStr += "|";
            ImGui::TextColored(ImVec4(0.55f, 0.85f, 0.65f, 1.0f), "%s", asciiStr.c_str());
        }

        ImGui::EndChild();

        ImGui::End();
    }
};
