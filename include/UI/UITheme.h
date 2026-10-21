#pragma once

#include "imgui.h"

class UITheme {
public:
    static void applyDarkCyberTheme() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        // Base window styling
        style.WindowRounding = 8.0f;
        style.ChildRounding = 6.0f;
        style.FrameRounding = 5.0f;
        style.PopupRounding = 6.0f;
        style.ScrollbarRounding = 8.0f;
        style.GrabRounding = 4.0f;
        style.TabRounding = 6.0f;

        style.WindowPadding = ImVec2(12, 12);
        style.FramePadding = ImVec2(8, 5);
        style.ItemSpacing = ImVec2(8, 8);
        style.ItemInnerSpacing = ImVec2(6, 6);
        style.IndentSpacing = 20.0f;
        style.ScrollbarSize = 12.0f;

        // Modern Cyber Dark Theme Colors
        colors[ImGuiCol_Text]                  = ImVec4(0.92f, 0.94f, 0.96f, 1.00f);
        colors[ImGuiCol_TextDisabled]          = ImVec4(0.45f, 0.50f, 0.55f, 1.00f);
        colors[ImGuiCol_WindowBg]              = ImVec4(0.08f, 0.10f, 0.13f, 1.00f);
        colors[ImGuiCol_ChildBg]               = ImVec4(0.10f, 0.12f, 0.16f, 1.00f);
        colors[ImGuiCol_PopupBg]               = ImVec4(0.12f, 0.14f, 0.18f, 0.98f);
        colors[ImGuiCol_Border]                = ImVec4(0.18f, 0.22f, 0.28f, 0.80f);
        colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        colors[ImGuiCol_FrameBg]               = ImVec4(0.14f, 0.17f, 0.22f, 1.00f);
        colors[ImGuiCol_FrameBgHovered]        = ImVec4(0.20f, 0.25f, 0.32f, 1.00f);
        colors[ImGuiCol_FrameBgActive]         = ImVec4(0.24f, 0.30f, 0.38f, 1.00f);
        colors[ImGuiCol_TitleBg]               = ImVec4(0.07f, 0.09f, 0.11f, 1.00f);
        colors[ImGuiCol_TitleBgActive]         = ImVec4(0.12f, 0.15f, 0.20f, 1.00f);
        colors[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.06f, 0.07f, 0.09f, 1.00f);
        colors[ImGuiCol_MenuBarBg]             = ImVec4(0.10f, 0.12f, 0.15f, 1.00f);
        colors[ImGuiCol_ScrollbarBg]           = ImVec4(0.08f, 0.10f, 0.13f, 0.60f);
        colors[ImGuiCol_ScrollbarGrab]         = ImVec4(0.22f, 0.26f, 0.33f, 1.00f);
        colors[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.30f, 0.36f, 0.45f, 1.00f);
        colors[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.00f, 0.55f, 0.85f, 1.00f);
        colors[ImGuiCol_CheckMark]             = ImVec4(0.00f, 0.75f, 1.00f, 1.00f);
        colors[ImGuiCol_SliderGrab]            = ImVec4(0.00f, 0.65f, 0.95f, 1.00f);
        colors[ImGuiCol_SliderGrabActive]      = ImVec4(0.00f, 0.85f, 1.00f, 1.00f);
        colors[ImGuiCol_Button]                = ImVec4(0.16f, 0.21f, 0.28f, 1.00f);
        colors[ImGuiCol_ButtonHovered]         = ImVec4(0.22f, 0.30f, 0.40f, 1.00f);
        colors[ImGuiCol_ButtonActive]          = ImVec4(0.00f, 0.55f, 0.85f, 1.00f);
        colors[ImGuiCol_Header]                = ImVec4(0.16f, 0.22f, 0.30f, 1.00f);
        colors[ImGuiCol_HeaderHovered]         = ImVec4(0.24f, 0.32f, 0.42f, 1.00f);
        colors[ImGuiCol_HeaderActive]          = ImVec4(0.00f, 0.55f, 0.85f, 1.00f);
        colors[ImGuiCol_Separator]             = ImVec4(0.18f, 0.22f, 0.28f, 1.00f);
        colors[ImGuiCol_SeparatorHovered]      = ImVec4(0.00f, 0.65f, 0.95f, 1.00f);
        colors[ImGuiCol_SeparatorActive]       = ImVec4(0.00f, 0.85f, 1.00f, 1.00f);
        colors[ImGuiCol_ResizeGrip]            = ImVec4(0.20f, 0.25f, 0.32f, 0.50f);
        colors[ImGuiCol_ResizeGripHovered]     = ImVec4(0.00f, 0.65f, 0.95f, 0.70f);
        colors[ImGuiCol_ResizeGripActive]      = ImVec4(0.00f, 0.85f, 1.00f, 1.00f);
        colors[ImGuiCol_Tab]                   = ImVec4(0.12f, 0.15f, 0.20f, 1.00f);
        colors[ImGuiCol_TabHovered]            = ImVec4(0.22f, 0.28f, 0.36f, 1.00f);
        colors[ImGuiCol_TabSelected]           = ImVec4(0.16f, 0.22f, 0.30f, 1.00f);
        colors[ImGuiCol_TabDimmed]             = ImVec4(0.10f, 0.12f, 0.16f, 1.00f);
        colors[ImGuiCol_TabDimmedSelected]     = ImVec4(0.14f, 0.18f, 0.24f, 1.00f);
        colors[ImGuiCol_TableHeaderBg]         = ImVec4(0.14f, 0.17f, 0.22f, 1.00f);
        colors[ImGuiCol_TableBorderStrong]     = ImVec4(0.22f, 0.26f, 0.33f, 1.00f);
        colors[ImGuiCol_TableBorderLight]      = ImVec4(0.15f, 0.18f, 0.23f, 1.00f);
        colors[ImGuiCol_TableRowBg]            = ImVec4(0.09f, 0.11f, 0.14f, 1.00f);
        colors[ImGuiCol_TableRowBgAlt]         = ImVec4(0.11f, 0.13f, 0.17f, 1.00f);
    }
};
