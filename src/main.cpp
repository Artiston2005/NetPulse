#include <iostream>
#include <chrono>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

#include "AppState.h"
#include "UI/UITheme.h"
#include "UI/NavigationBar.h"
#include "UI/PageLiveCapture.h"
#include "UI/PageInspector.h"
#include "UI/PageAnalytics.h"
#include "UI/PageSecurity.h"
#include "UI/PagePcapExport.h"

static void glfw_error_callback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}

int main(int argc, char** argv) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return 1;
    }

    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1366, 768, "NetPulse - Network Packet Sniffer & Traffic Analyzer", nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return 1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Apply Cyber Dark Theme
    UITheme::applyDarkCyberTheme();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Initialize Application State
    AppState state;
    state.init();

    auto lastTime = std::chrono::steady_clock::now();

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        auto now = std::chrono::steady_clock::now();
        float dt = std::chrono::duration<float>(now - lastTime).count();
        lastTime = now;

        state.update(dt);

        // Start ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        float fW = static_cast<float>(display_w);
        float fH = static_cast<float>(display_h);

        float navWidth = 230.0f;
        float contentWidth = fW - navWidth;

        // 1. Render Navigation Sidebar
        NavigationBar::render(state, navWidth, fH);

        // 2. Render Active View
        switch (state.currentPage) {
            case AppNavPage::LIVE_CAPTURE:
                PageLiveCapture::render(state, navWidth, 0, contentWidth, fH);
                break;
            case AppNavPage::PACKET_INSPECTOR:
                PageInspector::render(state, navWidth, 0, contentWidth, fH);
                break;
            case AppNavPage::ANALYTICS:
                PageAnalytics::render(state, navWidth, 0, contentWidth, fH);
                break;
            case AppNavPage::SECURITY_ALERTS:
                PageSecurity::render(state, navWidth, 0, contentWidth, fH);
                break;
            case AppNavPage::PCAP_EXPORT:
                PagePcapExport::render(state, navWidth, 0, contentWidth, fH);
                break;
        }

        // 3. Render Floating Toast Notification if present
        if (!state.toastMessage.empty()) {
            ImGui::SetNextWindowPos(ImVec2(fW - 380, fH - 60));
            ImGui::SetNextWindowSize(ImVec2(360, 45));
            ImGuiWindowFlags toastFlags = ImGuiWindowFlags_NoTitleBar |
                                         ImGuiWindowFlags_NoResize |
                                         ImGuiWindowFlags_NoMove |
                                         ImGuiWindowFlags_NoScrollbar;
            ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.45f, 0.75f, 0.95f));
            if (ImGui::Begin("##ToastWindow", nullptr, toastFlags)) {
                ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "INFO: %s", state.toastMessage.c_str());
                ImGui::End();
            }
            ImGui::PopStyleColor();
        }

        // Rendering
        ImGui::Render();
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.07f, 0.08f, 0.10f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
