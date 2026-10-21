cmake_minimum_required(VERSION 3.20)
project(NetPulse LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/UI
    ${CMAKE_CURRENT_SOURCE_DIR}/external/imgui
    ${CMAKE_CURRENT_SOURCE_DIR}/external/imgui/backends
)

set(IMGUI_SOURCES
    external/imgui/imgui.cpp
    external/imgui/imgui_demo.cpp
    external/imgui/imgui_draw.cpp
    external/imgui/imgui_tables.cpp
    external/imgui/imgui_widgets.cpp
    external/imgui/backends/imgui_impl_glfw.cpp
    external/imgui/backends/imgui_impl_opengl3.cpp
)

set(APP_SOURCES
    src/main.cpp
    src/Packet.cpp
    src/ProtocolParser.cpp
    src/PacketCapture.cpp
    src/PcapManager.cpp
    src/AnomalyDetector.cpp
    src/FilterEngine.cpp
    src/AppState.cpp
)

add_executable(NetPulse ${APP_SOURCES} ${IMGUI_SOURCES})

# Windows libraries
if (WIN32)
    target_link_libraries(NetPulse PRIVATE
        glfw3
        opengl32
        gdi32
        ws2_32
        iphlpapi
    )
else()
    target_link_libraries(NetPulse PRIVATE
        glfw
        GL
        pthread
    )
endif()
