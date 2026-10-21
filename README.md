# NetPulse - Network Packet Sniffer & Traffic Analyzer (Wireshark-Lite)

**NetPulse** is a high-performance, multi-page desktop application written in modern C++ (C++17) for capturing, dissecting, analyzing, and detecting security threats in real-time network traffic.

Built with a custom **Cyber Dark GUI** (Dear ImGui + GLFW/OpenGL3), it provides a professional, interactive experience with zero external runtime installations required.

---

## Key Features & Multi-Page Architecture

NetPulse features a modern desktop navigation sidebar switching between 5 full-screen pages:

### 1. 📡 Live Capture Hub
* **Real-Time Packet Grid:** Live-streaming data table with Wireshark-standard protocol color coding:
  * 🌐 **DNS:** Soft Cyan
  * 📄 **HTTP:** Mint Green
  * 🔒 **TLS:** Lavender Purple
  * ⚙️ **TCP:** Slate Blue
  * 📦 **UDP:** Light Steel Blue
  * 🏓 **ICMP:** Salmon / Pink
  * 🔗 **ARP:** Pastel Orange
  * 🚨 **Security Alerts:** Bright Crimson
* **Controls:** `Start`, `Pause`, `Resume`, `Stop`, and `Clear All`.
* **Adjustable Speed:** Slider to vary packet throughput from $1$ to $30\text{ pkts/sec}$.
* **Display Filter Engine:** Real-time query evaluation supporting:
  * Simple protocol filters: `tcp`, `udp`, `dns`, `http`, `tls`, `icmp`, `arp`, `alert`
  * Exact condition matching: `ip.src == 192.168.1.105`, `ip.dst == 8.8.8.8`, `port == 80`, `http.code == 200`
  * Free-text substring matching across all headers and payloads.
* **Attack / Threat Injection Triggers (1-Click Demo):**
  * `[+ SYN Flood]`: Injects 20 rapid TCP SYN packets from spoofed IPs.
  * `[+ Port Scan]`: Injects reconnaissance probes across 15 target ports.
  * `[+ Cred Leak]`: Injects an unencrypted HTTP POST containing plaintext passwords.
  * `[+ DNS Tunnel]`: Injects an oversized base64 encoded DNS query.

---

### 2. 🔍 Deep Packet Inspector & Hex Viewer
* **Wireshark-Style Protocol Tree Hierarchy:**
  * **Frame Layer:** Wire length, capture length, epoch delta, packet index.
  * **Ethernet II:** Source/Destination MAC addresses, EtherType.
  * **Address Resolution Protocol (ARP):** Hardware/Protocol type, Sender/Target MAC & IP.
  * **IPv4 / IPv6:** Version, IHL, Total Length, ID, DF/MF flags, TTL, Checksums, Source/Destination IPs.
  * **TCP / UDP:** Source/Destination ports, Sequence/Ack numbers, Data Offset, TCP Flags (`SYN, ACK, FIN, RST, PSH, URG`), Window size.
  * **Application Dissection:**
    * **HTTP:** Request methods (`GET`, `POST`), URI, Status Code (`200 OK`, `404`), Headers (`Host`, `User-Agent`), Payload previews.
    * **DNS:** Transaction ID, Query flags, Question count, Answer RRs with resolved IP mappings.
    * **TLS:** Record Type, Handshake Type (`Client Hello`, `Server Hello`).
* **Synchronized Hex & ASCII Dump:**
  * Monospace 16-byte aligned hex view with byte offsets (`0000`, `0010`, ...), hex octets, and printable ASCII text characters.

---

### 3. 📊 Traffic Analytics & Visualizer
* **KPI Telemetry Cards:** Total Packets, Total Volume (KB/MB), Live Bandwidth (Kbps), Threat Counts.
* **Real-Time Bandwidth Graph:** Continuous 60-second rolling line plot showing network throughput fluctuations.
* **Protocol Distribution:** Live animated progress bars showing the exact percentage breakdown of active traffic.
* **Top Communicating Endpoints:** Dynamic frequency tables ranking the most active Source IP addresses, Destination IP addresses, and Target Ports (HTTP 80, HTTPS 443, DNS 53, SSH 22, etc.).

---

### 4. 🛡️ Security & Anomaly Detection Engine (IDS)
Rule-based heuristic intrusion detection engine analyzing packets in real time:
* **Rule #1: TCP SYN Flood Detection (T1498)** — Flags when an IP address sends $>15$ SYN packets within 3 seconds without completing handshakes.
* **Rule #2: Reconnaissance Port Scanning (T1046)** — Detects when a host probes $\ge 8$ distinct destination ports within 4 seconds.
* **Rule #3: Plaintext Credential Exposure (T1552.001)** — Scans unencrypted HTTP traffic for passwords (`password=`, `passwd=`, or Basic Auth headers).
* **Rule #4: DNS Tunneling / Exfiltration (T1071.004)** — Flags abnormally long DNS query strings ($>45$ characters) commonly used for covert data exfiltration.
* **Interactive Alert Jump:** Clicking any alert automatically navigates to that exact packet in the Deep Inspector!

---

### 5. 💾 PCAP & Session Archiving
* **100% Wireshark Compatible:** Exports captures directly to standard binary `.pcap` files (Global Header: `0xa1b2c3d4`, Version 2.4, LinkType 1 Ethernet). Saved files can be opened in official Wireshark without conversion!
* **PCAP Import:** Load external or past `.pcap` capture files directly into NetPulse for offline forensics.
* **CSV Audit Export:** Generates structured CSV logs for spreadsheet reporting and academic evaluation.

---

## Project Structure

```
AOA_Project/
├── build.bat                   # 1-Click compiler script (CMake + Ninja)
├── run.bat                     # 1-Click launch script
├── CMakeLists.txt              # Build definition
├── build/                      # Compiled binaries and runtime DLLs
│   └── NetPulse.exe
├── include/
│   ├── Packet.h                # Protocol headers, packet models, and tree builders
│   ├── ProtocolParser.h        # Dissection and parsing logic
│   ├── PacketCapture.h         # Live socket + high-fidelity simulation engine
│   ├── PcapManager.h           # PCAP read/write and CSV generation
│   ├── AnomalyDetector.h       # Intrusion detection and heuristic rules
│   ├── FilterEngine.h          # Wireshark-like query filter parser
│   ├── AppState.h              # Central state machine, ring buffers, and telemetry
│   └── UI/
│       ├── UITheme.h           # Cyber dark theme color palette
│       ├── NavigationBar.h     # Multi-page sidebar router
│       ├── PageLiveCapture.h   # Page 1: Live packet table & filters
│       ├── PageInspector.h     # Page 2: Protocol hierarchy tree & Hex dump
│       ├── PageAnalytics.h     # Page 3: Real-time throughput plot & protocol bars
│       ├── PageSecurity.h      # Page 4: Intrusion detection alerts & IDS rules
│       └── PagePcapExport.h    # Page 5: Save/Load PCAP & CSV export
├── src/
│   ├── main.cpp                # App entrypoint, GLFW window, and render loop
│   ├── Packet.cpp
│   ├── ProtocolParser.cpp
│   ├── PacketCapture.cpp
│   ├── PcapManager.cpp
│   ├── AnomalyDetector.cpp
│   ├── FilterEngine.cpp
│   └── AppState.cpp
└── external/
    └── imgui/                  # Dear ImGui library
```

---

## Quick Start (How to Run)

### Method 1: Instant Launch (Pre-compiled)
Simply double-click:
```bat
run.bat
```
or run `build\NetPulse.exe`.

### Method 2: Rebuilding from Source
To recompile from scratch using MSYS2 / MinGW:
```bat
build.bat
```
or via command line:
```bash
cmake -B build -G "Ninja" -DCMAKE_CXX_COMPILER="C:/msys64/ucrt64/bin/g++.exe" -DCMAKE_C_COMPILER="C:/msys64/ucrt64/bin/gcc.exe" -DCMAKE_MAKE_PROGRAM="C:/msys64/ucrt64/bin/ninja.exe"
cmake --build build
```

---

## Technologies Used
* **C++17** (Standard Template Library, Multithreading, Sockets)
* **Dear ImGui** (Immediate-mode GUI with custom Dark Theme)
* **GLFW 3 & OpenGL 3** (High-FPS hardware-accelerated rendering)
* **Standard PCAP Format** (RFC / libpcap 2.4 specification)
