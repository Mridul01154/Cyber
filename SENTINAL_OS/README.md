# Network Intrusion Detection and Process Monitoring System

This project is a lightweight Windows-based Intrusion Detection System (IDS) and Process Monitor. It performs real-time network packet sniffing, blacklist-based IP and port monitoring, SYN/UDP flood detection, port scan detection, and suspicious process detection based on name and SHA-256 hash.

## Features

- 🧠 **Sniffer Module (`sniffer.c`)**
  - Captures packets via Npcap
  - Handles IPv4, IPv6, TCP, UDP, and ARP packets
  - Logs traffic, detects SYN/UDP floods, port scans, and blacklisted IPs/ports

- 🚨 **Detection Engine (`detection.c`)**
  - Maintains in-memory hash tables for:
    - IP blacklists
    - Port blacklists
    - Port scan detection
    - SYN and UDP flood detection
  - Supports configuration from `rules.config`
  - Persists newly detected blacklisted entries

- 🔍 **Process Monitor (`proc_monitor.c`)**
  - Enumerates running processes using `ToolHelp32`
  - Detects blacklisted process names and SHA-256 hashes
  - Runs in a background thread

- 📜 **Logging System (`logger.c`)**
  - Thread-safe logging using Windows Critical Sections
  - Logs all alerts and activities to files under `logs/`

## Requirements

- Windows OS (tested on Windows 10)
- [Npcap](https://nmap.org/npcap/) installed
- Visual Studio or MinGW for compilation
- Admin privileges (required for raw packet capture and process access)

## File Structure

- ├── src/
- │ ├── detection.c # Detection logic (blacklists, floods, port scans)
- │ ├── logger.c # Thread-safe logger
- │ ├── proc_monitor.c # Blacklist process and hash detection
- │ └── sniffer.c # Entry point, sniffer, dispatcher
- │
- ├── config/
- │ ├── rules.config # Contains IP, Port blacklists and thresholds
- │ ├── proc_rules.config # List of blacklisted process names
- │ └── bad_hashes.txt # List of malicious file hashes
- │
- ├── logs/ # Generated at runtime for logging
- │
- ├── scripts/
- │ ├── install.sh # Installation script
- │ └── cleanup.sh

## Setup Instructions

1. **Install Npcap**
   - Download and install from: https://nmap.org/npcap/
   - Ensure it’s installed with WinPcap compatibility mode.

2. **Build**
   - Use a C compiler for Windows (e.g., MSVC)
   - Link against `wpcap.lib`, `Packet.lib`, `Ws2_32.lib`, and `Crypt32.lib`
   - Example (MinGW):
     ```
     gcc sniffer.c detection.c proc_monitor.c logger.c -lpcap -lws2_32 -lcrypt32 -o sniffer.exe
     ```

3. **Configure**
   - Create and populate the `config/` folder with:
     - `rules.config`
     - `proc_rules.config`
     - `bad_hashes.txt`

4. **Run**
   - Run the executable with administrative rights
   - Select the interface number as prompted

### 📄 `rules.config`
```ini
BLACKLIST_IP=192.168.1.100           # Block traffic from this IP address
BLACKLIST_PORT=4444                  # Block access to this port
SYN_FLOOD_THRESHOLD=500              # Trigger alert after 500 SYN packets
SYN_FLOOD_WINDOW=10                  # Time window (in seconds) for SYN flood detection
PORT_SCAN_THRESHOLD=10               # Number of unique ports accessed to trigger scan alert
PORT_SCAN_WINDOW=60                  # Time window (in seconds) for port scan detection
UDP_FLOOD_THRESHOLD=500              # Trigger alert after 500 UDP packets
UDP_FLOOD_WINDOW=10                  # Time window (in seconds) for UDP flood detection
ALERT_ON_ARP=1                       # Enable ARP packet logging
```

### 📄 proc_rules.config
```ini
BLACKLIST_IP=192.168.1.100
BLACKLIST_PORT=4444
ALERT_ON_ARP=1
```

### 📄 bad_hashes.txt
```ini
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  # Example SHA-256 of a malicious binary
```

- 🚧 **Future Improvements**
  - 🖥️ GUI Support: Add a graphical interface for real-time monitoring and log viewing
  - 📤 Export Logs: Support JSON or CSV log export for integration with SIEM tools
  - 🔄 Rule Auto-Update: Pull blacklist and threat intel updates from a remote source or server
  - 🐧 Cross-Platform Support: Make compatible with Linux (using libpcap, POSIX APIs)

- 📜 **License**
  - This project is licensed under the MIT License.
  - [🔗 View License](https://github.com/Mridul01154/Cyber/blob/main/EncryptedVault/LICENSE)
 
- 🙋 **Author**
  - Mridul Gharami
  - GitHub: @Mridul01154
