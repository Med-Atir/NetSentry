# 🛡️ NetSentry — Hybrid AI-Powered Network Intrusion Detection System

[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![Qt 6](https://img.shields.io/badge/Qt-6-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://www.qt.io/)
[![ONNX Runtime](https://img.shields.io/badge/ONNX_Runtime-Inference-005CED?style=for-the-badge&logo=onnx&logoColor=white)](https://onnxruntime.ai/)
[![PcapPlusPlus](https://img.shields.io/badge/PcapPlusPlus-Packet_Engine-FF6F00?style=for-the-badge)](https://pcapplusplus.github.io/)
[![SQLite](https://img.shields.io/badge/SQLite-Persistence-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)

**NetSentry** is a high-throughput, native C++17 desktop Network Intrusion Detection System (NIDS) engineered for real-time packet inspection, bidirectional flow telemetry extraction, and dual-stage machine learning threat detection. 

Built from the ground up with **PcapPlusPlus**, **ONNX Runtime**, **Qt 6**, and **SQLite**, NetSentry eliminates Python runtime overhead—processing hundreds of thousands of packets with minimal memory footprint while catching both known attack signatures and zero-day behavioral anomalies.

---

## ✨ Key Highlights

* **⚡ Native C++17 Packet & Flow Engine:** Captures live network interfaces or parses multi-gigabyte offline `.pcap` files at wire speed using `PcapPlusPlus`, aggregating packets by 5-tuple (`SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `Protocol`) with deterministic 1-second flow eviction to keep RAM usage flat.
* **🧠 Two-Stage Hybrid AI Detection:**
  * **Stage 1 — Supervised Signature Classification (`ids_lightgbm.onnx`):** A custom-weighted **LightGBM** classifier trained on **CSE-CIC-IDS2018** that identifies `DoS`, `DDoS`, `BruteForce`, `Web Attack`, and `Botnet_Infiltration` flows with calibrated confidence thresholds.
  * **Stage 2 — Unsupervised Zero-Day Detection (`isolation_forest.onnx`):** An **Isolation Forest** anomaly detector trained exclusively on `log1p`-scaled benign traffic to flag novel, unseen, or mutated threats (`ZERO_DAY`) that bypass signature classifiers.
* **📊 30-Feature Real-Time Telemetry Extraction:** Computes CICFlowMeter-compatible statistical features on the fly—including forward/backward packet rates, inter-arrival time (IAT) distributions, TCP flag counts (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), payload length moments, and initial window sizes.
* **🖥️ Multi-Threaded Qt 6 Command Center:** Decouples background packet capture and ONNX inference from the UI via thread-safe `Qt::QueuedConnection` signals, delivering live telemetry cards, offline PCAP analysis, and filterable alert forensics.
* **🗄️ Persistent SQLite Alert Forensics:** Logs every threat event—timestamp (microsecond precision), 5-tuple metadata, confidence score, anomaly score, attack classification, and severity level—into an indexed SQLite database for historical review.

---

## 🏗️ System Architecture

```text
┌─────────────────────────┐      ┌──────────────────────────────────────────┐
│  Live NIC / PCAP File   │─────▶│       PacketSniffer (PcapPlusPlus)       │
└─────────────────────────┘      │  • Parses L2/L3/L4 headers & TCP flags   │
                                 │  • Extracts PacketMetaData structs       │
                                 └────────────────────┬─────────────────────┘
                                                      │ (Background Thread)
                                                      ▼
                                 ┌──────────────────────────────────────────┐
                                 │        FlowManager (5-Tuple Cache)       │
                                 │  • Bidirectional flow state tracking     │
                                 │  • 1-second sliding window eviction      │
                                 │  • 30-feature vector extraction          │
                                 └────────────────────┬─────────────────────┘
                                                      │
                                                      ▼
                                 ┌──────────────────────────────────────────┐
                                 │      Inference Engine (ONNX Runtime)     │
                                 │  1. LightGBM  ──▶ Known Attack Classes   │
                                 │  2. IsoForest ──▶ Zero-Day Anomalies     │
                                 └────────────────────┬─────────────────────┘
                                                      │
                            ┌─────────────────────────┴─────────────────────────┐
                            ▼ (Qt::QueuedConnection)                            ▼
           ┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
           │     Qt 6 GUI (MainWindow)       │                 │       SQLite DB (alerts)        │
           │  • Live & Offline Dashboards    │◀───────────────▶│  • 11-column forensic schema    │
           │  • Real-Time Alert Table        │                 │  • Microsecond-indexed queries  │
           └─────────────────────────────────┘                 └─────────────────────────────────┘
```

---

## 🔬 Machine Learning Pipeline & Features

NetSentry's detection models were trained and exported offline to **ONNX** (`opset 15+`) for zero-dependency C++ execution:

| Stage | Model | Preprocessing | Target Classes / Output |
| :--- | :--- | :--- | :--- |
| **Supervised** | `LightGBM` (`ids_lightgbm.onnx`) | Raw 30-feature vector | `Benign`, `DoS`, `DDoS`, `BruteForce`, `Web Attack`, `Botnet_Infiltration` |
| **Unsupervised** | `IsolationForest` (`isolation_forest.onnx`) | `log1p(x)` feature scaling | Anomaly score + dynamic threshold (`unsup_metadata.json`) $\rightarrow$ `ZERO_DAY` |

### Extracted Flow Features (30 Dimensions)
* **Flow & Volume Metrics:** Flow duration, total forward/backward packets, total payload bytes, bytes/sec, packets/sec, forward-to-backward packet ratio.
* **Packet Length Statistics:** Min, max, mean, and standard deviation of packet sizes across forward, backward, and combined directions.
* **Inter-Arrival Time (IAT):** Mean, std, max, and min IAT across flow, forward, and backward packet streams.
* **Protocol & TCP State:** `SYN`, `FIN`, `RST`, `PSH`, `ACK`, `URG` flag counters, initial forward/backward TCP window sizes, and active/idle timing bursts.

---

## 🛠️ Tech Stack

* **Core Language:** C++17
* **Packet Capture & Dissection:** PcapPlusPlus (`libpcap` backend)
* **ML Inference Engine:** Microsoft ONNX Runtime (C++ API)
* **Graphical User Interface:** Qt 6 (Qt Widgets, QSS Dark Theme)
* **Database:** SQLite3 via `QtSql`
* **Build System:** CMake & Ninja
* **Model Training (Offline):** Python, LightGBM, Scikit-learn, `onnxmltools`, CSE-CIC-IDS2018

---

## 🚀 Getting Started

### 1. Prerequisites (Linux / Fedora)
Ensure you have a C++17 compiler, CMake, Qt 6 development headers, `libpcap`, **PcapPlusPlus**, and **ONNX Runtime** installed:

```bash
sudo dnf install cmake ninja-build gcc-c++ qt6-qtbase-devel libpcap-devel sqlite-devel
```

*(Make sure `PcapPlusPlus` and `onnxruntime` include/lib paths are configured in `CMakeLists.txt`.)*

### 2. Clone & Build
```bash
git clone https://github.com/Med-Atir/NetSentry.git
cd NetSentry
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
```

### 3. Grant Packet Capture Capabilities
To sniff live network interfaces without running the entire Qt GUI as `root`, grant `CAP_NET_RAW` and `CAP_NET_ADMIN` directly to the compiled binary:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./NetSentry
```

### 4. Run NetSentry
```bash
./NetSentry
```

---

## 🧪 Benchmark & Stress-Test Results

Tested against real-world red-team vs. blue-team traffic (**MACCDC 2012** capture dataset):
* **Throughput:** Processed **400,000+ packets** continuously in a single session with **zero crashes** and near-flat memory usage thanks to deterministic 1-second flow eviction.
* **Detection Volume:** Identified and persisted **17,000+ malicious and anomalous flows** in real time across port sweeps, brute-force campaigns, and malformed protocol bursts.

---

## 📂 Project Structure

```text
NetSentry/
├── CMakeLists.txt              # Build configuration (Qt6, PcapPlusPlus, ONNX Runtime)
├── Database/
│   └── ids                     # SQLite database storing persisted security alerts
├── models/
│   ├── ids_lightgbm.onnx       # Stage-1 supervised multi-class classifier
│   ├── isolation_forest.onnx   # Stage-2 unsupervised zero-day detector
│   └── unsup_metadata.json     # Anomaly thresholds & feature metadata
├── include/                    # Header files (Sniffer, FlowManager, Engine, Controller, DB, UI)
└── src/
    ├── PacketSniffer.cpp       # Live NIC & offline PCAP capture engine
    ├── FlowManager.cpp         # 5-tuple flow tracking & 30-feature extraction
    ├── Engine.cpp              # ONNX Runtime session management & hybrid inference
    ├── Controller.cpp          # Thread coordination & alert pipeline orchestration
    ├── DB.cpp                  # SQLite schema initialization & thread-safe queries
    └── ui/                     # Qt 6 MainWindow, LiveCapture, FileCapture, and Alerts views
```

---

## 🗺️ Roadmap

- [ ] **Batched SQLite Transactions:** Wrap high-volume alert inserts in periodic transactions (`BEGIN` / `COMMIT`) to boost offline PCAP ingestion speed by 10x+.
- [ ] **Score Normalization & UI Visualization:** Map raw Isolation Forest decision scores to an intuitive `0–100%` threat risk gauge alongside live traffic charts.
- [ ] **Active IPS Mode:** Optional inline response hooks (`iptables` / `nftables` drop rules) for high-confidence critical alerts.
- [ ] **Alert Export:** One-click CSV / JSON forensic report export from the Alerts view.

---

## 👤 Author

**Mohammed Atir**  
Cybersecurity Engineering Student (ISSIC) — École des Sciences de l'Information (ESI), Rabat  
LinkedIn: [@Atir-Mohammed](https://www.linkedin.com/in/atir-mohammed-a00a2434b/)

---

## 📄 License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE) file for details.