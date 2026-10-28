# 🛡️ SentinelAI — Real-Time Network Monitoring, ML Validation, and Incident Response Platform

[![Python Version](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Streamlit-1.44+-FF4B4B.svg)](https://streamlit.io/)
[![Cloud API](https://img.shields.io/badge/FastAPI-Production%20Ready-009688.svg)](https://fastapi.tiangolo.com/)
[![Testing](https://img.shields.io/badge/Pytest-119%20Passed-brightgreen.svg)](https://pytest.org/)
[![TShark](https://img.shields.io/badge/TShark-4.6.x%20(Npcap)-1E88E5.svg)](https://www.wireshark.org/)
[![ML Pipeline](https://img.shields.io/badge/scikit--learn-Dual%20ML%20Pipelines-F7931E.svg)](https://scikit-learn.org/)
[![Message Broker](https://img.shields.io/badge/Redis-Streams%20Buffer-DC382D.svg)](https://redis.io/)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20%2B%20SQLite-336791.svg)](https://www.postgresql.org/)
[![AI Engine](https://img.shields.io/badge/Google%20Gemini-Threat%20Reasoning-4285F4.svg)](https://ai.google.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**SentinelAI** is an enterprise-grade, AI-assisted cybersecurity platform that detects suspicious network activity, validates machine learning models against label leakage and synthetic artifacts, explains threats in clear English, and recommends safe, non-disruptive response actions.

---

## 🏛️ System Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                                      WINDOWS HOST ENVIRONMENT                                     |
|                                                                                                   |
|  +----------------------------------+        +-------------------------------------------------+  |
|  |   Wireshark / Npcap (Hardware)   |        |           Offline PCAP / PCAPNG Replay          |  |
|  |    e.g. Wi-Fi / Ethernet / Loop  |        |      (Tagged with is_replay=True flag)          |  |
|  +-----------------+----------------+        +------------------------+------------------------+  |
|                    |                                                  |                           |
|                    +------------------------+-------------------------+                           |
|                                             |                                                     |
|                                             v                                                     |
|                           +-----------------------------------+                                   |
|                           |   Windows Supervised Collector    |                                   |
|                           |  (src/collector/tshark_collector) |                                   |
|                           |  - Bidirectional Flow Aggregation |                                   |
|                           |  - 27 Flow Feature Extraction     |                                   |
|                           |  - Health JSON & Error Recovery   |                                   |
|                           +-----------------+-----------------+                                   |
+---------------------------------------------|-----------------------------------------------------+
                                              | Authenticated HTTPS / REST (X-Agent-Secret)
                                              v
+---------------------------------------------------------------------------------------------------+
|                                  DOCKER CONTAINERIZED BACKEND                                     |
|                                                                                                   |
|                      +---------------------------------------------+                              |
|                      |             FastAPI Backend                 |                              |
|                      |  - /api/pcap/live-stream & /api/agent       |                              |
|                      |  - /health & /ready probes                  |                              |
|                      |  - WebSocket (/ws/alerts, /ws/events)       |                              |
|                      +----------------------+----------------------+                              |
|                                             |                                                     |
|                                             v                                                     |
|                      +---------------------------------------------+                              |
|                      |         Redis Streams Event Buffer          |                              |
|                      |           (Stream: 'sentinel:events')       |                              |
|                      +----------------------+----------------------+                              |
|                                             |                                                     |
|                                             v                                                     |
|                      +---------------------------------------------+                              |
|                      |      Detection & Flow Aggregation Worker    |                              |
|                      |      (src/workers/detection_worker.py)      |                              |
|                      |                                             |                              |
|                      |   Tier 1: Deterministic Heuristic Engine    |                              |
|                      |   Tier 2: Unsupervised Network Isolation    |                              |
|                      |   Tier 3: Supervised Random Forest Threat   |                              |
|                      |   Tier 4: Idempotent Deduplication Cache    |                              |
|                      +----------------------+----------------------+                              |
|                                             |                                                     |
|                         +-------------------+-------------------+                                 |
|                         |                                       |                                 |
|                         v                                       v                                 |
|         +-------------------------------+       +-------------------------------+                 |
|         |    PostgreSQL Relational DB   |       |       Redis Alert Stream      |                 |
|         |   (Audit trails & incidents)  |       |       'sentinel:alerts'       |                 |
|         +---------------+---------------+       +---------------+---------------+                 |
|                         |                                       |                                 |
|                         +-------------------+-------------------+                                 |
|                                             |                                                     |
|                                             v                                                     |
|                      +---------------------------------------------+                              |
|                      |          Streamlit SOC Dashboard            |                              |
|                      |  - Live TShark / Replay / Demo Indicators   |                              |
|                      |  - Real-Time Flow & Traffic Rate Charts     |                              |
|                      |  - Transparent Alert Forensic Explanations  |                              |
|                      |  - Safe Simulated Response Controls         |                              |
|                      +---------------------------------------------+                              |
+---------------------------------------------------------------------------------------------------+
```

---

## 🔍 Forensic Dataset Audit & Bias Discovery

The synthetic dataset `data/advanced_cybersecurity_data.csv` was audited using `src/ml/audit_dataset.py`.

### Verified Dataset Metrics
- **Total Records:** 10,000 rows
- **Total Columns:** 8 (`Timestamp`, `IP_Address`, `Request_Type`, `Status_Code`, `Anomaly_Flag`, `User_Agent`, `Session_ID`, `Location`)
- **Missing Values:** 0
- **Duplicate Rows:** 0
- **Target Distribution (`Anomaly_Flag`):**
  - Normal (0): 9,510 records (95.10%)
  - Anomaly (1): 490 records (4.90%)
  - Imbalance Ratio: 19.41 : 1

### Critical Forensic Discoveries & Label Leakage Analysis
1. **The "North Korea" Shortcut:**
   - There are exactly 10 records with `Location = 'North Korea'`.
   - **All 10 records (100.0%) are labeled anomalous (`Anomaly_Flag = 1`)**.
   - *Implication:* If `Location` is included as an ML feature, any tree model creates a trivial geographic shortcut rule (`if Location == 'North Korea' -> Anomaly`). This produces catastrophic false positives on regional traffic while failing on attackers originating from any other country.
2. **IP Address Cardinality:**
   - Exactly 9,952 unique IP addresses out of 10,000 rows.
   - Only a single IP (`15.6.62.53`) appears more than once (49 times: 47 normal, 2 anomalous).
   - *Implication:* Direct IP addresses must not be used as raw categorical features to prevent memory-memorization over-fitting.
3. **Monotonic Timestamps:**
   - Timestamps are synthetic increments of exactly 60 seconds (`2023-01-01 00:00:00` to `2023-01-07 22:39:00`).
4. **Weak Feature Correlation:**
   - Categorical HTTP attributes (`Request_Type`, `Status_Code`, `User_Agent`) all have uniform anomaly rates between 3.7% and 5.8%, resulting in weak predictive baseline power (ROC-AUC ~0.55), proving that web-log verbs alone cannot substitute for packet-level flow telemetry.

---

## 🤖 Strict Model Separation: Web-Log vs Network Anomaly

SentinelAI enforces a strict architectural boundary between **Application Web-Log Models** and **Packet Network-Flow Models**:

| Property | Web-Log Baseline Model | Network-Flow Intrusion Model |
|---|---|---|
| **Pipeline Script** | `src/ml/train_baseline.py` | `src/ml/train_network_model.py` |
| **Input Telemetry** | HTTP Application Logs (L7) | Bidirectional Flow Metadata (L3/L4) |
| **Training Features** | `Request_Type`, `Status_Code`, `User_Agent` | 27 Packet & Flow features (bytes/s, IAT, TCP flags) |
| **Excluded Features** | `IP_Address`, `Session_ID`, `Timestamp`, `Location` | Raw payloads, machine IDs |
| **Splitting Strategy** | `GroupShuffleSplit` on `Session_ID` (zero leakage) | Time & scenario split (Browsing, Scan, Flood, Brute) |
| **Model Architectures** | Logistic Regression, Decision Tree, Random Forest | Unsupervised Isolation Forest + Random Forest |
| **Artifact Path** | `artifacts/web_log_model.joblib` | `artifacts/network_anomaly_isolation_forest.joblib` |
| **Metadata File** | `artifacts/web_log_model_metadata.json` | `artifacts/network_model_metadata.json` |

---

## 🦈 Windows Live TShark Collector & PCAP Replay

The capture agent runs natively on the Windows host machine using the installed Wireshark/Npcap runtime.

### TShark Verification Commands (PowerShell)
```powershell
# 1. Verify TShark is installed and accessible
& "C:\Program Files\Wireshark\tshark.exe" --version

# 2. List all network interfaces recognized by Npcap
python src/collector/tshark_collector.py --list-interfaces
```

### Running Live Packet Capture on Windows
```powershell
# Capture on Wi-Fi adapter and batch flows to SentinelAI API every 3 seconds
python src/collector/tshark_collector.py --interface "Wi-Fi" --interval 3.0 --batch-size 25
```

### Replaying an Offline PCAP/PCAPNG File
```powershell
# Replay an authorized PCAP capture file into the pipeline
python src/collector/tshark_collector.py --replay-pcap data/test_replay.pcap
```
> All replayed events are automatically tagged with `is_replay=True` and `source="pcap_replay"` so they appear with a distinct badge on the dashboard.

---

## 📊 Engineered Network Features (27 Features)

See complete documentation in [docs/network_features.md](file:///c:/Users/Asus/Downloads/cybersync/CYBERplus/docs/network_features.md).

1. **Volume & Duration:** `total_packets`, `total_bytes`, `duration`, `packets_per_sec`, `bytes_per_sec`
2. **Port Role Intelligence:** `src_port`, `dst_port`, `is_privileged_port`, `is_admin_port`, `is_ephemeral_src`
3. **Protocol Representation:** `protocol_tcp`, `protocol_udp`, `protocol_icmp`, `protocol_other`
4. **TCP Flag Ratios & Counts:** `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ratio`, `rst_ratio`
5. **Payload Characteristics:** `mean_packet_length`, `std_packet_length`
6. **Inter-Arrival Timing (IAT):** `flow_iat_mean`, `flow_iat_std`
7. **Behavioral Diversity & Heuristics:** `unique_dst_ports_src`, `flow_frequency_src`, `failed_conn_indicator`

---

## 🛡️ Safe Defensive Response Orchestration

SentinelAI operates strictly under a **Defense-in-Depth, Zero Autonomous Disruption** model:
- **Allowlist Protection:** Gateway (`192.168.1.1`), Loopback (`127.0.0.1`), DNS (`8.8.8.8`), and broadcast IPs cannot be blocked.
- **Human-in-the-Loop:** All disruptive actions (e.g. rate-limiting, blocking) require explicit operator confirmation.
- **Dry-Run by Default:** All recommendations operate in simulation mode unless explicitly approved with a documented audit justification.
- **Recommended Actions:**
  1. *Investigate Source Host:* Check endpoint inventory, past detections, and anomalous processes.
  2. *Review Service Exposure:* Audit listening ports on target servers.
  3. *Temporary Rate Limiting:* Simulated traffic shaping at reverse proxy.
  4. *Administrator Review:* Flag incident for senior security architect review.

---

## 🐳 Docker Deployment Guide

### Multi-Stage Architecture
- `base`: Shared Debian slim runtime with pinned dependencies and non-root user `sentinel`.
- `api`: FastAPI cloud backend listening on port 8000.
- `dashboard`: Streamlit dashboard listening on port 8501.
- `agent`: Synthetic telemetry collector container.
- `worker`: Redis Streams detection and aggregation background worker.
- `redis`: Redis 7 alpine message broker.
- `db`: PostgreSQL 16 persistence database.

### Running with Docker Compose (PowerShell)
```powershell
# 1. Start all containers in background
docker compose up -d

# 2. Check service health
docker compose ps

# 3. View detection worker logs
docker compose logs -f worker
```

---

## ⚡ Quick-Start Step-by-Step (Windows PowerShell)

```powershell
# Step 1: Install Python Dependencies
pip install -r requirements-dev.txt

# Step 2: Audit the Dataset
python src/ml/audit_dataset.py --dataset data/advanced_cybersecurity_data.csv --output reports

# Step 3: Train Web-Log Baseline Models
python src/ml/train_baseline.py --dataset data/advanced_cybersecurity_data.csv

# Step 4: Generate Synthetic Network Flows
python src/ml/generate_network_data.py --output data/synthetic_network_flows.csv

# Step 5: Train Network Anomaly Models
python src/ml/train_network_model.py --dataset data/synthetic_network_flows.csv

# Step 6: Run Full Automated Test Suite (119 Tests)
python -m pytest tests/

# Step 7: Start the Streamlit Dashboard Locally
streamlit run app.py
```

---

## 🧪 Acceptance Criteria & Verification Scenarios

| Scenario | Description | Verification Command | Status |
|---|---|---|---|
| **A. Docker Health** | API and Dashboard pass container health checks | `docker compose ps` | ✅ Verified |
| **B. Windows Collector** | TShark captures live flows from active host NIC | `python src/collector/tshark_collector.py -i "Wi-Fi"` | ✅ Verified |
| **C. PCAP Replay** | Replays offline capture tagged with `is_replay=True` | `python src/collector/tshark_collector.py --replay-pcap data/test_replay.pcap` | ✅ Verified |
| **D. Network Flow ML** | Isolation Forest & Random Forest produce anomaly scores | `python -m pytest tests/test_network_ml_models.py` | ✅ Verified |
| **E. Web-Log Baseline** | Session group split prevents data leakage across partitions | `python -m pytest tests/test_web_log_ml.py` | ✅ Verified |
| **F. Dashboard Updates** | Streamlit displays live collector health, telemetry source, & alerts | `streamlit run app.py` | ✅ Verified |
| **G. Resilient Queue** | Worker falls back to in-memory queue when Redis is offline | `python -m pytest tests/test_redis_detection_worker.py` | ✅ Verified |
| **H. Safe Response** | Disruption remains simulated until explicit admin approval | `python -m pytest tests/test_safe_response.py` | ✅ Verified |

---

## 📄 Educational and Compliance Disclaimer
SentinelAI is developed strictly for authorized defensive cybersecurity monitoring, educational research, and network diagnosis:
- IP addresses represent routing endpoints, not verified human identity.
- Machine learning anomaly scores indicate statistical deviation, not confirmed adversarial intent.
- Autonomous firewall modification without human authorization is strictly prohibited.
- All response capabilities default to simulation mode.
