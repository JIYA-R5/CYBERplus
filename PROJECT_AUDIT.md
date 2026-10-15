# SentinelAI Project Audit: Architecture, Codebase & Security Review

**Repository:** `https://github.com/JIYA-R5/CYBERplus.git`  
**Date of Audit:** October 15, 2026  
**Auditor:** Senior Cybersecurity & Software Architecture Review  
**Project Objective:** Autonomous AI-Driven Network Intrusion Detection & Incident Response System for College Project & Hackathon Demonstration  

---

## 1. Executive Summary

SentinelAI is intended to be a defensive network security monitoring and automated incident analysis platform. It aims to ingest network logs and structured events, identify cyber threats (including port scanning, brute-force authentication, volumetric DDoS floods, and data exfiltration), explain detected incidents via Google Gemini, present actionable telemetry on a SOC dashboard, and orchestrate safe incident response workflows.

The current repository represents an early-stage proof of concept (MVP) consisting of a basic Streamlit dashboard and heuristic helper modules. While the frontend renders basic metrics and charts cleanly, a deep architectural and source-code inspection reveals critical functional gaps:
- **No Google Gemini integration exists:** The AI Explainer module (`explainerAI.py`) relies entirely on static dictionary lookups. No API calls, SDK dependencies, or prompt templates are implemented.
- **No Machine Learning model exists:** Threat detection relies entirely on static threshold checks and, in fact, depends heavily on whether the incoming CSV already contains a pre-labeled `"Activity"` column.
- **No persistent database or incident lifecycle:** Alerts are generated ephemerally in memory per Streamlit session. A static file `alert.csv` exists in the repository, but it is not linked to or written by the application.
- **Typographical errors in core files:** `response_enigne.py` (misspelled "enigne") and `requiremnets.txt` (duplicate misspelled requirements file).
- **No test suite or validation:** Zero unit or integration tests exist in the codebase.
- **Empty Documentation:** `README.md` is 0 bytes with no setup instructions, environment variables, or architecture descriptions.

---

## 2. Component-by-Component Architectural Audit

### 2.1. Frontend & Dashboard (`app.py`)
- **Status:** Partially implemented.
- **What Works:**
  - Streamlit page renders a dark-themed cybersecurity interface with KPI metrics (Monitored Flows, Total Packets, High & Critical Alerts, Risk Index).
  - Two Plotly charts: "Packet Volume Timeline" and "Source IP Distribution".
  - Alert table displaying rows filtered by risk level.
  - Expandable panels per alert displaying canned AI threat summaries and copyable firewall containment commands.
- **Flaws & Missing Capabilities:**
  - **Single Page Monolith:** Lacks tabbed segregation for Incident Management, Live Monitoring, Log File Analysis, and Response Audit Logs.
  - **No Interactive Incident State:** Incidents cannot be acknowledged, updated (e.g., Open → Investigating → Mitigated → Resolved → False Positive), or assigned.
  - **No Dry-Run Response Execution:** The response containment section only displays raw string commands; analysts cannot execute, test in dry-run mode, verify, or log responses.
  - **Missing Input Validation:** Uploading an arbitrary CSV with unexpected columns will raise an unhandled exception or fail silently into fallback data.
  - **No Live Monitoring Controls:** No live packet capture, Suricata EVE JSON stream, or realistic simulated streaming controls.

### 2.2. Detection Engine (`detector.py`)
- **Status:** Minimal heuristic baseline; logically flawed.
- **What Works:**
  - Encapsulated within `ThreatDetector` class.
  - Defines baseline signature dictionary (`Port Scan`, `Brute Force`, `DDoS Flood`, `Data Exfiltration`, `Suspicious Reconnaissance`) with MITRE ATT&CK IDs.
  - Evaluates individual flow records and enriches DataFrames with `"Threat Detected"`, `"Risk"`, `"Confidence"`, and `"Threat Details"`.
- **Critical Flaws & Logical Gaps:**
  - **Circular Dependency on Pre-labeled Data:** The engine checks `if activity in self.known_signatures`. In `sample_traafic.csv`, the `Activity` column already explicitly names the attack (e.g. `Activity: "Port Scan"`). If raw, unclassified network logs are provided (e.g. `Activity: "Normal Traffic"` or unlabelled flow logs), the engine only checks whether `packets >= 800` or `packets >= 350`, or if `destination_port in [22, 3389, 445] and packets > 250`.
  - **No Multi-event Temporal Correlation:** Genuine port scans contact many distinct ports over time. Genuine brute-force attacks generate high failure counts or repeated requests to a single service over time. `detector.py` evaluates only single rows in isolation without sliding windows, target aggregation, or cross-event state.
  - **Missing Essential Network Fields:** Does not inspect or track `Destination IP`, TCP flags (SYN/ACK/RST), duration, connection state, or authentication status codes.

### 2.3. Traffic Analyzer (`analyzer.py`)
- **Status:** Functional for basic descriptive statistics.
- **What Works:**
  - `TrafficAnalyzer` computes total records, total packet volume, average packets, peak volume, and breakdown by risk levels.
  - Calculates a weighted overall network risk score (0–100) and assigns DEFCON-style labels (`Low`, `Medium`, `High`, `Critical`).
  - Aggregates top source IPs by volume and flow counts.
- **Flaws & Missing Capabilities:**
  - Hardcoded baseline packet average (150.0). Does not dynamically calculate standard deviation or statistical anomalies (e.g. z-scores or IQR).
  - Lacks protocol analysis (TCP vs UDP vs ICMP vs HTTP/DNS).
  - `get_timeline_aggregates()` is implemented in `analyzer.py` but unused by `app.py`.

### 2.4. AI Explainer & Copilot (`explainerAI.py`)
- **Status:** Completely simulated; NO actual Google Gemini integration.
- **What Works:**
  - Provides a pre-written static dictionary of technical explanations, impact assessments, and MITRE techniques for 6 attack names.
  - Generates a templated executive briefing string from DataFrame risk counts.
- **Critical Flaws & Missing Capabilities:**
  - **Zero LLM Integration:** Despite claims of "AI Explainer", no Gemini API calls are made. No `google-generativeai` or `google-genai` libraries are imported or listed in requirements.
  - **No Error Handling or Fallback Framework:** Because no real API is called, there is no logic to handle API timeouts, quota limits, missing `GEMINI_API_KEY`, or schema validation.
  - **No Interactive Analyst Copilot:** Cannot answer ad-hoc questions regarding an alert or generate custom investigative playbooks.

### 2.5. Incident Response Engine (`response_enigne.py`)
- **Status:** Stub / Static command formatter; Typo in filename.
- **What Works:**
  - Maps attack categories to priority levels (`P1 - Critical`, `P2 - High`, `P3 - Medium`) and policy text.
  - Formats copyable firewall block strings for Linux `iptables`, `ufw`, Windows `PowerShell`, and Cisco IOS ACL.
- **Critical Flaws & Missing Capabilities:**
  - **Typo in filename:** Named `response_enigne.py` instead of `response_engine.py`.
  - **No Audit Trail:** Responses are neither logged nor persisted.
  - **No Safe Execution / Dry-Run Mode:** No mechanism to safely simulate, approve, or verify defensive actions.
  - **No Rollback Capability:** Does not generate rollback / unblock commands or expiry timers.

### 2.6. Data & Persistence (`alert.csv`, `sample_traafic.csv`)
- **Status:** Static disconnected CSV files.
- **Issues:**
  - `alert.csv` contains 4 static rows that are never read, updated, or written to by `app.py`.
  - `sample_traafic.csv` has a typo in filename ("traafic") and contains only 10 rows without destination IP or protocol fields.
  - No database (SQLite or MongoDB) is connected to store event history, audit logs, or incident state transitions.

---

## 3. Feature Completeness Matrix

| Feature Area | Sub-Feature | Claimed in UI/Doc | Actually Implemented | Status |
| :--- | :--- | :---: | :---: | :--- |
| **Detection Engine** | Volumetric Flood Detection | Yes | Threshold-based (`packets > 800`) | Partially Implemented |
| | Port Scan Detection | Yes | Pre-labeled signature match only | Broken / Trivial |
| | Brute Force Detection | Yes | Checks port 22/3389/445 + packets > 250 | Broken / Trivial |
| | Data Exfiltration Detection | Yes | Pre-labeled signature match only | Missing Real Logic |
| | Multi-Event Correlation | No | None (isolated single-row evaluations) | Missing |
| | Machine Learning Classifier | Claimed | None | Missing |
| **AI Integration** | Google Gemini Threat Explainer | Claimed ("AI Explainer") | Static hardcoded Python dictionary | Broken / Missing API |
| | Structured Gemini Responses | No | None | Missing |
| | Offline / Graceful Fallback | No | Only returns static text | Missing Real Handling |
| **Incident Response** | Firewall Rule Generation | Yes | String formatting templates | Functional (Static) |
| | Response Workflow & Approval | No | None | Missing |
| | Dry-Run Simulation | No | None | Missing |
| | Tamper-Evident Audit Logging | No | None | Missing |
| **Live Monitoring** | Real-Time Packet Capture | No | None | Missing |
| | Suricata EVE JSON Ingestion | No | None | Missing |
| | Real-Time Simulator Stream | No | None | Missing |
| **Data & Storage** | Persistent Incident Database | No | Static `alert.csv` (unlinked) | Missing |
| | Status Lifecycle Management | No | None | Missing |
| **Testing & Quality** | Automated Test Suite | No | 0 tests | Missing |
| | Input Validation & Error Handling | No | Minimal | Inadequate |
| | Windows Setup Documentation | No | `README.md` is 0 bytes | Missing |

---

## 4. Security & Quality Assessment

1. **Hardcoded Secrets & API Key Exposure:**
   - Currently, no secrets are hardcoded because no external APIs are configured.
   - However, no `.env.example` file exists to guide developers on configuring `GEMINI_API_KEY` securely without checking `.env` into Git.
2. **Untrusted Data & Injection Risks:**
   - Firewall command generators interpolate `source_ip` directly into string commands (`f"New-NetFirewallRule ... -RemoteAddress \"{source_ip}\""`). If an uploaded log contains a malicious string in `Source IP` (e.g. `192.168.1.1; Remove-Item C:\ -Recurse`), executing this without strict IP validation creates a command injection vulnerability.
3. **Over-promising & Misleading Claims:**
   - Labeling static dictionary strings as "AI Threat Intelligence Briefing" and "AI Threat Analysis" will fail scrutiny in a technical evaluation or hackathon judging session. Real Gemini API integration with demonstrable fallback is essential.
4. **Resilience & Fault Tolerance:**
   - Currently, if any unexpected data format or missing column occurs, Streamlit displays raw Python tracebacks.

---

## 5. Feasibility & Recommendations for College Demo & Hackathon

To turn SentinelAI into a standout, defensible, and reliable project, we must prioritize:
1. **Fix Core Quality & Architecture:** Fix module typos (`response_engine.py`), establish clean separation of concerns, and add a `.env.example`.
2. **Build a Reliable Stateful Detection Engine:** Add genuine temporal correlation (sliding window) for port scanning across distinct ports, brute force failed attempts, volumetric DDoS floods, and data exfiltration. Provide transparent confidence scores and evidence strings.
3. **Genuine Google Gemini Integration with Bulletproof Fallback:** Implement real Google Gemini API calls via official SDK for structured explanations, risk summaries, and mitigation playbooks, with automatic fallback to local rule explanations whenever `GEMINI_API_KEY` is absent or the system is offline.
4. **Safe, Auditable Incident Response:** Create a complete approval workflow with dry-run mode, firewall script verification, rollback capability, and an immutable audit log.
5. **Persistent Incident & Telemetry Store (SQLite):** Provide an embedded SQLite database that tracks incidents, audit logs, and allows real-time status transitions.
6. **Live Telemetry Simulator & Structured JSON Ingestion:** Support uploading Suricata EVE JSON / Zeek logs, alongside a controllable real-time event generator that simulates attacks in an isolated, labeled manner.
7. **Comprehensive Pytest Suite & Verified Windows Setup:** Achieve 100% test coverage for detection rules, validation, fallback, and response safety.
