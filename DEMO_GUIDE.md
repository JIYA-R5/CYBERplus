# 🎤 SentinelAI: 5–7 Minute Presentation & Demo Guide

**Target Audience:** Hackathon Judges, College Evaluation Panel, Cybersecurity Mentors  
**Presenter:** Project Lead / Developer  
**System Prerequisites:** Windows PowerShell, Virtual environment active, `streamlit run app.py` running at `http://localhost:8501`.

---

## ⏱️ Presentation Timeline & Script

### Minute 0:00 – 1:00 | The Problem & Architectural Overview
- **Opening Statement:**  
  *"Good morning judges. Modern Security Operations Centers (SOCs) face an overwhelming volume of alerts and alert fatigue. SentinelAI is our autonomous AI-powered defensive intrusion detection and incident response platform. It bridges the gap between raw telemetry ingestion, behavioral anomaly correlation, Google Gemini generative AI reasoning, and auditable defensive containment."*
- **Visual Action:**  
  Show the **Overview Tab (`📊 SOC Overview`)**. Highlight the DEFCON Risk indicator (`DEFCON 1 - CRITICAL`), total monitored flows, and the **AI Executive Threat Briefing** summarizing recent high-risk behaviors across the enterprise.

---

### Minute 1:00 – 2:30 | Ingesting Telemetry & Stateful Detection
- **Talking Points:**  
  *"Unlike basic rule engines that rely on single packet thresholds or pre-labeled tags, SentinelAI implements stateful multi-event temporal correlation. Let's demonstrate by ingesting a structured attack stream."*
- **Visual Action:**  
  1. Click on **`📁 Telemetry Ingestion`** tab.
  2. Select `"Simulated Port Scan Attack (attack_port_scan.json)"` or `"Suricata EVE JSON Alert Stream"`.
  3. Click **"Load and Analyze Selected Sample"**.
  4. Point out the detection results table:
     - Show how individual probe events across ports 21, 22, 23, 80, 443 are correlated into a single high-confidence incident: `T1046 - Network Service Discovery`.
     - Explain the evidence string: *"Host contacted 7 distinct ports across 7 connection attempts within 10 seconds."*

---

### Minute 2:30 – 3:45 | Incident Triage & MITRE ATT&CK Mapping
- **Talking Points:**  
  *"Once an anomaly is correlated, it enters our persistent Incident Management Queue backed by an embedded SQLite database."*
- **Visual Action:**  
  1. Switch to the **`🚨 Incident Queue`** tab.
  2. Filter by Severity: `Critical` or `High`.
  3. Select `INC-1001` or the newly generated incident.
  4. Demonstrate the drill-down card:
     - Show Source IP, Target IP, Ports probed, Severity badge, and Confidence rating (90%+).
     - Click **"Investigating"** to transition the incident status. Explain that status transitions are immediately audited in SQLite.

---

### Minute 3:45 – 5:00 | Google Gemini AI Copilot & Offline Fallback
- **Talking Points:**  
  *"Now let's examine our AI Threat Copilot. SentinelAI leverages Google Gemini to translate cryptic packet indicators into actionable forensic intelligence. Importantly, it features a 100% deterministic local fallback, ensuring SOC operations never halt if the cloud API is offline or unconfigured."*
- **Visual Action:**  
  1. Open the **`🤖 AI Threat Copilot`** tab.
  2. Point out:
     - **Executive Summary & Technical Mechanism:** Clear technical breakdown of the attack vector.
     - **Potential Impact:** Explaining risk to business operations.
     - **Interactive Forensic Investigation Checklist:** Check off the interactive triage items (e.g., *"Verify whether internal honeypots were touched"*).
     - **Ask Copilot Box:** Type a quick question (e.g., *"What is the best perimeter defense for this scan?"*) and show the responsive response.

---

### Minute 5:00 – 6:15 | Safe Incident Response & Tamper-Evident Audit Trail
- **Talking Points:**  
  *"A major vulnerability in automated systems is accidental disruption or command injection. SentinelAI implements strict defense-in-depth: IP addresses are sanitized via Python's standard `ipaddress` library, dry-run simulation is enabled by default, and reversible rollback scripts are generated automatically."*
- **Visual Action:**  
  1. Return to the Incident Drill-down in **`🚨 Incident Queue`**.
  2. Click **"Simulate Firewall Quarantine"**.
  3. Show the copyable containment commands:
     - Windows PowerShell (`New-NetFirewallRule`)
     - Linux `iptables`
     - Linux `ufw`
     - Cisco IOS ACL
  4. Expand the **Reversible Rollback Scripts** (`Remove-NetFirewallRule`, `iptables -D`).
  5. Switch to **`📜 Response Audit Trail`** tab:
     - Point out the immutable audit log entry displaying `timestamp`, `incident_id`, `execution_mode: dry_run`, `result: SIMULATED_SUCCESS`, and operator notes.

---

### Minute 6:15 – 7:00 | Live Telemetry Simulator & Conclusion
- **Talking Points:**  
  *"Finally, for continuous monitoring demonstrations, SentinelAI includes a thread-safe live telemetry simulator streaming realistic network flows."*
- **Visual Action:**  
  1. Open **`📡 Live Monitoring`** tab.
  2. Click **"Start Live Telemetry Stream"**.
  3. Watch events populate in real time, clearly tagged with `[SIMULATED: Lab Scenario]` to maintain ethical transparency.
  4. Conclude:
     *"In summary: SentinelAI delivers reliable multi-event correlation, Google Gemini AI reasoning with deterministic fallback, and safe, auditable response workflows—fully tested with 25 automated Pytest checks. Thank you, and we welcome your questions!"*

---

## ❓ Common Judge Questions & Recommended Answers

| Question | Recommended Answer |
| :--- | :--- |
| **"What happens if Gemini API quota expires or you have no Internet?"** | *"SentinelAI has a built-in deterministic local knowledge base. It uses the exact same validated Pydantic schema and provides comprehensive root-cause analysis and investigation checklists completely offline."* |
| **"How do you prevent a malicious attacker from injecting commands into the firewall rules?"** | *"All incoming IP strings are strictly validated using Python's standard `ipaddress.ip_address` library before rule generation. Any string with shell characters like `;`, `&`, or `|` fails validation and is neutralized."* |
| **"Is your live monitoring real packet capture?"** | *"Our live monitoring simulator generates realistic multi-protocol enterprise traffic in a controlled laboratory environment. To ensure ethical compliance, every generated record is strictly marked `[SIMULATED: Lab Scenario]`. The system also ingests genuine real-world Suricata EVE JSON logs."* |
| **"How is machine learning separated from heuristic rules?"** | *"We implemented Scikit-Learn IsolationForest for unsupervised anomaly scoring. Its continuous deviation score is reported separately from our deterministic rule engine so analysts know exactly which detection triggered."* |
