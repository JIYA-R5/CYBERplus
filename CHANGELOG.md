# SentinelAI - Project Changelog

All notable changes and technical modifications to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased] - 2026-10-15

### Stage 9: Comprehensive Documentation & Hackathon Presentation Prep
#### Added
- **`README.md`**: Complete production-ready documentation with architectural diagrams (Mermaid), key features, Windows PowerShell setup, virtual environment activation, and test execution commands.
- **`DEMO_GUIDE.md`**: Rehearsed 5–7 minute presentation script for college evaluation and hackathons, complete with anticipated judge Q&A.

---

### Stage 8: SOC Dashboard Architecture & UI Elevation
#### Changed
- **`app.py`**: Transformed into a 6-tab SOC cybersecurity dashboard:
  1. `📊 SOC Overview`: DEFCON posture, KPI metric cards, threat severity pie chart, attack category bar chart, and AI Executive briefing.
  2. `🚨 Incident Queue`: Multi-criteria search and filter, drill-down incident cards, status transitions, and defensive containment triggers.
  3. `🤖 AI Threat Copilot`: Validated root-cause analysis, interactive forensic investigation checklist, and interactive Q&A analyst prompt.
  4. `📁 Telemetry Ingestion`: Suricata EVE JSON parser, generic JSON parser, built-in laboratory attack samples, and CSV export.
  5. `📡 Live Monitoring`: Real-time streaming simulation with explicit `[SIMULATED: Lab Scenario]` labeling.
  6. `📜 Response Audit Trail`: Filterable SQLite audit table recording all status transitions and simulated/live containment actions.

---

### Stage 7: Safe, Auditable Defensive Response Workflow
#### Added
- **`response_engine.py`**: Added `execute_response_action()` implementing the formal defense lifecycle: `Validation -> Execution (Dry-Run by Default) -> Verification -> Tamper-Evident Audit Logging`.
- **Injection Defense**: Enforced strict IP sanitization via `ipaddress.ip_address` to reject command injection attempts.
- **Automated Tests**: Added `tests/test_response.py` verifying dry-run safety, malicious input rejection, and rollback symmetry.

---

### Stage 6: Structured JSON Ingestion & Live Monitoring Simulator
#### Added
- **`log_parser.py`**: Built multi-format log parser supporting Suricata EVE JSON alert/flow streams and generic JSON arrays with line-by-line syntax error isolation.
- **`live_monitor.py`**: Implemented thread-safe `LiveMonitoringSimulator` streaming realistic enterprise traffic with controlled laboratory scenario injections.
- **Automated Tests**: Added `tests/test_ingestion.py` covering Suricata EVE JSON parsing, generic JSON parsing, and simulator thread safety.
- **Sample Datasets**: Added `data/normal_traffic.csv`, `data/attack_port_scan.json`, `data/attack_brute_force.json`, `data/attack_ddos_flood.json`, `data/suricata_sample.json`, and `data/malformed_records.json`.

---

### Stage 5: Incident Persistence & SQLite Database
#### Added
- **`database.py`**: Embedded zero-configuration SQLite persistence engine (`sentinel.db`) with tables for `incidents`, `audit_logs`, and `telemetry_events`.
- **Status Lifecycle Transitions**: Enabled state changes (`Open`, `Investigating`, `Mitigated`, `Resolved`, `False Positive`) with automated audit trail logging.
- **Automated Tests**: Added `tests/test_database.py` covering schema creation, incident retrieval, status updates, and demo data reset.

---

### Stage 4: Google Gemini AI Integration & Safe Fallback
#### Added
- **Google GenAI Client Integration**: Upgraded `explainerAI.py` with official `google.genai` SDK support, connecting to `gemini-2.5-flash` for live incident explanations.
- **Pydantic Validation Contract**: Introduced `ThreatExplanation` model enforcing strict schema validation (`summary`, `mechanism`, `potential_impact`, `mitre_technique`, `investigation_steps`, `containment_recommendations`, `provider`, `ai_disclaimer`).
- **Deterministic Local Fallback**: Provided comprehensive offline knowledge base with forensic investigation checklists and containment recommendations, ensuring 100% operational reliability when `GEMINI_API_KEY` is missing or the system is offline.
- **Compliance & Attribution Labels**: Added explicit provider attribution (`google_gemini` vs `local_rule_fallback`) and human-in-the-loop validation disclaimers.
- **Automated Tests**: Added `tests/test_explainer.py` covering fallback contracts, all attack categories, API error resilience, and executive summary generation.

#### Verified
- Ran full test suite via `pytest -v tests/`: **14 passed in 2.48s (100% pass rate)**.

---

### Stage 3: Robust Behavioral Detection Engine & Automated Test Suite
#### Added
- **Stateful Multi-Event Temporal Correlation**: Implemented `ThreatDetector.correlate_incidents()` to detect distributed port scanning across distinct ports, repeated brute-force authentication attacks on administrative services, and aggregated volumetric surges.
- **Structured Incident Contract**: Created `Incident` dataclass defining professional SOC fields (`incident_id`, `category`, `source_ip`, `destination_ip`, `destination_ports`, `severity`, `confidence`, `rule_id`, `mitre_id`, `evidence`, `recommended_action`, `status`).
- **Machine Learning Anomaly Classifier**: Added `MLAnomalyDetector` using Scikit-Learn `IsolationForest` to generate transparent continuous anomaly scores, clearly segregated from deterministic rule-based classifications.
- **Resilient Input Validation**: Hardened against missing fields, non-numeric packet values, empty/NaN rows, and malicious IP injection strings.
- **Automated Test Suite**: Added `tests/test_detector.py` covering normal nominal traffic, volumetric DDoS, single-flow brute force, known signatures, stateful port scan correlation, stateful brute force correlation, DataFrame backward compatibility, malformed data handling, and ML anomaly detection.
- **Configuration**: Added `pytest.ini` with `pythonpath = .`.

#### Verified
- Ran full test suite via `pytest -v tests/test_detector.py`: **9 passed in 5.61s (100% pass rate)**.
- Verified end-to-end compatibility with `sample_traafic.csv` pipeline.

---

### Stage 2: Bug Fixes, Project Clean-Up & Environment Setup
#### Added
- **`response_engine.py`**: Created canonical response engine module with strict IP sanitization (`ipaddress.ip_address`), prevention of command injection, reversible containment rollback scripts, and multi-tier response playbooks.
- **`.env.example`**: Standardized environment configuration template documenting `GEMINI_API_KEY`, `SENTINEL_ENV`, `RESPONSE_MODE`, and detection thresholds.
- **`requirements.txt`**: Modernized dependency specification adding `pydantic`, `python-dotenv`, `pytest`, `scikit-learn`, and `google-generativeai`.

#### Changed
- **`response_enigne.py`**: Transformed into a backwards-compatible alias module that redirects all calls to `response_engine.py`.
- **`app.py`**: Updated module import from `response_enigne` to canonical `response_engine`.

#### Removed
- **`requiremnets.txt`**: Deleted redundant duplicate file with misspelled name.

---

### Stage 1: Audit, Architecture Assessment & Initial Documentation
#### Added
- **`PROJECT_AUDIT.md`**: Comprehensive architectural and security audit of the existing codebase. Documents component status, feature completeness matrix, security vulnerabilities (untrusted input in command generation, lack of validation), and gaps (lack of Gemini API integration, absence of database, missing test suite).
- **`IMPLEMENTATION_PLAN.md`**: Nine-stage prioritized roadmap with technical specifications, dependency matrix, acceptance criteria, and verification procedures for transformational upgrade.
- **`CHANGELOG.md`**: Tracking log to record all architectural, algorithmic, and functional changes throughout development.
- **`.gitignore`**: Added standard Python `.gitignore` to prevent compiled `.pyc` bytecode, `__pycache__/`, virtual environments (`.venv/`), and IDE configuration files from polluting the Git repository.

#### Changed
- Unstaged and cleaned up cached `__pycache__/*.pyc` files from Git index.
- Committed initial codebase snapshot (`3700de5`) with clean working tree.

#### Verified
- Verified that existing modules (`detector.py`, `analyzer.py`, `explainerAI.py`, `response_enigne.py`) can be imported under Python 3.12 without syntax errors.
- Verified end-to-end execution of current baseline pipeline against `sample_traafic.csv`.
- Confirmed that `$env:GEMINI_API_KEY` is currently unset and that `explainerAI.py` currently uses static dictionary lookups rather than live Google Gemini API calls.

---

## [0.1.0] - Baseline MVP (Initial State)
- Initial Streamlit UI (`app.py`) with basic dark theme and Plotly charts.
- Heuristic threat detector (`detector.py`) with basic packet thresholds and known signature names.
- Traffic analyzer (`analyzer.py`) computing basic volume metrics and weighted risk score.
- Simulated threat explainer (`explainerAI.py`) providing pre-written text summaries.
- Response engine template (`response_enigne.py`) providing string-formatted firewall commands.
- Static data files (`alert.csv`, `sample_traafic.csv`).
