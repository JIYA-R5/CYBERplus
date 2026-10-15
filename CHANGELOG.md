# SentinelAI - Project Changelog

All notable changes and technical modifications to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased] - 2026-10-15

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
