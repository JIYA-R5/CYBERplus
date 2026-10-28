# SentinelAI Endpoint Telemetry Agent

The **SentinelAI Endpoint Telemetry Agent** is a lightweight network telemetry collector designed to monitor endpoint socket connections and stream authenticated telemetry directly to the SentinelAI API.

---

## Architecture & Important Security Boundary

> [!IMPORTANT]
> **Container vs Host Network Isolation:**
> A standard Linux container inside Docker Desktop **cannot** automatically inspect the Windows host machine's native network connections or Windows Security Event Logs without privileged kernel extensions.
>
> Therefore, SentinelAI provides two distinct modes:
> 1. **Native Host Agent (Recommended for Live Endpoints):** Runs directly on the Windows/Linux host OS with standard Python, collecting real active TCP/UDP endpoints and shipping them to the Dockerized API.
> 2. **Dockerized Synthetic Agent:** Runs inside Docker Compose as an automated telemetry generator for continuous defensive demonstrations and pipeline testing.

---

## Telemetry Collection Modes

The agent supports three collection modes:

| Mode | Command Flag | Description |
|---|---|---|
| **`native`** | `--mode native` | Safely samples active TCP/UDP socket connections (via `netstat` and standard socket libraries) without requiring root or kernel drivers. |
| **`synthetic`** | `--mode synthetic` | Simulates enterprise HTTP, DNS, and periodic external port scan / brute force anomalies for testing detection engines. |
| **`file`** | `--mode file --file <path>` | Ships records from a local Suricata EVE JSON or network CSV log file. |

---

## Deployment Scenarios

### Scenario A: Single Laptop (Docker API + Native Agent on same machine)

Run Docker Compose for the API and dashboard, and run the agent natively on the same machine:

```powershell
# 1. Start Docker stack (API on port 8000, Dashboard on 8501)
docker compose up -d api dashboard

# 2. Run the agent natively on Windows
python agent/agent.py --mode native --api-url http://localhost:8000 --agent-secret sentinel-agent-secret-token --interval 10
```

- Target URL: `http://localhost:8000`
- Telemetry Flow: Windows Host Sockets &rarr; Python Agent &rarr; Docker Port Forward (8000) &rarr; FastAPI Backend &rarr; SQLite Volume &rarr; Streamlit Dashboard.

---

### Scenario B: Two Laptops (API Server on Laptop 1, Monitored Agent on Laptop 2)

Monitor a second computer on the same Local Area Network (LAN):

#### 1. On Laptop 1 (Host running Docker):
Find Laptop 1's local LAN IP:
```powershell
ipconfig
# Example output: IPv4 Address. . . . . . . . . . . : 192.168.1.150
```

Ensure Windows Defender Firewall allows incoming connections on port 8000:
```powershell
New-NetFirewallRule -DisplayName "SentinelAI API Port 8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
```

#### 2. On Laptop 2 (Endpoint being monitored):
Run the agent pointing to Laptop 1's IP address:
```powershell
python agent/agent.py --mode native --api-url http://192.168.1.150:8000 --agent-secret sentinel-agent-secret-token --interval 10
```

---

### Scenario C: Automated Container Collector (Inside Docker Compose)

The `agent` service in `docker-compose.yml` runs in `synthetic` mode automatically:
```powershell
docker compose up -d
```
The agent sends authenticated telemetry bursts to `http://api:8000` through the internal `sentinel-net` bridge network every 15 seconds. New events and correlated incidents will automatically appear in the Streamlit dashboard on `http://localhost:8501` without manual file upload.

---

## Configuration & Environment Variables

The agent can be configured via command-line arguments or environment variables:

| Variable | CLI Flag | Default | Description |
|---|---|---|---|
| `SENTINEL_API_URL` | `--api-url` | `http://localhost:8000` | Target SentinelAI API base URL |
| `SENTINEL_AGENT_SECRET` | `--agent-secret` | `sentinel-agent-secret-token` | Shared secret token passed in `X-Agent-Secret` header |
| `AGENT_MODE` | `--mode` | `native` (host) / `synthetic` (container) | Collection mode (`native`, `synthetic`, `file`) |
| `AGENT_INTERVAL` | `--interval` | `10` | Frequency in seconds between telemetry shipments |
| `AGENT_HOST_ID` | `--host-id` | Machine hostname | Friendly host identifier displayed in SOC audit trails |

---

## Testing & Verification

Test telemetry collection without transmitting (dry-run):
```powershell
python agent/agent.py --mode native --dry-run --once
```

Test single-shot transmission:
```powershell
python agent/agent.py --mode native --api-url http://localhost:8000 --once
```
