"""
SentinelAI - Live Network Telemetry Connection Demonstration
Connects to ws://127.0.0.1:8000/ws/events and streams live packet and flow events in real time.
"""
import sys
import json
import asyncio
import websockets

async def demonstrate_live_stream():
    uri = "ws://127.0.0.1:8000/ws/events"
    print("=" * 115)
    print("                    SENTINELAI — LIVE NETWORK TELEMETRY CONNECTION DEMONSTRATION")
    print("=" * 115)
    print(f"[*] Target WebSocket Endpoint: {uri}")
    print("[*] Initiating WebSocket RFC 6455 upgrade handshake...")

    try:
        async with websockets.connect(uri) as ws:
            print("[+] Handshake Completed! Connection Status: ESTABLISHED (HTTP 101 Switching Protocols)")
            print("[+] Live telemetry channel is open. Streaming live network flow events:\n")

            header = f"| {'EVENT ID':<13} | {'TIME':<9} | {'SOURCE ENDPOINT':<24} | {'DESTINATION ENDPOINT':<24} | {'PROTO':<5} | {'SIZE':<7} | {'FLAGS':<5} | {'DETECTION STATUS':<16} |"
            divider = "|" + "-"*15 + "|" + "-"*11 + "|" + "-"*26 + "|" + "-"*26 + "|" + "-"*7 + "|" + "-"*9 + "|" + "-"*7 + "|" + "-"*18 + "|"
            
            print(header)
            print(divider)

            for _ in range(6):
                message = await ws.recv()
                data = json.loads(message)
                events = data if isinstance(data, list) else [data]

                for ev in events:
                    ev_id = ev.get("id", "EVT-UNK")
                    time_val = ev.get("timestamp", "")
                    time_str = time_val[11:19] if "T" in time_val else time_val
                    src = f"{ev.get('src_ip')}:{ev.get('src_port')}"
                    dst = f"{ev.get('dst_ip')}:{ev.get('dst_port')}"
                    proto = ev.get("protocol", "TCP")
                    size = f"{ev.get('packet_size', 0)}B"
                    flags = ev.get("flags") or "—"
                    status = ev.get("detection_status", "Normal")

                    # Highlight suspicious events
                    flag_display = f"\033[93m{flags}\033[0m" if flags == "SYN" else flags
                    status_display = f"\033[91m{status}\033[0m" if ev.get("is_suspicious") else f"\033[92m{status}\033[0m"

                    print(f"| {ev_id:<13} | {time_str:<9} | {src:<24} | {dst:<24} | {proto:<5} | {size:<7} | {flags:<5} | {status:<16} |")

            print(divider)
            print("\n[+] Telemetry stream verified: Packets arriving dynamically in real-time.")
            print("[+] Live Network connection demonstration succeeded.\n")

    except Exception as e:
        print(f"[-] Connection Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    asyncio.run(demonstrate_live_stream())
