# TCP Handshake Simulator

A cybersecurity education tool that visualises the TCP three-way handshake and detects abrupt TCP RST resets — the difference between a server that closes connections properly and one that drops them without warning.

## What This Demonstrates

Every TCP connection begins with a **three-way handshake**: the client sends SYN, the server responds with SYN-ACK, and the client completes the exchange with ACK. When the conversation is over, a well-behaved server initiates a graceful **four-way teardown** using FIN segments. However, servers can also abruptly terminate a connection with a **TCP RST (reset)** segment — skipping the teardown entirely.

This distinction matters because:
- **RST connections** leave the peer in an uncertain state and can indicate crashed services, firewall interventions, or misconfigured applications
- Detecting RST behaviour programmatically helps security engineers map unexpected connection terminations across a network
- Understanding how `SO_LINGER` with a zero linger time forces RST instead of FIN explains how servers deliberately drop connections

## How It Works

```
┌──────────────────────────┐        ┌──────────────────────────────────────────┐
│   tool/main.py           │        │   server/main.py                         │
│   TCP Handshake Scanner  │        │   FastAPI (HTTP) + two raw TCP servers   │
│                          │        │                                          │
│  1. GET /tcp-ports ──────┼──────▶ │  /tcp-ports: {echo: port+1, rst: port+2}│
│  2. probe(echo port) ────┼──────▶ │  Echo server: recv data → sendall(data) │
│     ← ESTABLISHED        │        │  → graceful FIN close                    │
│     ← DATA (echo)        │        │                                          │
│     → FIN (normal)       │        │                                          │
│  3. probe(rst port) ─────┼──────▶ │  RST server: recv data → SO_LINGER(1,0) │
│     ← ESTABLISHED        │        │  → close() sends TCP RST instead of FIN  │
│     ← ConnectionResetError│       │                                          │
│  4. Output JSON findings  │        │                                          │
└──────────────────────────┘        └──────────────────────────────────────────┘
```

- **Demo server** (`server/main.py`): FastAPI app on the main port exposes `/health` and `/tcp-ports`. Two raw TCP servers run on adjacent ports in daemon threads — one echoes data back and closes with FIN, the other uses `SO_LINGER` to send RST.
- **Scanner tool** (`tool/main.py`): discovers TCP ports via HTTP, probes each one by establishing a real TCP connection, logs every state transition (CLOSED → SYN_SENT → ESTABLISHED → DATA_SENT → RST_RECEIVED/FIN_SENT → CLOSED), and reports RST-terminated connections as `ABRUPT_CONNECTION_RESET` findings.
- **Tests** (`tests/test.py`): verify server health, confirm the RST endpoint is detected, confirm the echo endpoint is not flagged (false positive check), validate JSON output structure, and handle unreachable servers gracefully.

## Quick Start

```bash
# Install and run the demo server
cd server
pip install -r requirements.txt
python main.py

# In a second terminal — run the scanner
cd tool
pip install -r requirements.txt
python main.py --target http://localhost:3000

# Run the full test suite
cd tests
pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "127.0.0.1:3002",
      "vulnerability_type": "ABRUPT_CONNECTION_RESET",
      "evidence": "Server on port 3002 sent TCP RST after receiving probe data (Receives probe data then abruptly resets the connection with TCP RST instead of FIN)",
      "severity": "MEDIUM"
    }
  ],
  "summary": "Probed 2 TCP endpoint(s) on 127.0.0.1. 1 finding(s). port 3001 (normal_fin): NORMAL_CLOSE, port 3002 (rst): RST."
}
```

The tool also writes a human summary to stderr:

```
Target:   http://localhost:3000
Findings: 1
  [MEDIUM] 127.0.0.1:3002 — ABRUPT_CONNECTION_RESET
```

## Key Takeaways

1. **The three-way handshake is invisible to application code** — the OS handles SYN/SYN-ACK/ACK. Applications see only a connected socket. The tool models the states explicitly to make the mechanism visible.
2. **RST vs FIN**: FIN means "I am done sending; please acknowledge." RST means "Discard this connection immediately." RST skips TIME_WAIT and leaves no guarantee that all data was delivered.
3. **`SO_LINGER(l_onoff=1, l_linger=0)`** tells the OS to abort the connection with RST when the socket is closed, rather than flushing the send buffer and sending FIN.
4. **Why RST matters for security**: abrupt resets can indicate a firewall silently dropping packets, a server crash mid-session, or an application actively rejecting connections. Scanners that map RST patterns can infer firewall rules without sending a single exploit payload.
5. **Graceful teardown protects data**: the four-way FIN sequence (FIN → ACK → FIN → ACK) ensures both sides acknowledge the end of data before the connection is released.

## Further Reading

- [RFC 9293 — Transmission Control Protocol (2022)](https://www.rfc-editor.org/rfc/rfc9293) — the current TCP specification, including reset generation (§3.5.3)
- [OWASP Testing Guide — Network Infrastructure Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage.html)
- [Beej's Guide to Network Programming — TCP/IP Sockets](https://beej.us/guide/bgnet/)
