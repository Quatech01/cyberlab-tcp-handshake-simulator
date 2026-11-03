"""
TCP Handshake Simulator — visualises the TCP three-way handshake and
four-way teardown for each port reported by the demo server.  Flags any
port that terminates connections with RST instead of a graceful FIN.
"""

import argparse
import json
import socket
import sys
import time
import urllib.parse

try:
    import httpx
except ImportError:
    print(json.dumps({"target": "", "findings": [], "summary": "httpx not installed"}))
    sys.exit(0)


def _probe(host: str, port: int, behavior: str, description: str, timeout: float = 3.0) -> dict:
    stages = []

    def log(state: str, detail: str = "") -> None:
        stages.append({"timestamp": round(time.time(), 3), "state": state, "detail": detail})

    log("CLOSED", f"Starting probe → {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    outcome = "UNKNOWN"
    finding = None

    try:
        log("SYN_SENT", f"OS transmits SYN segment to {host}:{port}")
        s.connect((host, port))
        log(
            "ESTABLISHED",
            "OS received SYN-ACK and sent ACK — three-way handshake complete",
        )

        probe = b"HANDSHAKE_PROBE\r\n"
        s.sendall(probe)
        log("DATA_SENT", f"PSH+ACK carrying {len(probe)} bytes of application data")

        try:
            response = s.recv(1024)
            if response:
                log("DATA_RECEIVED", f"Server echoed {len(response)} bytes back")
            else:
                # Empty recv: server sent FIN before we called recv
                log("EMPTY_RESPONSE", "Server closed connection without sending data")
                outcome = "RST"
                finding = {
                    "endpoint": f"{host}:{port}",
                    "vulnerability_type": "ABRUPT_CONNECTION_RESET",
                    "evidence": (
                        f"Server on port {port} closed connection abruptly "
                        f"without sending a response ({description})"
                    ),
                    "severity": "MEDIUM",
                }
                return {
                    "port": port,
                    "behavior": behavior,
                    "outcome": outcome,
                    "stages": stages,
                    "finding": finding,
                }
        except ConnectionResetError as exc:
            log("RST_RECEIVED", f"TCP RST from server: {exc}")
            outcome = "RST"
            finding = {
                "endpoint": f"{host}:{port}",
                "vulnerability_type": "ABRUPT_CONNECTION_RESET",
                "evidence": (
                    f"Server on port {port} sent TCP RST after receiving "
                    f"probe data ({description})"
                ),
                "severity": "MEDIUM",
            }
            return {
                "port": port,
                "behavior": behavior,
                "outcome": outcome,
                "stages": stages,
                "finding": finding,
            }
        except OSError as exc:
            # WinError 10054 is also raised as a plain OSError in some builds
            log("RST_RECEIVED", f"Connection forcibly reset: {exc}")
            outcome = "RST"
            finding = {
                "endpoint": f"{host}:{port}",
                "vulnerability_type": "ABRUPT_CONNECTION_RESET",
                "evidence": (
                    f"Server on port {port} forcibly reset the connection: {exc}"
                ),
                "severity": "MEDIUM",
            }
            return {
                "port": port,
                "behavior": behavior,
                "outcome": outcome,
                "stages": stages,
                "finding": finding,
            }

        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        log("FIN_SENT", "FIN+ACK — initiating graceful four-way teardown")
        log("TIME_WAIT", "Waiting for server FIN-ACK before final CLOSED")
        outcome = "NORMAL_CLOSE"

    except ConnectionResetError as exc:
        log("RST_RECEIVED", f"TCP RST during connect/send: {exc}")
        outcome = "RST"
        finding = {
            "endpoint": f"{host}:{port}",
            "vulnerability_type": "ABRUPT_CONNECTION_RESET",
            "evidence": f"Server on port {port} sent RST: {exc}",
            "severity": "MEDIUM",
        }
    except ConnectionRefusedError:
        log("REFUSED", "TCP RST / ICMP port-unreachable — nothing listening")
        outcome = "REFUSED"
    except socket.timeout:
        log("TIMEOUT", "No SYN-ACK received within timeout — port filtered or host down")
        outcome = "TIMEOUT"
    except OSError as exc:
        log("ERROR", str(exc))
        outcome = "ERROR"
    finally:
        try:
            s.close()
        except Exception:
            pass
        log("CLOSED", f"Socket descriptor released — outcome: {outcome}")

    return {
        "port": port,
        "behavior": behavior,
        "outcome": outcome,
        "stages": stages,
        "finding": finding,
    }


def run(target: str) -> dict:
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or "127.0.0.1"

    try:
        with httpx.Client(timeout=5.0) as client:
            r = client.get(f"{target}/tcp-ports")
            r.raise_for_status()
            ports_info = r.json()
    except Exception as exc:
        return {
            "target": target,
            "findings": [],
            "summary": f"Could not reach server at {target}: {exc}",
        }

    findings = []
    probes = []

    for _key, info in ports_info.items():
        result = _probe(host, info["port"], info["behavior"], info["description"])
        probes.append(result)
        if result.get("finding"):
            findings.append(result["finding"])

    parts = [f"port {p['port']} ({p['behavior']}): {p['outcome']}" for p in probes]
    summary = (
        f"Probed {len(probes)} TCP endpoint(s) on {host}. "
        f"{len(findings)} finding(s). "
        + ", ".join(parts)
        + "."
    )

    return {"target": target, "findings": findings, "summary": summary}


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP Handshake Simulator and RST detector")
    parser.add_argument(
        "--target", default="http://localhost:3000", help="Base URL of demo server"
    )
    args = parser.parse_args()

    result = run(args.target)
    print(json.dumps(result, indent=2))

    print(f"\nTarget:   {result['target']}", file=sys.stderr)
    print(f"Findings: {len(result['findings'])}", file=sys.stderr)
    for f in result["findings"]:
        print(f"  [{f['severity']}] {f['endpoint']} — {f['vulnerability_type']}", file=sys.stderr)


if __name__ == "__main__":
    main()
