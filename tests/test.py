import json
import socket
import subprocess
import sys
import time

import httpx
import pytest

sys.path.insert(0, "..")
from server.main import app, start  # noqa: E402

BASE_URL: str = None
_server = None
HTTP_PORT: int = None


@pytest.fixture(scope="session", autouse=True)
def run_server():
    global BASE_URL, _server, HTTP_PORT
    HTTP_PORT = 3456
    BASE_URL = f"http://127.0.0.1:{HTTP_PORT}"
    _server = start(HTTP_PORT)
    yield
    _server.should_exit = True


# ─────────────────────────────────────────────────────────────────────────────
# Group 1 — Server health
# ─────────────────────────────────────────────────────────────────────────────

def test_health_returns_200():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.status_code == 200


def test_health_body_ok():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.json()["status"] == "ok"


def test_tcp_ports_endpoint_200():
    r = httpx.get(f"{BASE_URL}/tcp-ports")
    assert r.status_code == 200


def test_tcp_ports_has_echo_key():
    r = httpx.get(f"{BASE_URL}/tcp-ports")
    assert "echo" in r.json()


def test_tcp_ports_has_rst_key():
    r = httpx.get(f"{BASE_URL}/tcp-ports")
    assert "rst" in r.json()


def test_echo_tcp_port_is_reachable():
    port = httpx.get(f"{BASE_URL}/tcp-ports").json()["echo"]["port"]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    result = s.connect_ex(("127.0.0.1", port))
    s.close()
    assert result == 0, f"connect_ex returned {result} for echo port {port}"


def test_rst_tcp_port_is_reachable():
    port = httpx.get(f"{BASE_URL}/tcp-ports").json()["rst"]["port"]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    result = s.connect_ex(("127.0.0.1", port))
    s.close()
    assert result == 0, f"connect_ex returned {result} for rst port {port}"


# ─────────────────────────────────────────────────────────────────────────────
# Group 2 — True positives (RST endpoint flagged)
# ─────────────────────────────────────────────────────────────────────────────

def _run_tool(target: str = None) -> dict:
    url = target or BASE_URL
    out = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", url],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert out.returncode == 0, f"Tool exited {out.returncode}:\n{out.stderr}"
    return json.loads(out.stdout)


def test_tool_finds_at_least_one_finding():
    result = _run_tool()
    assert len(result["findings"]) >= 1


def test_tool_detects_abrupt_connection_reset():
    result = _run_tool()
    types = [f["vulnerability_type"] for f in result["findings"]]
    assert "ABRUPT_CONNECTION_RESET" in types


def test_tool_rst_finding_has_medium_or_higher_severity():
    result = _run_tool()
    rst = [f for f in result["findings"] if f["vulnerability_type"] == "ABRUPT_CONNECTION_RESET"]
    assert len(rst) >= 1
    assert rst[0]["severity"] in ("HIGH", "MEDIUM")


def test_tool_rst_finding_has_evidence():
    result = _run_tool()
    rst = [f for f in result["findings"] if f["vulnerability_type"] == "ABRUPT_CONNECTION_RESET"]
    assert len(rst[0]["evidence"]) > 10


def test_rst_server_directly_sends_rst():
    """Direct socket test: RST port closes with RST, not clean FIN."""
    port = httpx.get(f"{BASE_URL}/tcp-ports").json()["rst"]["port"]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    s.sendall(b"PROBE\r\n")
    connection_reset = False
    try:
        data = s.recv(1024)
        connection_reset = data == b""
    except (ConnectionResetError, OSError):
        connection_reset = True
    finally:
        try:
            s.close()
        except Exception:
            pass
    assert connection_reset, "Expected RST or abrupt close from RST server"


# ─────────────────────────────────────────────────────────────────────────────
# Group 3 — False positives (echo port must NOT be flagged)
# ─────────────────────────────────────────────────────────────────────────────

def test_echo_port_not_in_findings():
    echo_port = httpx.get(f"{BASE_URL}/tcp-ports").json()["echo"]["port"]
    result = _run_tool()
    flagged = [f["endpoint"] for f in result["findings"]]
    assert not any(str(echo_port) in ep for ep in flagged)


def test_echo_server_returns_probe_data():
    """Direct socket test: echo port sends data back and closes with FIN."""
    port = httpx.get(f"{BASE_URL}/tcp-ports").json()["echo"]["port"]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    s.sendall(b"ECHO_PROBE\r\n")
    response = s.recv(1024)
    s.close()
    assert response == b"ECHO_PROBE\r\n"


# ─────────────────────────────────────────────────────────────────────────────
# Group 4 — Output format validation
# ─────────────────────────────────────────────────────────────────────────────

def test_output_is_valid_json():
    out = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    parsed = json.loads(out.stdout)
    assert isinstance(parsed, dict)


def test_output_has_target_field():
    result = _run_tool()
    assert "target" in result


def test_output_target_matches_input():
    result = _run_tool()
    assert BASE_URL in result["target"]


def test_output_has_findings_list():
    result = _run_tool()
    assert "findings" in result
    assert isinstance(result["findings"], list)


def test_output_has_summary_string():
    result = _run_tool()
    assert "summary" in result
    assert isinstance(result["summary"], str)
    assert len(result["summary"]) > 0


def test_finding_has_endpoint_field():
    result = _run_tool()
    for f in result["findings"]:
        assert "endpoint" in f


def test_finding_has_vulnerability_type_field():
    result = _run_tool()
    for f in result["findings"]:
        assert "vulnerability_type" in f


def test_finding_has_evidence_field():
    result = _run_tool()
    for f in result["findings"]:
        assert "evidence" in f


def test_finding_has_severity_field():
    result = _run_tool()
    for f in result["findings"]:
        assert "severity" in f
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW")


# ─────────────────────────────────────────────────────────────────────────────
# Group 5 — Edge cases
# ─────────────────────────────────────────────────────────────────────────────

def test_unreachable_server_returns_valid_json():
    result = _run_tool(target="http://127.0.0.1:9")
    assert isinstance(result, dict)
    assert "findings" in result


def test_unreachable_server_returns_empty_findings():
    result = _run_tool(target="http://127.0.0.1:9")
    assert result["findings"] == []


def test_unreachable_server_returns_summary():
    result = _run_tool(target="http://127.0.0.1:9")
    assert "summary" in result
    assert len(result["summary"]) > 0


def test_tool_does_not_crash_on_refused_tcp_port():
    """Direct test: tool handles a refused TCP port gracefully."""
    # Port 9 (Discard protocol) is almost always refused on modern OSes
    out = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", "http://127.0.0.1:9"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert out.returncode == 0
