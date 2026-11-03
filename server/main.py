import socket
import struct
import sys
import threading
import time
import urllib.request

import uvicorn
from fastapi import FastAPI

app = FastAPI()

_tcp_echo_port: int = None
_tcp_rst_port: int = None
_shutdown = threading.Event()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/tcp-ports")
def tcp_ports():
    return {
        "echo": {
            "port": _tcp_echo_port,
            "behavior": "normal_fin",
            "description": (
                "Echoes probe data back and closes with graceful FIN "
                "— the standard four-way TCP teardown"
            ),
        },
        "rst": {
            "port": _tcp_rst_port,
            "behavior": "rst",
            "description": (
                "Receives probe data then abruptly resets the connection "
                "with TCP RST instead of FIN"
            ),
        },
    }


# ─── TCP echo server (graceful FIN close) ────────────────────────────────────

def _handle_echo(conn: socket.socket) -> None:
    with conn:
        try:
            conn.settimeout(2.0)
            data = conn.recv(1024)
            if data:
                conn.sendall(data)
        except Exception:
            pass
    # The `with` block exit triggers graceful FIN teardown


def _run_echo_server(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(32)
        srv.settimeout(0.2)
        while not _shutdown.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=_handle_echo, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue


# ─── TCP RST server (abrupt reset via SO_LINGER) ─────────────────────────────

def _handle_rst(conn: socket.socket) -> None:
    try:
        conn.settimeout(2.0)
        conn.recv(1024)  # wait for probe data so the handshake is established
        time.sleep(0.05)  # ensure client's recv() is in flight before we RST
    except Exception:
        pass
    finally:
        try:
            # SO_LINGER with l_onoff=1, l_linger=0 causes close() to send RST
            if sys.platform == "win32":
                linger = struct.pack("HH", 1, 0)  # two unsigned shorts on Windows
            else:
                linger = struct.pack("ii", 1, 0)  # two ints on Linux/macOS
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _run_rst_server(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(32)
        srv.settimeout(0.2)
        while not _shutdown.is_set():
            try:
                conn, _ = srv.accept()
                threading.Thread(target=_handle_rst, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue


# ─── Startup ─────────────────────────────────────────────────────────────────

def start(port: int = 3000):
    global _tcp_echo_port, _tcp_rst_port
    _shutdown.clear()
    _tcp_echo_port = port + 1
    _tcp_rst_port = port + 2

    threading.Thread(target=_run_echo_server, args=(port + 1,), daemon=True).start()
    threading.Thread(target=_run_rst_server, args=(port + 2,), daemon=True).start()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            break
        except Exception:
            time.sleep(0.2)

    # Brief pause so TCP servers finish binding
    time.sleep(0.15)
    return server


if __name__ == "__main__":
    import sys as _sys
    _port = int(_sys.argv[1]) if len(_sys.argv) > 1 else 3000
    _tcp_echo_port = _port + 1
    _tcp_rst_port = _port + 2
    _shutdown.clear()
    threading.Thread(target=_run_echo_server, args=(_port + 1,), daemon=True).start()
    threading.Thread(target=_run_rst_server, args=(_port + 2,), daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=_port)
