#!/usr/bin/env python3
"""Functional check of the XDP connection limit, run on the runner against the VM.

run-in-vm.sh starts an echo server on :18080 (client closes) and a server on
:18081 that closes after 0.2s (server closes), with XDP_CONN_LIMIT=20 and the
VM's gateway (where port-forwarded connections come from) not whitelisted.
"""
import re
import socket
import sys
import time
import urllib.request

METRICS_URL = "http://127.0.0.1:9100/metrics"
ECHO_PORT = 18080
SERVER_CLOSE_PORT = 18081
CONN_LIMIT = 20
SEQUENTIAL = 50
STATS_INTERVAL = 12  # Beeward refreshes XDP metrics every 10s


def metric(name, labels=""):
    with urllib.request.urlopen(METRICS_URL, timeout=5) as resp:
        text = resp.read().decode()
    m = re.search(rf'^{name}(\{{{re.escape(labels)}\}})? (\S+)$', text, re.M)
    return float(m.group(2)) if m else 0.0


def echo_connection():
    """Open a connection to the echo server; None if XDP blocked it.

    QEMU accepts the host side immediately, so a dropped SYN in the VM shows
    up as no echo (timeout or EOF) rather than a failed connect.
    """
    s = socket.create_connection(("127.0.0.1", ECHO_PORT), timeout=5)
    try:
        s.sendall(b"x")
        if s.recv(1) == b"x":
            return s
    except OSError:
        pass
    s.close()
    return None


def server_closed_connection():
    s = socket.create_connection(("127.0.0.1", SERVER_CLOSE_PORT), timeout=5)
    try:
        return s.recv(1) == b""  # EOF: the server closed first
    except OSError:
        return False
    finally:
        s.close()


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    # Wait for the servers and the XDP program to come up
    for _ in range(60):
        s = echo_connection()
        if s:
            s.close()
            break
        time.sleep(2)
    else:
        fail("echo server not reachable")

    # Phase 1: far more connections than the limit, one at a time, must never trip it
    for i in range(SEQUENTIAL):
        s = echo_connection()
        if not s:
            fail(f"client-closed connection {i + 1} was blocked")
        s.close()
    for i in range(SEQUENTIAL):
        if not server_closed_connection():
            fail(f"server-closed connection {i + 1} was blocked")

    time.sleep(STATS_INTERVAL)
    tracked = metric("xdp_ratelimit_map_entries", 'map="conn_track"')
    adds = metric("xdp_ratelimit_blacklist_adds")
    print(f"after {2 * SEQUENTIAL} sequential connections: tracked={tracked:.0f} blacklist_adds={adds:.0f}")
    if adds != 0:
        fail("sequential connections got the client blacklisted")
    if tracked != 0:
        fail("closed connections are still tracked")

    # Phase 2: exactly CONN_LIMIT concurrent connections fit, one more is blocked.
    # Short-lived connections in between must not count down the held ones
    # (a close used to be counted twice when both sides sent FIN).
    def hold(n):
        for _ in range(n):
            s = echo_connection()
            if not s:
                fail(f"concurrent connection {len(held) + 1} of {CONN_LIMIT} was blocked")
            held.append(s)

    held = []
    hold(CONN_LIMIT // 2)
    for _ in range(15):
        s = echo_connection()
        if not s:
            fail("short-lived connection was blocked")
        s.close()
        if not server_closed_connection():
            fail("short-lived server-closed connection was blocked")
    hold(CONN_LIMIT - len(held))
    if echo_connection():
        fail(f"connection {CONN_LIMIT + 1} was allowed while {CONN_LIMIT} were open")

    time.sleep(STATS_INTERVAL)
    adds = metric("xdp_ratelimit_blacklist_adds")
    dropped = metric("xdp_ratelimit_packets", 'action="drop_conn_limit"')
    print(f"after {CONN_LIMIT + 1} concurrent connections: blacklist_adds={adds:.0f} drop_conn_limit={dropped:.0f}")
    if adds < 1 or dropped < 1:
        fail("over-limit connection was not dropped and blacklisted")

    print("PASS: sequential connections never trip the limit; the limit blocks the extra concurrent one")


if __name__ == "__main__":
    main()
