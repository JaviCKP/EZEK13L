"""
Blind Generalization Test — attack generators with parameters disjoint from training.

Same attack *types* as common.py but different IPs, ports, domains, endpoints, and
payloads. Used to measure whether the model detects attack behavior it has never
seen in the exact form it was trained on.
"""
from __future__ import annotations

import random
import string
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from scapy.all import TCP

from common import (
    add_packet,
    generate_dns_query,
    generate_http_conn,
    ip_pkt,
    path_bytes,
    write_packets,
    next_capture_name,
)

# ---------------------------------------------------------------------------
# Blind hosts — different IPs and MACs from the training topology
# ---------------------------------------------------------------------------

BLIND_ATTACKER = {"ip": "172.16.0.50", "mac": "02:ac:10:00:00:32"}
BLIND_C2 = {"ip": "172.16.0.51", "mac": "02:ac:10:00:00:33"}

# Reuse internal servers from the known topology as targets so Zeek/Suricata
# still sees recognisable internal traffic, but the *source* is unfamiliar.
from common import HOSTS as _HOSTS

_SRV_WEB = _HOSTS["srv_web"]
_SRV_DNS = _HOSTS["srv_dns"]
_PC_RRHH = _HOSTS["pc_rrhh"]

BLIND_HOST_HTTP = "intranet.local"
BLIND_HOST_BACKUP = "backup.external.net"

# ---------------------------------------------------------------------------
# Windows-service port set used by blind port scan — disjoint from 20..20+N
# ---------------------------------------------------------------------------

WINDOWS_PORTS = [
    135, 137, 139, 389, 443, 445, 636, 1433, 1521, 3306,
    3389, 5432, 5900, 5985, 8080, 8443, 9200, 27017, 49152, 49153,
]


def _blind_entropy_label(rng: random.Random, length: int) -> str:
    """Lower-entropy alphabet than the training generator (no '+/')."""
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Blind attack builders
# ---------------------------------------------------------------------------

def blind_port_scan(ts: float, rng: random.Random, ports: int = 50) -> tuple[list, float]:
    """SYN scan from 172.16.0.50 to Windows-service port set."""
    packets: list = []
    src = BLIND_ATTACKER
    dst = _SRV_WEB
    port_list = rng.sample(WINDOWS_PORTS * 3, min(ports, len(WINDOWS_PORTS * 3)))
    for index, port in enumerate(port_list):
        sport = 40_000 + index
        add_packet(packets, ip_pkt(src, dst, TCP(sport=sport, dport=port, flags="S", seq=20_000 + index)), ts)
        ts += 0.018
        add_packet(
            packets,
            ip_pkt(dst, src, TCP(sport=port, dport=sport, flags="RA", seq=60_000 + index, ack=20_001 + index)),
            ts,
        )
        ts += 0.025
    return packets, ts + 0.1


def blind_dns_exfil(ts: float, rng: random.Random, queries: int = 20) -> tuple[list, float]:
    """DNS exfiltration with shorter labels (12 chars), different C2 domain."""
    packets: list = []
    src = _HOSTS["pc_dev"]
    dns_server = _SRV_DNS
    for _ in range(queries):
        label_a = _blind_entropy_label(rng, 12)
        label_b = _blind_entropy_label(rng, 12)
        domain = f"{label_a}.{label_b}.static.cdn-update.net"
        rows, ts = generate_dns_query(src, dns_server, domain, ts, rng, nx_domain=True)
        packets.extend(rows)
        ts += 0.03
    return packets, ts + 0.1


def blind_bruteforce_http(ts: float, rng: random.Random, attempts: int = 35) -> tuple[list, float]:
    """Brute force against /api/auth/token with 8-char hex secrets."""
    packets: list = []
    src = BLIND_ATTACKER
    server = _SRV_WEB
    hex_chars = string.hexdigits[:16]
    for attempt in range(attempts):
        secret = "".join(rng.choice(hex_chars) for _ in range(8))
        body = f'{{"user":"svc","secret":"{secret}","attempt":{attempt}}}'.encode("utf-8")
        rows, ts = generate_http_conn(
            src=src,
            server=server,
            uri="/api/auth/token",
            method="POST",
            status=401,
            ts=ts,
            rng=rng,
            request_body=body,
            response_body=b'{"ok":false,"error":"unauthorized"}',
            host_name=BLIND_HOST_HTTP,
            content_type="application/json",
        )
        packets.extend(rows)
        ts += 0.06
    return packets, ts + 0.1


def blind_sql_injection(ts: float, rng: random.Random, attempts: int = 8) -> tuple[list, float]:
    """SQL injection with MSSQL-style payloads different from training UNION/OR set."""
    packets: list = []
    src = BLIND_ATTACKER
    server = _SRV_WEB
    payloads = (
        "/api/v1/status?id=1%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--",
        "/api/v1/status?id=1%3BEXEC%20xp_cmdshell(%27whoami%27)--",
        "/reports?filter=1%20AND%20CAST((SELECT%20TOP%201%20name%20FROM%20sysobjects)%20AS%20INT)--",
        "/dashboard?ref=%27%3B%20DROP%20TABLE%20users%3B--",
    )
    for index in range(attempts):
        uri = payloads[index % len(payloads)]
        rows, ts = generate_http_conn(
            src=src,
            server=server,
            uri=uri,
            method="GET",
            status=500,
            ts=ts,
            rng=rng,
            response_body=b'{"error":"internal server error"}',
            host_name=BLIND_HOST_HTTP,
            content_type="application/json",
        )
        packets.extend(rows)
        ts += 0.07
    return packets, ts + 0.1


def blind_data_exfil(ts: float, rng: random.Random, body_size: int = 250_000) -> tuple[list, float]:
    """Smaller but repeated data exfiltration to a different endpoint/host."""
    packets: list = []
    src = _PC_RRHH
    server = _SRV_WEB
    chunks = rng.randint(3, 6)
    for _ in range(chunks):
        body = path_bytes("employee-records", body_size)
        rows, ts = generate_http_conn(
            src=src,
            server=server,
            uri="/api/v2/upload",
            method="POST",
            status=200,
            ts=ts,
            rng=rng,
            request_body=body,
            response_body=b'{"status":"ok"}',
            host_name=BLIND_HOST_BACKUP,
            content_type="application/octet-stream",
        )
        packets.extend(rows)
        ts += 0.5
    return packets, ts + 0.1


# ---------------------------------------------------------------------------
# Builder registry — same keys/labels as ATTACK_BUILDERS in common.py
# ---------------------------------------------------------------------------

BLIND_ATTACK_BUILDERS: dict[str, tuple[str, callable]] = {
    "1": ("Port Scan", blind_port_scan),
    "2": ("DNS Exfiltration", blind_dns_exfil),
    "3": ("Brute Force HTTP", blind_bruteforce_http),
    "4": ("SQL Injection", blind_sql_injection),
    "5": ("Data Exfiltration", blind_data_exfil),
}
