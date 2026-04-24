from __future__ import annotations

import random
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scapy.all import DNS, DNSQR, DNSRR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap
from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS

BASE_TS = 1_717_000_000.0
DEFAULT_SEED = 1337
HTTP_HOST = "intranet.local"
GATEWAY_HOST = "gateway.local"

HOSTS = {
    "pc_admin": {"ip": "192.168.50.10", "mac": "02:50:00:00:00:10"},
    "pc_dev": {"ip": "192.168.50.11", "mac": "02:50:00:00:00:11"},
    "pc_rrhh": {"ip": "192.168.50.12", "mac": "02:50:00:00:00:12"},
    "srv_web": {"ip": "192.168.50.1", "mac": "02:50:00:00:00:01"},
    "srv_dns": {"ip": "192.168.50.2", "mac": "02:50:00:00:00:02"},
    "gateway": {"ip": "192.168.50.254", "mac": "02:50:00:00:00:fe"},
    "attacker": {"ip": "10.0.0.99", "mac": "02:0a:00:00:00:63"},
}

HTTP_ROUTES = {
    "/": ("GET", 200, "text/html", 2048, 0),
    "/dashboard": ("GET", 200, "text/html", 4096, 0),
    "/reports/q1.pdf": ("GET", 200, "application/pdf", 32_768, 0),
    "/api/v1/status": ("GET", 200, "application/json", 640, 0),
    "/api/v1/deploy": ("POST", 202, "application/json", 512, 640),
    "/files/nominas.xlsx": ("GET", 200, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 98_304, 0),
    "/upload": ("POST", 201, "application/json", 384, 48_000),
    "/login": ("POST", 401, "application/json", 192, 92),
    "/sync": ("POST", 201, "application/json", 256, 0),
}

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EZEK13L/1.0",
    "Mozilla/5.0 (X11; Linux x86_64) EZEK13L/1.0",
    "curl/8.7.1",
    "python-requests/2.32.3",
)

DNS_RESPONSES = {
    "intranet.local": "192.168.50.1",
    "mail.empresa.com": "203.0.113.10",
    "google.com": "142.250.184.14",
    "registry.npmjs.org": "104.16.27.34",
    "api.github.com": "140.82.121.6",
    "outlook.office365.com": "52.96.164.34",
    "login.microsoftonline.com": "20.190.129.10",
}

NORMAL_BUILDERS: list[tuple[float, Callable[[float, random.Random], tuple[list, float]]]] = []


def host(name: str) -> dict:
    return HOSTS[name]


def path_bytes(seed_text: str, size: int) -> bytes:
    if size <= 0:
        return b""
    unit = (seed_text + "|EZEK13L|").encode("utf-8")
    return (unit * ((size // len(unit)) + 1))[:size]


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_packets(path: Path, packets: list) -> None:
    ensure_parent(path)
    ordered = sorted(packets, key=lambda pkt: float(getattr(pkt, "time", 0.0)))
    wrpcap(str(path), ordered)


def next_capture_name(outdir: Path, prefix: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    max_id = 0
    for candidate in outdir.glob(f"{prefix}_*.pcap"):
        try:
            max_id = max(max_id, int(candidate.stem.split("_")[-1]))
        except ValueError:
            continue
    return outdir / f"{prefix}_{max_id + 1:06d}.pcap"


def add_packet(packets: list, pkt, ts: float) -> None:
    pkt.time = round(float(ts), 6)
    packets.append(pkt)


def chunk_payload(payload: bytes, size: int) -> list[bytes]:
    if not payload:
        return []
    return [payload[index:index + size] for index in range(0, len(payload), size)]


def ip_pkt(src: dict, dst: dict, payload):
    return Ether(src=src["mac"], dst=dst["mac"]) / IP(src=src["ip"], dst=dst["ip"]) / payload


def http_status_line(status: int) -> str:
    mapping = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        304: "Not Modified",
        401: "Unauthorized",
    }
    return mapping.get(status, "OK")


def http_request_bytes(
    method: str,
    host_name: str,
    uri: str,
    body: bytes = b"",
    content_type: str = "application/x-www-form-urlencoded",
    user_agent: str = USER_AGENTS[0],
) -> bytes:
    headers = [
        f"{method} {uri} HTTP/1.1",
        f"Host: {host_name}",
        f"User-Agent: {user_agent}",
        "Accept: */*",
        "Connection: keep-alive",
    ]
    if body:
        headers.extend(
            [
                f"Content-Type: {content_type}",
                f"Content-Length: {len(body)}",
            ]
        )
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body


def http_response_bytes(status: int, body: bytes = b"", content_type: str = "text/html") -> bytes:
    headers = [
        f"HTTP/1.1 {status} {http_status_line(status)}",
        "Server: ezek13l-lab/1.0",
        f"Content-Length: {len(body)}",
        f"Content-Type: {content_type}",
        "Connection: close",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body


@dataclass
class TcpConversation:
    packets: list
    client: dict
    server: dict
    client_port: int
    server_port: int
    client_seq: int
    server_seq: int
    ts: float

    @classmethod
    def start(
        cls,
        packets: list,
        client: dict,
        server: dict,
        client_port: int,
        server_port: int,
        ts: float,
        rng: random.Random,
    ) -> "TcpConversation":
        client_seq = rng.randint(10_000, 900_000_000)
        server_seq = rng.randint(10_000, 900_000_000)
        add_packet(
            packets,
            ip_pkt(client, server, TCP(sport=client_port, dport=server_port, flags="S", seq=client_seq)),
            ts,
        )
        ts += 0.002
        add_packet(
            packets,
            ip_pkt(server, client, TCP(sport=server_port, dport=client_port, flags="SA", seq=server_seq, ack=client_seq + 1)),
            ts,
        )
        ts += 0.002
        add_packet(
            packets,
            ip_pkt(client, server, TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq + 1, ack=server_seq + 1)),
            ts,
        )
        return cls(
            packets=packets,
            client=client,
            server=server,
            client_port=client_port,
            server_port=server_port,
            client_seq=client_seq + 1,
            server_seq=server_seq + 1,
            ts=ts + 0.002,
        )

    def _send(self, from_client: bool, payload: bytes, segment_size: int = 1200, spacing: float = 0.0015) -> None:
        if not payload:
            return

        sender = self.client if from_client else self.server
        receiver = self.server if from_client else self.client
        sport = self.client_port if from_client else self.server_port
        dport = self.server_port if from_client else self.client_port
        seq = self.client_seq if from_client else self.server_seq
        ack = self.server_seq if from_client else self.client_seq

        for chunk in chunk_payload(payload, segment_size):
            add_packet(
                self.packets,
                ip_pkt(sender, receiver, TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack) / Raw(load=chunk)),
                self.ts,
            )
            seq += len(chunk)
            self.ts += spacing
            add_packet(
                self.packets,
                ip_pkt(receiver, sender, TCP(sport=dport, dport=sport, flags="A", seq=ack, ack=seq)),
                self.ts,
            )
            self.ts += spacing

        if from_client:
            self.client_seq = seq
        else:
            self.server_seq = seq

    def client_data(self, payload: bytes, segment_size: int = 1200, spacing: float = 0.0015) -> None:
        self._send(True, payload, segment_size=segment_size, spacing=spacing)

    def server_data(self, payload: bytes, segment_size: int = 1200, spacing: float = 0.0015) -> None:
        self._send(False, payload, segment_size=segment_size, spacing=spacing)

    def close(self, active_close: str = "client") -> None:
        if active_close == "server":
            first, second = False, True
        else:
            first, second = True, False

        self._fin(from_client=first)
        self._fin(from_client=second)

    def _fin(self, from_client: bool) -> None:
        sender = self.client if from_client else self.server
        receiver = self.server if from_client else self.client
        sport = self.client_port if from_client else self.server_port
        dport = self.server_port if from_client else self.client_port
        seq = self.client_seq if from_client else self.server_seq
        ack = self.server_seq if from_client else self.client_seq

        add_packet(
            self.packets,
            ip_pkt(sender, receiver, TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=ack)),
            self.ts,
        )
        seq += 1
        self.ts += 0.002
        add_packet(
            self.packets,
            ip_pkt(receiver, sender, TCP(sport=dport, dport=sport, flags="A", seq=ack, ack=seq)),
            self.ts,
        )
        self.ts += 0.002

        if from_client:
            self.client_seq = seq
        else:
            self.server_seq = seq


def generate_dns_query(
    src: dict,
    dns_server: dict,
    domain: str,
    ts: float,
    rng: random.Random,
    answer: str | None = None,
    nx_domain: bool = False,
    qtype: str = "A",
) -> tuple[list, float]:
    packets: list = []
    query_id = rng.randint(0, 65535)
    sport = rng.randint(20_000, 60_000)

    query = DNS(id=query_id, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    add_packet(packets, ip_pkt(src, dns_server, UDP(sport=sport, dport=53) / query), ts)
    ts += 0.01

    response = DNS(
        id=query_id,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname=domain, qtype=qtype),
        rcode=3 if nx_domain else 0,
    )
    if not nx_domain and answer:
        response.an = DNSRR(rrname=domain, ttl=180, type=qtype, rdata=answer)
        response.ancount = 1

    add_packet(packets, ip_pkt(dns_server, src, UDP(sport=53, dport=sport) / response), ts)
    return packets, ts + 0.02


def generate_http_conn(
    src: dict,
    server: dict,
    uri: str,
    method: str,
    status: int,
    ts: float,
    rng: random.Random,
    request_body: bytes = b"",
    response_body: bytes = b"",
    host_name: str = HTTP_HOST,
    content_type: str = "text/html",
) -> tuple[list, float]:
    packets: list = []
    sport = rng.randint(20_000, 60_000)
    conv = TcpConversation.start(packets, src, server, sport, 80, ts, rng)
    conv.client_data(
        http_request_bytes(
            method=method,
            host_name=host_name,
            uri=uri,
            body=request_body,
            content_type="application/json" if uri.startswith("/api/") else "application/x-www-form-urlencoded",
            user_agent=rng.choice(USER_AGENTS),
        )
    )
    conv.server_data(http_response_bytes(status=status, body=response_body, content_type=content_type))
    conv.close(active_close="server")
    return packets, conv.ts + 0.02


def generate_tls_conn(src: dict, gateway: dict, sni: str, ts: float, rng: random.Random) -> tuple[list, float]:
    packets: list = []
    sport = rng.randint(20_000, 60_000)
    conv = TcpConversation.start(packets, src, gateway, sport, 443, ts, rng)
    client_hello = TLS(
        msg=[
            TLSClientHello(
                gmt_unix_time=int(ts),
                ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode("utf-8"))])],
            )
        ]
    )
    server_hello = TLS(msg=[TLSServerHello(version=0x0303, sid=b"EZEK13L", cipher=0x1301, comp=0)])
    conv.client_data(bytes(client_hello), segment_size=512)
    conv.server_data(bytes(server_hello), segment_size=512)
    conv.close(active_close="server")
    return packets, conv.ts + 0.02


def generate_icmp_ping(src: dict, dst: dict, ts: float, rng: random.Random) -> tuple[list, float]:
    packets: list = []
    icmp_id = rng.randint(0, 65535)
    seq = rng.randint(1, 1024)
    payload = path_bytes(f"{src['ip']}->{dst['ip']}", 48)
    add_packet(
        packets,
        ip_pkt(src, dst, ICMP(type="echo-request", id=icmp_id, seq=seq) / Raw(load=payload)),
        ts,
    )
    ts += 0.01
    add_packet(
        packets,
        ip_pkt(dst, src, ICMP(type="echo-reply", id=icmp_id, seq=seq) / Raw(load=payload)),
        ts,
    )
    return packets, ts + 0.02


def generate_port_scan(ts: float, rng: random.Random, ports: int = 50) -> tuple[list, float]:
    packets: list = []
    src = host("attacker")
    dst = host("srv_web")
    port_list = list(range(20, 20 + ports))
    for index, port in enumerate(port_list):
        sport = 35_000 + index
        add_packet(packets, ip_pkt(src, dst, TCP(sport=sport, dport=port, flags="S", seq=10_000 + index)), ts)
        ts += 0.015
        add_packet(
            packets,
            ip_pkt(dst, src, TCP(sport=port, dport=sport, flags="RA", seq=50_000 + index, ack=10_001 + index)),
            ts,
        )
        ts += 0.03
    return packets, ts + 0.1


def entropy_label(rng: random.Random, length: int) -> str:
    alphabet = string.ascii_letters + string.digits + "+/"
    return "".join(rng.choice(alphabet) for _ in range(length))


def generate_dns_exfil(ts: float, rng: random.Random, queries: int = 24) -> tuple[list, float]:
    packets: list = []
    src = host("pc_dev")
    dns_server = host("srv_dns")
    for _ in range(queries):
        label_a = entropy_label(rng, 18)
        label_b = entropy_label(rng, 18)
        label_c = entropy_label(rng, 14)
        domain = f"{label_a}.{label_b}.{label_c}.sync.ops.a1.evil-c2.com"
        rows, ts = generate_dns_query(src, dns_server, domain, ts, rng, nx_domain=True)
        packets.extend(rows)
        ts += 0.02
    return packets, ts + 0.1


def generate_bruteforce_http(ts: float, rng: random.Random, attempts: int = 40) -> tuple[list, float]:
    packets: list = []
    src = host("attacker")
    server = host("srv_web")
    for attempt in range(attempts):
        password = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(10))
        body = f"username=admin&password={password}&attempt={attempt}".encode("utf-8")
        rows, ts = generate_http_conn(
            src=src,
            server=server,
            uri="/login",
            method="POST",
            status=401,
            ts=ts,
            rng=rng,
            request_body=body,
            response_body=b'{"ok":false,"reason":"invalid"}',
            host_name=HTTP_HOST,
            content_type="application/json",
        )
        packets.extend(rows)
        ts += 0.08
    return packets, ts + 0.1


def generate_sql_injection(ts: float, rng: random.Random, attempts: int = 8) -> tuple[list, float]:
    packets: list = []
    src = host("attacker")
    server = host("srv_web")
    payloads = (
        "/reports?id=10%20UNION%20SELECT%20user,password%20FROM%20users",
        "/dashboard?filter=%27%20OR%201=1--",
        "/api/v1/status?id=1;SELECT%20*%20FROM%20information_schema.tables",
        "/login?user=admin%27%20AND%20sleep(5)--",
    )
    for index in range(attempts):
        uri = payloads[index % len(payloads)]
        rows, ts = generate_http_conn(
            src=src,
            server=server,
            uri=uri,
            method="GET",
            status=200,
            ts=ts,
            rng=rng,
            response_body=b'{"ok":true}',
            host_name=HTTP_HOST,
            content_type="application/json",
        )
        packets.extend(rows)
        ts += 0.09
    return packets, ts + 0.1


def generate_data_exfil(ts: float, rng: random.Random, body_size: int = 2_000_000) -> tuple[list, float]:
    body = path_bytes("payroll-export", body_size)
    packets, end_ts = generate_http_conn(
        src=host("pc_rrhh"),
        server=host("gateway"),
        uri="/sync",
        method="POST",
        status=201,
        ts=ts,
        rng=rng,
        request_body=body,
        response_body=b'{"accepted":true}',
        host_name=GATEWAY_HOST,
        content_type="application/json",
    )
    return packets, end_ts + 0.1


def normal_admin_web(ts: float, rng: random.Random) -> tuple[list, float]:
    route = rng.choice(("/", "/dashboard", "/reports/q1.pdf"))
    method, status, content_type, response_size, request_size = HTTP_ROUTES[route]
    effective_status = 304 if route == "/dashboard" and rng.random() < 0.2 else status
    packets, end_ts = generate_http_conn(
        src=host("pc_admin"),
        server=host("srv_web"),
        uri=route,
        method=method,
        status=effective_status,
        ts=ts,
        rng=rng,
        request_body=path_bytes("admin", request_size),
        response_body=path_bytes(route, 0 if effective_status == 304 else response_size),
        host_name=HTTP_HOST,
        content_type=content_type,
    )
    return packets, end_ts


def normal_admin_dns(ts: float, rng: random.Random) -> tuple[list, float]:
    domain = rng.choice(("intranet.local", "mail.empresa.com", "google.com"))
    return generate_dns_query(host("pc_admin"), host("srv_dns"), domain, ts, rng, answer=DNS_RESPONSES[domain])


def normal_dev_api(ts: float, rng: random.Random) -> tuple[list, float]:
    route = rng.choice(("/api/v1/status", "/api/v1/deploy"))
    method, status, content_type, response_size, request_size = HTTP_ROUTES[route]
    request_body = b""
    if method == "POST":
        request_body = path_bytes("deploy", request_size)
    return generate_http_conn(
        src=host("pc_dev"),
        server=host("srv_web"),
        uri=route,
        method=method,
        status=status,
        ts=ts,
        rng=rng,
        request_body=request_body,
        response_body=path_bytes(route, response_size),
        host_name=HTTP_HOST,
        content_type=content_type,
    )


def normal_dev_tls(ts: float, rng: random.Random) -> tuple[list, float]:
    return generate_tls_conn(host("pc_dev"), host("gateway"), rng.choice(("github.com", "stackoverflow.com", "docs.python.org")), ts, rng)


def normal_dev_dns(ts: float, rng: random.Random) -> tuple[list, float]:
    domain = rng.choice(("registry.npmjs.org", "api.github.com"))
    return generate_dns_query(host("pc_dev"), host("srv_dns"), domain, ts, rng, answer=DNS_RESPONSES[domain])


def normal_rrhh_files(ts: float, rng: random.Random) -> tuple[list, float]:
    route = rng.choice(("/files/nominas.xlsx", "/upload"))
    method, status, content_type, response_size, request_size = HTTP_ROUTES[route]
    return generate_http_conn(
        src=host("pc_rrhh"),
        server=host("srv_web"),
        uri=route,
        method=method,
        status=status,
        ts=ts,
        rng=rng,
        request_body=path_bytes("upload", request_size),
        response_body=path_bytes(route, response_size),
        host_name=HTTP_HOST,
        content_type=content_type,
    )


def normal_rrhh_dns(ts: float, rng: random.Random) -> tuple[list, float]:
    domain = rng.choice(("outlook.office365.com", "login.microsoftonline.com"))
    return generate_dns_query(host("pc_rrhh"), host("srv_dns"), domain, ts, rng, answer=DNS_RESPONSES[domain])


def normal_ping(ts: float, rng: random.Random) -> tuple[list, float]:
    pair = rng.choice(
        (
            ("pc_admin", "srv_web"),
            ("pc_admin", "pc_dev"),
            ("pc_dev", "srv_web"),
            ("pc_rrhh", "gateway"),
        )
    )
    return generate_icmp_ping(host(pair[0]), host(pair[1]), ts, rng)


NORMAL_BUILDERS = [
    (0.22, normal_admin_web),
    (0.12, normal_admin_dns),
    (0.18, normal_dev_api),
    (0.12, normal_dev_tls),
    (0.10, normal_dev_dns),
    (0.16, normal_rrhh_files),
    (0.07, normal_rrhh_dns),
    (0.03, normal_ping),
]


def weighted_builder(rng: random.Random) -> Callable[[float, random.Random], tuple[list, float]]:
    weights = [item[0] for item in NORMAL_BUILDERS]
    builders = [item[1] for item in NORMAL_BUILDERS]
    return rng.choices(builders, weights=weights, k=1)[0]


def build_normal_traffic(connections: int, duration_seconds: float, rng: random.Random, start_ts: float = BASE_TS) -> list:
    packets: list = []
    if connections <= 0:
        return packets

    step = max(float(duration_seconds) / max(connections, 1), 0.02)
    for index in range(connections):
        ts = start_ts + (index * step) + rng.uniform(0.0, step * 0.35)
        builder = weighted_builder(rng)
        built, _ = builder(ts, rng)
        packets.extend(built)
    return sorted(packets, key=lambda pkt: float(getattr(pkt, "time", 0.0)))


ATTACK_BUILDERS = {
    "1": ("Port Scan", generate_port_scan),
    "2": ("DNS Exfiltration", generate_dns_exfil),
    "3": ("Brute Force HTTP", generate_bruteforce_http),
    "4": ("SQL Injection", generate_sql_injection),
    "5": ("Data Exfiltration", generate_data_exfil),
}
