import argparse
import json
import math
from collections import Counter, defaultdict, deque
from pathlib import Path


CONN_STATES = ("SF", "S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3", "SH", "SHR", "OTH")
HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS")
TLS_VERSIONS = ("TLSv10", "TLSv11", "TLSv12", "TLSv13", "SSLv3")

def load_jsonl(path: Path):
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def num(value, default=0.0):
    try:
        if value in (None, "-", ""):
            return default
        return float(value)
    except Exception:
        return default


def truthy(value):
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    return 1.0 if str(value).lower() in {"true", "t", "yes", "1"} else 0.0


def text(value):
    if value in (None, "-"):
        return ""
    return str(value)


def safe_div(a, b):
    return float(a) / float(b) if b else 0.0


def log1p(value):
    return math.log1p(max(float(value), 0.0))


def count_items(value):
    if value in (None, "-", ""):
        return 0.0
    if isinstance(value, list):
        return float(len(value))
    return float(len([p for p in str(value).split(",") if p]))


def entropy(value):
    value = text(value)
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def max_feature(features, key, value):
    features[key] = max(features.get(key, 0.0), float(value))


def add_feature(features, key, value):
    features[key] = features.get(key, 0.0) + float(value)


def empty_http_features():
    features = {
        "http_tx_count": 0.0,
        "http_status_code": 0.0,
        "http_status_2xx": 0.0,
        "http_status_3xx": 0.0,
        "http_status_4xx": 0.0,
        "http_status_5xx": 0.0,
        "http_uri_len_max": 0.0,
        "http_uri_entropy_max": 0.0,
        "http_query_len_max": 0.0,
        "http_param_count_max": 0.0,
        "http_path_depth_max": 0.0,
        "http_alpha_count_max": 0.0,
        "http_digit_count_max": 0.0,
        "http_special_char_count_max": 0.0,
        "http_symbol_ratio_max": 0.0,
        "http_percent_encoding_count_max": 0.0,
        "http_host_len_max": 0.0,
        "http_user_agent_len_max": 0.0,
        "http_request_body_len": 0.0,
        "http_response_body_len": 0.0,
    }
    for method in HTTP_METHODS:
        features[f"http_method_{method.lower()}"] = 0.0
    return features


def empty_dns_features():
    return {
        "dns_tx_count": 0.0,
        "dns_query_len_max": 0.0,
        "dns_query_entropy_max": 0.0,
        "dns_label_count_max": 0.0,
        "dns_answer_count_max": 0.0,
        "dns_qtype": 0.0,
        "dns_rcode": 0.0,
        "dns_nxdomain": 0.0,
        "dns_rejected": 0.0,
    }


def empty_tls_features():
    features = {
        "tls_tx_count": 0.0,
        "tls_sni_len_max": 0.0,
        "tls_established": 0.0,
        "tls_resumed": 0.0,
        "tls_ja3_present": 0.0,
    }
    for version in TLS_VERSIONS:
        features[f"tls_version_{version.lower()}"] = 0.0
    return features


def build_http_index(rows):
    by_uid = defaultdict(empty_http_features)
    for row in rows:
        uid = row.get("uid")
        if not uid:
            continue
        features = by_uid[uid]
        add_feature(features, "http_tx_count", 1.0)

        method = text(row.get("method")).upper()
        if method in HTTP_METHODS:
            features[f"http_method_{method.lower()}"] = 1.0

        status = int(num(row.get("status_code")))
        if status:
            max_feature(features, "http_status_code", status)
            if 200 <= status < 300:
                features["http_status_2xx"] = 1.0
            elif 300 <= status < 400:
                features["http_status_3xx"] = 1.0
            elif 400 <= status < 500:
                features["http_status_4xx"] = 1.0
            elif status >= 500:
                features["http_status_5xx"] = 1.0

        uri = text(row.get("uri"))
        query = uri.split("?", 1)[1] if "?" in uri else ""
        special_chars = sum(uri.count(ch) for ch in "'\"<>(){}[];")
        alpha_chars = sum(1 for ch in uri if ch.isalpha())
        digit_chars = sum(1 for ch in uri if ch.isdigit())

        max_feature(features, "http_uri_len_max", len(uri))
        max_feature(features, "http_uri_entropy_max", entropy(uri))
        max_feature(features, "http_query_len_max", len(query))
        max_feature(features, "http_param_count_max", query.count("=") + query.count("&"))
        max_feature(features, "http_path_depth_max", uri.count("/"))
        max_feature(features, "http_alpha_count_max", alpha_chars)
        max_feature(features, "http_digit_count_max", digit_chars)
        max_feature(features, "http_special_char_count_max", special_chars)
        max_feature(features, "http_symbol_ratio_max", safe_div(special_chars + uri.count("%"), len(uri)))
        max_feature(features, "http_percent_encoding_count_max", uri.count("%"))
        max_feature(features, "http_host_len_max", len(text(row.get("host"))))
        max_feature(features, "http_user_agent_len_max", len(text(row.get("user_agent"))))

        add_feature(features, "http_request_body_len", num(row.get("request_body_len")))
        add_feature(features, "http_response_body_len", num(row.get("response_body_len")))
    return by_uid


def build_dns_index(rows):
    by_uid = defaultdict(empty_dns_features)
    for row in rows:
        uid = row.get("uid")
        if not uid:
            continue
        features = by_uid[uid]
        query = text(row.get("query"))
        add_feature(features, "dns_tx_count", 1.0)
        max_feature(features, "dns_query_len_max", len(query))
        max_feature(features, "dns_query_entropy_max", entropy(query))
        max_feature(features, "dns_label_count_max", len([p for p in query.split(".") if p]))
        max_feature(features, "dns_answer_count_max", count_items(row.get("answers")))
        max_feature(features, "dns_qtype", num(row.get("qtype")))
        max_feature(features, "dns_rcode", num(row.get("rcode")))
        if text(row.get("rcode_name")).upper() == "NXDOMAIN":
            features["dns_nxdomain"] = 1.0
        features["dns_rejected"] = max(features["dns_rejected"], truthy(row.get("rejected")))
    return by_uid


def build_tls_index(rows):
    by_uid = defaultdict(empty_tls_features)
    for row in rows:
        uid = row.get("uid")
        if not uid:
            continue
        features = by_uid[uid]
        add_feature(features, "tls_tx_count", 1.0)
        server_name = text(row.get("server_name"))
        max_feature(features, "tls_sni_len_max", len(server_name))
        features["tls_established"] = max(features["tls_established"], truthy(row.get("established")))
        features["tls_resumed"] = max(features["tls_resumed"], truthy(row.get("resumed")))
        features["tls_ja3_present"] = max(features["tls_ja3_present"], 1.0 if text(row.get("ja3")) else 0.0)

        version = text(row.get("version"))
        if version in TLS_VERSIONS:
            features[f"tls_version_{version.lower()}"] = 1.0
    return by_uid


class WindowStats:
    def __init__(self, seconds):
        self.seconds = seconds
        self.events = deque()
        self.src_count = Counter()
        self.src_failed = Counter()
        self.dst_count = Counter()
        self.pair_count = Counter()
        self.src_bytes = Counter()
        self.src_pkts = Counter()
        self.dst_bytes = Counter()
        self.dst_pkts = Counter()
        self.src_http = Counter()
        self.src_http_error = Counter()
        self.src_http_post = Counter()
        self.src_http_post_error = Counter()
        self.pair_http = Counter()
        self.pair_http_error = Counter()
        self.pair_http_post = Counter()
        self.pair_http_post_error = Counter()
        self.src_dst_ips = defaultdict(Counter)
        self.src_dst_ports = defaultdict(Counter)
        self.dst_src_ips = defaultdict(Counter)

    def _dec(self, counter, key, amount=1.0):
        counter[key] -= amount
        if counter[key] <= 0:
            del counter[key]

    def _dec_nested(self, nested, key, subkey):
        nested[key][subkey] -= 1
        if nested[key][subkey] <= 0:
            del nested[key][subkey]
        if not nested[key]:
            del nested[key]

    def evict(self, ts):
        cutoff = ts - self.seconds
        while self.events and self.events[0]["ts"] < cutoff:
            event = self.events.popleft()
            src = event["src_ip"]
            dst = event["dst_ip"]
            dport = event["dst_port"]
            pair = (src, dst)

            self._dec(self.src_count, src)
            self._dec(self.dst_count, dst)
            self._dec(self.pair_count, pair)
            self._dec(self.src_bytes, src, event["total_bytes"])
            self._dec(self.src_pkts, src, event["total_pkts"])
            self._dec(self.dst_bytes, dst, event["total_bytes"])
            self._dec(self.dst_pkts, dst, event["total_pkts"])
            if event["failed"]:
                self._dec(self.src_failed, src)
            if event["http"]:
                self._dec(self.src_http, src)
                self._dec(self.pair_http, pair)
            if event["http_error"]:
                self._dec(self.src_http_error, src)
                self._dec(self.pair_http_error, pair)
            if event["http_post"]:
                self._dec(self.src_http_post, src)
                self._dec(self.pair_http_post, pair)
            if event["http_post_error"]:
                self._dec(self.src_http_post_error, src)
                self._dec(self.pair_http_post_error, pair)
            self._dec_nested(self.src_dst_ips, src, dst)
            self._dec_nested(self.src_dst_ports, src, dport)
            self._dec_nested(self.dst_src_ips, dst, src)

    def snapshot(self, event):
        self.evict(event["ts"])
        src = event["src_ip"]
        dst = event["dst_ip"]
        pair = (src, dst)
        suffix = f"{self.seconds}s"
        src_count = float(self.src_count[src])
        dst_count = float(self.dst_count[dst])
        pair_count = float(self.pair_count[pair])
        src_http = float(self.src_http[src])
        pair_http = float(self.pair_http[pair])
        src_http_post = float(self.src_http_post[src])
        pair_http_post = float(self.pair_http_post[pair])
        src_failed = float(self.src_failed[src])
        src_bytes = float(self.src_bytes[src])
        src_pkts = float(self.src_pkts[src])
        dst_bytes = float(self.dst_bytes[dst])
        dst_pkts = float(self.dst_pkts[dst])
        src_unique_dst_ips = float(len(self.src_dst_ips[src]))
        src_unique_dst_ports = float(len(self.src_dst_ports[src]))
        dst_unique_src_ips = float(len(self.dst_src_ips[dst]))
        return {
            f"src_conn_count_{suffix}": src_count,
            f"src_failed_conn_count_{suffix}": src_failed,
            f"src_failed_conn_ratio_{suffix}": safe_div(src_failed, src_count),
            f"src_unique_dst_ips_{suffix}": src_unique_dst_ips,
            f"src_unique_dst_ip_ratio_{suffix}": safe_div(src_unique_dst_ips, src_count),
            f"src_unique_dst_ports_{suffix}": src_unique_dst_ports,
            f"src_unique_dst_port_ratio_{suffix}": safe_div(src_unique_dst_ports, src_count),
            f"src_total_bytes_{suffix}": src_bytes,
            f"src_total_pkts_{suffix}": src_pkts,
            f"src_bytes_per_conn_{suffix}": safe_div(src_bytes, src_count),
            f"src_pkts_per_conn_{suffix}": safe_div(src_pkts, src_count),
            f"dst_conn_count_{suffix}": dst_count,
            f"dst_unique_src_ips_{suffix}": dst_unique_src_ips,
            f"dst_unique_src_ip_ratio_{suffix}": safe_div(dst_unique_src_ips, dst_count),
            f"dst_total_bytes_{suffix}": dst_bytes,
            f"dst_total_pkts_{suffix}": dst_pkts,
            f"dst_bytes_per_conn_{suffix}": safe_div(dst_bytes, dst_count),
            f"dst_pkts_per_conn_{suffix}": safe_div(dst_pkts, dst_count),
            f"pair_conn_count_{suffix}": pair_count,
            f"src_http_count_{suffix}": src_http,
            f"src_http_error_count_{suffix}": float(self.src_http_error[src]),
            f"src_http_error_ratio_{suffix}": safe_div(self.src_http_error[src], src_http),
            f"src_http_post_count_{suffix}": src_http_post,
            f"src_http_post_ratio_{suffix}": safe_div(src_http_post, src_http),
            f"src_http_post_error_count_{suffix}": float(self.src_http_post_error[src]),
            f"src_http_post_error_ratio_{suffix}": safe_div(self.src_http_post_error[src], src_http_post),
            f"pair_http_count_{suffix}": pair_http,
            f"pair_http_error_count_{suffix}": float(self.pair_http_error[pair]),
            f"pair_http_error_ratio_{suffix}": safe_div(self.pair_http_error[pair], pair_http),
            f"pair_http_post_count_{suffix}": pair_http_post,
            f"pair_http_post_ratio_{suffix}": safe_div(pair_http_post, pair_http),
            f"pair_http_post_error_count_{suffix}": float(self.pair_http_post_error[pair]),
            f"pair_http_post_error_ratio_{suffix}": safe_div(self.pair_http_post_error[pair], pair_http_post),
        }

    def add(self, event):
        src = event["src_ip"]
        dst = event["dst_ip"]
        dport = event["dst_port"]
        pair = (src, dst)
        self.events.append(event)
        self.src_count[src] += 1
        self.dst_count[dst] += 1
        self.pair_count[pair] += 1
        self.src_bytes[src] += event["total_bytes"]
        self.src_pkts[src] += event["total_pkts"]
        self.dst_bytes[dst] += event["total_bytes"]
        self.dst_pkts[dst] += event["total_pkts"]
        if event["failed"]:
            self.src_failed[src] += 1
        if event["http"]:
            self.src_http[src] += 1
            self.pair_http[pair] += 1
        if event["http_error"]:
            self.src_http_error[src] += 1
            self.pair_http_error[pair] += 1
        if event["http_post"]:
            self.src_http_post[src] += 1
            self.pair_http_post[pair] += 1
        if event["http_post_error"]:
            self.src_http_post_error[src] += 1
            self.pair_http_post_error[pair] += 1
        self.src_dst_ips[src][dst] += 1
        self.src_dst_ports[src][dport] += 1
        self.dst_src_ips[dst][src] += 1


def build_base_features(row, http_uids, dns_uids, tls_uids):
    uid = row.get("uid")
    proto = text(row.get("proto")).lower()
    state = text(row.get("conn_state")).upper()
    service = text(row.get("service")).lower()

    duration = max(num(row.get("duration")), 0.0)
    orig_bytes = max(num(row.get("orig_bytes")), 0.0)
    resp_bytes = max(num(row.get("resp_bytes")), 0.0)
    orig_pkts = max(num(row.get("orig_pkts")), 0.0)
    resp_pkts = max(num(row.get("resp_pkts")), 0.0)
    orig_ip_bytes = max(num(row.get("orig_ip_bytes")), 0.0)
    resp_ip_bytes = max(num(row.get("resp_ip_bytes")), 0.0)
    missed_bytes = max(num(row.get("missed_bytes")), 0.0)

    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts
    duration_floor = duration if duration > 0 else 0.001

    features = {
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_ip_bytes,
        "resp_ip_bytes": resp_ip_bytes,
        "missed_bytes": missed_bytes,
        "dst_port": max(num(row.get("id.resp_p")), 0.0),
        "total_bytes": total_bytes,
        "total_pkts": total_pkts,
        "bytes_per_pkt": safe_div(total_bytes, total_pkts),
        "orig_resp_byte_ratio": safe_div(orig_bytes, resp_bytes + 1.0),
        "resp_orig_byte_ratio": safe_div(resp_bytes, orig_bytes + 1.0),
        "orig_resp_pkt_ratio": safe_div(orig_pkts, resp_pkts + 1.0),
        "bytes_per_second": safe_div(total_bytes, duration_floor),
        "pkts_per_second": safe_div(total_pkts, duration_floor),
        "log_duration": log1p(duration),
        "log_orig_bytes": log1p(orig_bytes),
        "log_resp_bytes": log1p(resp_bytes),
        "log_total_bytes": log1p(total_bytes),
        "log_total_pkts": log1p(total_pkts),
        "proto_tcp": 1.0 if proto == "tcp" else 0.0,
        "proto_udp": 1.0 if proto == "udp" else 0.0,
        "proto_icmp": 1.0 if proto == "icmp" else 0.0,
        "proto_other": 1.0 if proto not in {"tcp", "udp", "icmp"} else 0.0,
        "svc_dns": 1.0 if uid in dns_uids or "dns" in service else 0.0,
        "svc_http": 1.0 if uid in http_uids or "http" in service else 0.0,
        "svc_tls": 1.0 if uid in tls_uids or "ssl" in service or "tls" in service else 0.0,
        "svc_other": 1.0 if service and service not in {"dns", "http", "ssl", "tls"} else 0.0,
    }

    for conn_state in CONN_STATES:
        features[f"state_{conn_state.lower()}"] = 1.0 if state == conn_state else 0.0

    return features


def event_from_row(row, features):
    state = text(row.get("conn_state")).upper()
    failed = state in {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR", "OTH"}
    return {
        "ts": num(row.get("ts")),
        "src_ip": text(row.get("id.orig_h")),
        "dst_ip": text(row.get("id.resp_h")),
        "dst_port": int(num(row.get("id.resp_p"))),
        "total_bytes": features["total_bytes"],
        "total_pkts": features["total_pkts"],
        "failed": failed,
        "http": features.get("http_tx_count", 0.0) > 0.0,
        "http_error": features.get("http_status_4xx", 0.0) > 0.0 or features.get("http_status_5xx", 0.0) > 0.0,
        "http_post": features.get("http_method_post", 0.0) > 0.0,
        "http_post_error": features.get("http_method_post", 0.0) > 0.0
        and (features.get("http_status_4xx", 0.0) > 0.0 or features.get("http_status_5xx", 0.0) > 0.0),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zeek-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--allow-empty", action="store_true")
    args = parser.parse_args()

    zeek_dir = Path(args.zeek_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    conn_path = zeek_dir / "conn.log"
    if not conn_path.exists() and not args.allow_empty:
        raise SystemExit(f"[ERROR] No existe conn.log en {zeek_dir}")

    dns_rows = load_jsonl(zeek_dir / "dns.log")
    http_rows = load_jsonl(zeek_dir / "http.log")
    tls_rows = load_jsonl(zeek_dir / "ssl.log") + load_jsonl(zeek_dir / "tls.log")
    conn_rows = sorted(load_jsonl(conn_path), key=lambda row: num(row.get("ts")))

    if not conn_rows and not args.allow_empty:
        raise SystemExit(f"[ERROR] conn.log no contiene conexiones en {zeek_dir}")

    dns_by_uid = build_dns_index(dns_rows)
    http_by_uid = build_http_index(http_rows)
    tls_by_uid = build_tls_index(tls_rows)

    dns_uids = set(dns_by_uid)
    http_uids = set(http_by_uid)
    tls_uids = set(tls_by_uid)

    windows = (WindowStats(60), WindowStats(300))
    written = 0

    with out_path.open("w", encoding="utf-8") as wf:
        for row in conn_rows:
            uid = row.get("uid")
            proto = text(row.get("proto")).lower()
            features = build_base_features(row, http_uids, dns_uids, tls_uids)
            features.update(empty_http_features())
            features.update(empty_dns_features())
            features.update(empty_tls_features())
            features.update(http_by_uid.get(uid, {}))
            features.update(dns_by_uid.get(uid, {}))
            features.update(tls_by_uid.get(uid, {}))

            event = event_from_row(row, features)
            for window in windows:
                features.update(window.snapshot(event))
            for window in windows:
                window.add(event)

            record = {
                "ts": event["ts"],
                "uid": uid,
                "proto": proto,
                "src_ip": event["src_ip"],
                "src_port": int(num(row.get("id.orig_p"))),
                "dst_ip": event["dst_ip"],
                "dst_port": event["dst_port"],
                "features": features,
            }
            wf.write(json.dumps(record) + "\n")
            written += 1

    print(f"[OK] {written} eventos con features creados en {out_path}")


if __name__ == "__main__":
    main()
