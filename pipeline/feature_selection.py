from __future__ import annotations


BASELINE_DROP_EXACT = {
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "total_bytes",
    "total_pkts",
    "bytes_per_second",
    "pkts_per_second",
    "dst_port",
    "http_status_code",
    "dns_qtype",
    "dns_rcode",
}

BASELINE_DROP_WINDOW_TOKENS = (
    "conn_count",
    "failed_conn_count",
    "unique_dst_ips",
    "unique_dst_ports",
    "unique_src_ips",
    "total_bytes",
    "total_pkts",
    "http_count",
    "http_error_count",
    "http_post_count",
    "http_post_error_count",
)


def is_window_feature(name: str) -> bool:
    return name.endswith("_60s") or name.endswith("_300s")


def is_ratio_feature(name: str) -> bool:
    return name.endswith("_ratio") or "_ratio_" in name or name.endswith("_per_conn_60s") or name.endswith("_per_conn_300s")


def is_baseline_feature(name: str) -> bool:
    if name in BASELINE_DROP_EXACT:
        return False
    if is_window_feature(name) and not is_ratio_feature(name):
        return not any(token in name for token in BASELINE_DROP_WINDOW_TOKENS)
    return True


def select_baseline_features(features: dict) -> dict:
    return {
        key: value
        for key, value in features.items()
        if is_baseline_feature(key)
    }
