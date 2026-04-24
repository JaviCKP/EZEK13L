from __future__ import annotations


def feature_value(features: dict, key: str) -> float:
    try:
        return float(features.get(key, 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def scan_pressure_boost(features: dict) -> tuple[float, list[str]]:
    ports_60 = feature_value(features, "src_unique_dst_ports_60s")
    ips_60 = feature_value(features, "src_unique_dst_ips_60s")
    failed_60 = feature_value(features, "src_failed_conn_count_60s")
    ports_300 = feature_value(features, "src_unique_dst_ports_300s")
    failed_300 = feature_value(features, "src_failed_conn_count_300s")

    factors: list[str] = []
    boost = 0.0

    if ports_60 >= 8 and failed_60 >= 4:
        pressure = max(
            clamp01((ports_60 - 8.0) / 15.0),
            clamp01((failed_60 - 4.0) / 10.0),
        )
        boost = max(boost, 0.12 + 0.12 * pressure)
        factors.append("scan_ports_60s")

    if ips_60 >= 15 and failed_60 >= 4:
        pressure = max(
            clamp01((ips_60 - 15.0) / 20.0),
            clamp01((failed_60 - 4.0) / 10.0),
        )
        boost = max(boost, 0.10 + 0.10 * pressure)
        factors.append("scan_ips_60s")

    if ports_300 >= 12 and failed_300 >= 6:
        pressure = max(
            clamp01((ports_300 - 12.0) / 15.0),
            clamp01((failed_300 - 6.0) / 12.0),
        )
        boost = max(boost, 0.08 + 0.08 * pressure)
        factors.append("scan_ports_300s")

    return boost, factors


def suspicious_http_boost(features: dict) -> tuple[float, list[str]]:
    if feature_value(features, "http_tx_count") <= 0.0:
        return 0.0, []

    uri_entropy = feature_value(features, "http_uri_entropy_max")
    query_len = feature_value(features, "http_query_len_max")
    param_count = feature_value(features, "http_param_count_max")
    special_chars = feature_value(features, "http_special_char_count_max")
    percent_encodings = feature_value(features, "http_percent_encoding_count_max")
    status_4xx = feature_value(features, "http_status_4xx")
    status_5xx = feature_value(features, "http_status_5xx")

    suspicion = max(
        clamp01((uri_entropy - 4.8) / 1.0),
        clamp01((query_len - 80.0) / 180.0),
        clamp01((param_count - 4.0) / 10.0),
        clamp01((special_chars - 3.0) / 12.0),
        clamp01((percent_encodings - 2.0) / 6.0),
    )
    if suspicion <= 0.0:
        return 0.0, []

    boost = 0.12 + 0.16 * suspicion
    factors = ["http_payload_shape"]
    if status_4xx > 0.0 or status_5xx > 0.0:
        boost += 0.04
        factors.append("http_error_response")

    return boost, factors


def suspicious_dns_boost(features: dict) -> tuple[float, list[str]]:
    if feature_value(features, "dns_tx_count") <= 0.0:
        return 0.0, []
    if int(feature_value(features, "dst_port")) == 5353:
        return 0.0, []

    entropy = feature_value(features, "dns_query_entropy_max")
    labels = feature_value(features, "dns_label_count_max")
    nxdomain = feature_value(features, "dns_nxdomain")
    rejected = feature_value(features, "dns_rejected")

    suspicion = max(
        clamp01((entropy - 4.1) / 0.7),
        clamp01((labels - 6.0) / 6.0),
        0.75 if nxdomain > 0.0 and entropy >= 3.8 else 0.0,
        0.6 if rejected > 0.0 and entropy >= 3.8 else 0.0,
    )
    if suspicion <= 0.0:
        return 0.0, []

    boost = 0.08 + 0.12 * suspicion
    factors = ["dns_query_shape"]
    if nxdomain > 0.0:
        factors.append("dns_nxdomain")
    if rejected > 0.0:
        factors.append("dns_rejected")

    return boost, factors


def suspicious_volume_boost(features: dict) -> tuple[float, list[str]]:
    bytes_per_second = feature_value(features, "bytes_per_second")
    src_total_bytes = feature_value(features, "src_total_bytes_300s")
    total_bytes = feature_value(features, "total_bytes")

    suspicion = max(
        clamp01((bytes_per_second - 500_000.0) / 2_000_000.0),
        clamp01((src_total_bytes - 1_000_000.0) / 5_000_000.0),
        clamp01((total_bytes - 500_000.0) / 2_000_000.0),
    )
    if suspicion <= 0.0:
        return 0.0, []

    return 0.05 + 0.08 * suspicion, ["volume_spike"]


def compose_anomaly_score(raw_score: float, features: dict) -> dict:
    boosts = []
    factors: list[str] = []

    for boost, names in (
        scan_pressure_boost(features),
        suspicious_http_boost(features),
        suspicious_dns_boost(features),
        suspicious_volume_boost(features),
    ):
        if boost > 0.0:
            boosts.append(boost)
            factors.extend(names)

    total_boost = min(sum(boosts), 0.35)
    ml_score = float(raw_score)
    hybrid_score = min(ml_score + total_boost, 1.0)

    return {
        "raw_score": ml_score,
        "behavioral_boost": float(total_boost),
        "behavioral_factors": sorted(set(factors)),
        "hybrid_score": float(hybrid_score),
        "score": ml_score,
    }
