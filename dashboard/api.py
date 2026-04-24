import json
import math
import sys
from collections import Counter, deque
from pathlib import Path

import pandas as pd
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

APP_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_DIR = APP_ROOT / "pipeline"
for candidate in (APP_ROOT, PIPELINE_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

try:
    from pipeline.suricata_utils import alert_signature, classify_suricata_alert
except ModuleNotFoundError:
    from suricata_utils import alert_signature, classify_suricata_alert

app = FastAPI(title="Ezek13l Dashboard API")

# Serve static files for the frontend
app.mount("/static", StaticFiles(directory=str(APP_ROOT / "dashboard")), name="static")

MAX_SCORE_ROWS = 4000
MAX_ALERT_ROWS = 8000

# We'll use global state to cache file readings similar to Streamlit's session_state
GLOBAL_STATE = {
    "score-state": None,
    "alert-state": None
}

def parse_json_line(line: str):
    line = line.strip()
    if not line: return None
    try: return json.loads(line)
    except json.JSONDecodeError: return None

def choose_path(preferred: Path, fallback: Path) -> Path:
    return preferred if preferred.exists() else fallback

def normalize_proto(value) -> str:
    if value in (None, "-", ""): return ""
    return str(value).lower()

def normalize_port(value) -> int:
    try:
        if value in (None, "-", ""): return 0
        return int(value)
    except (TypeError, ValueError):
        try: return int(float(value))
        except (TypeError, ValueError): return 0

def normalized_flow_key(src_ip, src_port, dst_ip, dst_port, proto):
    left = (str(src_ip or ""), normalize_port(src_port))
    right = (str(dst_ip or ""), normalize_port(dst_port))
    ordered = tuple(sorted((left, right)))
    return ordered + (normalize_proto(proto),)

def score_flow_key(row: dict):
    return normalized_flow_key(
        row.get("src_ip"), row.get("src_port"),
        row.get("dst_ip"), row.get("dst_port"),
        row.get("proto"),
    )

def empty_score_state():
    return {
        "path": "", "position": 0, "rows": deque(maxlen=MAX_SCORE_ROWS),
        "total_rows": 0, "anomalies": 0, "expert_signals": 0,
        "ml_detections": 0, "ml_labels": Counter(),
        "classifier_detections": 0, "attack_predictions": Counter(),
        "learned": 0, "blocked": 0, "block_reasons": Counter(),
    }

def update_score_state(state: dict, row: dict):
    state["rows"].append(row)
    state["total_rows"] += 1
    if row.get("is_ml_anomaly", row.get("is_anomaly")): state["anomalies"] += 1
    is_ml_detection = row.get(
        "is_ml_detection",
        row.get("is_ml_anomaly", False) or row.get("is_attack_classifier_detection", False) or row.get("is_anomaly", False),
    )
    if is_ml_detection:
        state["ml_detections"] += 1
        state["ml_labels"][row.get("ml_label") or row.get("attack_prediction") or "unknown"] += 1
    if row.get("has_expert_signal") or float(row.get("behavioral_boost", 0.0) or 0.0) > 0.0:
        state["expert_signals"] += 1
    if row.get("is_attack_classifier_detection"):
        state["classifier_detections"] += 1
        state["attack_predictions"][row.get("attack_prediction") or "unknown"] += 1
    if row.get("learned"): state["learned"] += 1
    reasons = row.get("learning_blocked_reasons") or []
    if reasons:
        state["blocked"] += 1
        for reason in reasons: state["block_reasons"][reason] += 1

def empty_alert_state():
    return {
        "path": "", "position": 0, "rows": deque(maxlen=MAX_ALERT_ROWS),
        "total_alerts": 0, "class_counts": Counter(), "useful_signatures": Counter(),
        "useful_ips": Counter(), "ip_signals": {}, "flow_signals": {},
    }

ALERT_RANK = {"non_alert": 0, "noise": 1, "telemetry": 2, "threat": 3}
SURICATA_CLASS_LABELS = {
    "threat": "Amenaza", "telemetry": "Telemetria", "noise": "Ruido",
    "non_alert": "Sin alerta", "none": "Sin alerta",
}
STATUS_PRIORITY = {
    "Critico": 7, "Ataque ML": 6, "Confirmado": 5, "Deriva ML": 4, "Senal experta": 3, "Telemetria": 2, "Observado": 1,
}
BLOCK_REASON_LABELS = {
    "score_above_threshold": "score >= threshold",
    "score_above_learn_below": "score > learn_below",
    "ml_classifier_detection": "clasificador ML detecto ataque",
    "suricata_alerted_ip": "Suricata alerto la IP",
    "suricata_alerted_flow": "Suricata alerto el flow",
    "already_marked_anomalous": "ya estaba marcado como anomalo",
}
FACTOR_LABELS = {
    "scan_ports_60s": "scan puertos 60s",
    "scan_ips_60s": "scan IPs 60s",
    "scan_ports_300s": "scan puertos 5m",
    "http_payload_shape": "payload HTTP",
    "http_error_response": "errores HTTP",
    "dns_query_shape": "DNS entropico",
    "dns_nxdomain": "NXDOMAIN",
    "dns_rejected": "DNS rechazado",
    "volume_spike": "pico volumen",
}

def stronger_signal(current: dict | None, candidate: dict) -> dict:
    if current is None: return candidate
    current_rank = ALERT_RANK.get(current.get("suricata_class"), 0)
    candidate_rank = ALERT_RANK.get(candidate.get("suricata_class"), 0)
    if candidate_rank > current_rank: return candidate
    if candidate_rank < current_rank: return current
    if (candidate.get("timestamp") or "") >= (current.get("timestamp") or ""): return candidate
    return current

def update_alert_state(state: dict, row: dict):
    if row.get("event_type") != "alert": return
    signature = alert_signature(row) or "Sin firma"
    suricata_class = classify_suricata_alert(row)
    enriched = {
        **row, "signature": signature, "suricata_class": suricata_class,
        "suricata_label": SURICATA_CLASS_LABELS.get(suricata_class, "Sin alerta"),
    }
    state["rows"].append(enriched)
    state["total_alerts"] += 1
    state["class_counts"][suricata_class] += 1

    signal = {"suricata_class": suricata_class, "signature": signature, "timestamp": row.get("timestamp")}
    for ip_key in ("src_ip", "dest_ip"):
        ip_value = row.get(ip_key)
        if ip_value: state["ip_signals"][ip_value] = stronger_signal(state["ip_signals"].get(ip_value), signal)

    if row.get("src_ip") or row.get("dest_ip"):
        flow_key = normalized_flow_key(row.get("src_ip"), row.get("src_port"), row.get("dest_ip"), row.get("dest_port"), row.get("proto"))
        state["flow_signals"][flow_key] = stronger_signal(state["flow_signals"].get(flow_key), signal)

    if suricata_class != "noise":
        state["useful_signatures"][signature] += 1
        if row.get("src_ip"): state["useful_ips"][row["src_ip"]] += 1
        if row.get("dest_ip"): state["useful_ips"][row["dest_ip"]] += 1

def load_incremental_jsonl(path: Path, state_key: str, initializer, updater):
    state = GLOBAL_STATE.get(state_key)
    if state is None or state.get("path") != str(path):
        state = initializer()
        state["path"] = str(path)

    if not path.exists():
        state = initializer()
        state["path"] = str(path)
        GLOBAL_STATE[state_key] = state
        return state

    current_size = path.stat().st_size
    if current_size < state.get("position", 0):
        state = initializer()
        state["path"] = str(path)

    with path.open("r", encoding="utf-8") as handle:
        if state["position"]: handle.seek(state["position"])
        for line in handle:
            row = parse_json_line(line)
            if row is not None: updater(state, row)
        state["position"] = handle.tell()

    GLOBAL_STATE[state_key] = state
    return state

def correlate_signal(row: dict, alert_state: dict, show_noise: bool):
    signal = None
    flow_match = alert_state["flow_signals"].get(score_flow_key(row))
    if flow_match: signal = stronger_signal(signal, {**flow_match, "match": "flow"})
    for ip_value in (row.get("src_ip"), row.get("dst_ip")):
        ip_match = alert_state["ip_signals"].get(ip_value)
        if ip_match: signal = stronger_signal(signal, {**ip_match, "match": "ip"})
    if signal and signal.get("suricata_class") == "noise" and not show_noise: return None
    return signal

def learning_state(row: dict) -> str:
    if row.get("learned"): return "Aprendido"
    if row.get("learning_blocked_reasons"): return "Bloqueado"
    return "Sin aprendizaje"

def combined_status(row: dict, signal: dict | None) -> str:
    signal_class = signal.get("suricata_class") if signal else "none"
    is_ml_anomaly = row.get("is_ml_anomaly", row.get("is_anomaly"))
    is_classifier_detection = row.get("is_attack_classifier_detection", False)
    is_ml_detection = row.get("is_ml_detection", is_ml_anomaly or is_classifier_detection)
    has_expert_signal = row.get("has_expert_signal") or float(row.get("behavioral_boost", 0.0) or 0.0) > 0.0
    if is_ml_detection and signal_class == "threat": return "Critico"
    if is_classifier_detection: return "Ataque ML"
    if signal_class == "threat": return "Confirmado"
    if is_ml_anomaly: return "Deriva ML"
    if has_expert_signal: return "Senal experta"
    if signal_class == "telemetry": return "Telemetria"
    return "Observado"

def format_block_reasons(reasons) -> str:
    reasons = reasons or []
    if not reasons: return "-"
    return " | ".join(BLOCK_REASON_LABELS.get(reason, reason) for reason in reasons)

def format_factors(factors) -> str:
    factors = factors or []
    if not factors:
        return "-"
    return " | ".join(FACTOR_LABELS.get(factor, factor) for factor in factors)

def read_meta(path: Path) -> dict:
    if not path.exists(): return {}
    try: return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError: return {}


def sanitize_json(value):
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, dict):
        return {key: sanitize_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    return value

def live_progress():
    live_in = APP_ROOT / "data" / "live_in"
    live_done = APP_ROOT / "data" / "live_done"
    live_error = APP_ROOT / "data" / "live_error"

    pending = sorted(live_in.glob("*.pcap")) if live_in.exists() else []
    processed = sorted(live_done.glob("*.pcap")) if live_done.exists() else []
    failed = sorted(live_error.glob("*.pcap")) if live_error.exists() else []

    latest = processed[-1].name if processed else "-"
    return {
        "pending": len(pending),
        "processed": len(processed),
        "failed": len(failed),
        "latest": latest,
    }

@app.get("/")
def serve_index():
    index_path = APP_ROOT / "dashboard" / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Dashboard UI no encontrada</h1>")

@app.get("/api/data")
def get_dashboard_data(window_minutes: int = 15, show_noise: bool = False):
    score_path = choose_path(APP_ROOT / "output" / "live_scores.jsonl", APP_ROOT / "output" / "detections.jsonl")
    eve_path = choose_path(APP_ROOT / "logs" / "live" / "suricata" / "eve.json", APP_ROOT / "logs" / "offline" / "test_suricata" / "eve.json")
    meta = read_meta(APP_ROOT / "model" / "meta.json")
    threshold = float(meta.get("threshold", 0.0))
    learn_below = float(meta.get("learn_below", 0.0))

    score_state = load_incremental_jsonl(score_path, "score-state", empty_score_state, update_score_state)
    alert_state = load_incremental_jsonl(eve_path, "alert-state", empty_alert_state, update_alert_state)

    # Process scores
    score_rows = []
    for raw in score_state["rows"]:
        signal = correlate_signal(raw, alert_state, show_noise)
        status = combined_status(raw, signal)
        score_rows.append({
            **raw,
            "dt": pd.to_datetime(raw.get("ts"), unit="s", errors="coerce", utc=True).tz_convert(None),
            "raw_score": float(raw.get("raw_score", raw.get("score", 0.0)) or 0.0),
            "behavioral_boost": float(raw.get("behavioral_boost", 0.0) or 0.0),
            "hybrid_score": float(raw.get("hybrid_score", raw.get("score", 0.0)) or 0.0),
            "is_ml_anomaly": bool(raw.get("is_ml_anomaly", raw.get("is_anomaly", False))),
            "is_ml_detection": bool(raw.get("is_ml_detection", raw.get("is_ml_anomaly", False) or raw.get("is_attack_classifier_detection", False) or raw.get("is_anomaly", False))),
            "ml_label": raw.get("ml_label", raw.get("attack_prediction", "unavailable")),
            "ml_detection_source": raw.get("ml_detection_source", "unknown"),
            "has_expert_signal": bool(raw.get("has_expert_signal") or float(raw.get("behavioral_boost", 0.0) or 0.0) > 0.0),
            "attack_prediction": raw.get("attack_prediction", "unavailable"),
            "attack_confidence": float(raw.get("attack_confidence", 0.0) or 0.0),
            "is_attack_classifier_detection": bool(raw.get("is_attack_classifier_detection", False)),
            "factor_text": format_factors(raw.get("behavioral_factors")),
            "suricata_class": signal.get("suricata_class", "none") if signal else "none",
            "suricata_label": SURICATA_CLASS_LABELS.get(signal.get("suricata_class", "none") if signal else "none", "Sin alerta"),
            "suricata_signature": signal.get("signature", "-") if signal else "-",
            "suricata_match": signal.get("match", "-") if signal else "-",
            "learning_state": learning_state(raw),
            "block_reason_text": format_block_reasons(raw.get("learning_blocked_reasons")),
            "combined_status": status,
            "priority": STATUS_PRIORITY.get(status, 0) + (0.2 if raw.get("learning_blocked_reasons") else 0.0),
        })
    
    score_df = pd.DataFrame(score_rows) if score_rows else pd.DataFrame()
    if not score_df.empty:
        score_df = score_df.sort_values(["priority", "hybrid_score", "raw_score", "dt"], ascending=[False, False, False, False]).reset_index(drop=True)
    
    # Process alerts
    alert_rows = list(alert_state["rows"])
    alert_df = pd.DataFrame(alert_rows) if alert_rows else pd.DataFrame()
    if not alert_df.empty:
        alert_df["dt"] = pd.to_datetime(alert_df["timestamp"], errors="coerce", utc=True).dt.tz_convert(None)
        if not show_noise: alert_df = alert_df[alert_df["suricata_class"] != "noise"]
        alert_df = alert_df.sort_values("dt", ascending=False).reset_index(drop=True)

    # Window filtering
    if window_minutes > 0:
        if not score_df.empty:
            cutoff = score_df["dt"].max() - pd.Timedelta(minutes=window_minutes)
            score_df = score_df[score_df["dt"] >= cutoff]
        if not alert_df.empty:
            cutoff = alert_df["dt"].max() - pd.Timedelta(minutes=window_minutes)
            alert_df = alert_df[alert_df["dt"] >= cutoff]

    # Format for JSON
    def serialize_df(df):
        if df.empty: return []
        df_copy = df.copy()
        if "dt" in df_copy.columns: df_copy["dt"] = df_copy["dt"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        df_copy = df_copy.where(pd.notnull(df_copy), None)
        return df_copy.to_dict(orient="records")

    live_info = live_progress()
    useful_alerts = alert_state["class_counts"]["threat"] + alert_state["class_counts"]["telemetry"]
    noise_alerts = alert_state["class_counts"]["noise"]
    
    pipeline = {
        "Generador": live_info["processed"] > 0 or live_info["pending"] > 0,
        "Watcher": live_info["processed"] > 0 or live_info["failed"] > 0,
        "Zeek": any((APP_ROOT / "logs" / "live" / "zeek").glob("*")),
        "Suricata": alert_state["total_alerts"] > 0 or (APP_ROOT / "logs" / "live" / "suricata" / "eve.json").exists(),
        "Scoring": score_state["total_rows"] > 0,
        "Aprendizaje": score_state["learned"] > 0 or (APP_ROOT / "output" / "learning_audit.jsonl").exists(),
    }

    return sanitize_json({
        "meta": {"threshold": threshold, "learn_below": learn_below},
        "metrics": {
            "processed_pcaps": live_info["processed"],
            "pending_pcaps": live_info["pending"],
            "failed_pcaps": live_info["failed"],
            "latest_pcap": live_info["latest"],
            "total_scores": score_state["total_rows"],
            "anomalies": score_state["anomalies"],
            "ml_detections": score_state["ml_detections"],
            "classifier_detections": score_state["classifier_detections"],
            "expert_signals": score_state["expert_signals"],
            "useful_alerts": useful_alerts,
            "noise_alerts": noise_alerts,
            "learned": score_state["learned"],
            "blocked": score_state["blocked"],
        },
        "pipeline": pipeline,
        "block_reasons": dict(score_state["block_reasons"].most_common(5)),
        "ml_labels": dict(score_state["ml_labels"].most_common(6)),
        "attack_predictions": dict(score_state["attack_predictions"].most_common(6)),
        "useful_ips": dict(alert_state["useful_ips"].most_common(8)),
        "useful_signatures": dict(alert_state["useful_signatures"].most_common(8)),
        "scores": serialize_df(score_df),
        "alerts": serialize_df(alert_df)
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8501, reload=True)
