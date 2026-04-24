import argparse
import json
import pickle
import sys
from pathlib import Path

try:
    from pipeline.anomaly_utils import compose_anomaly_score
    from pipeline.feature_selection import select_baseline_features
except ModuleNotFoundError:
    from anomaly_utils import compose_anomaly_score
    from feature_selection import select_baseline_features

try:
    from pipeline.suricata_utils import should_guard_learning
except ModuleNotFoundError:
    from suricata_utils import should_guard_learning

def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def normalize_proto(value):
    if value in (None, "-", ""):
        return ""
    return str(value).lower()


def normalize_port(value):
    try:
        if value in (None, "-", ""):
            return 0
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return 0


def event_key(row):
    uid = row.get("uid")
    if uid:
        return ("uid", str(uid))

    return (
        "flow",
        (
            row.get("ts"),
            row.get("src_ip"),
            row.get("src_port"),
            row.get("dst_ip"),
            row.get("dst_port"),
            normalize_proto(row.get("proto")),
        ),
    )


def normalized_flow_key(src_ip, src_port, dst_ip, dst_port, proto):
    proto = normalize_proto(proto)
    left = (str(src_ip or ""), normalize_port(src_port))
    right = (str(dst_ip or ""), normalize_port(dst_port))
    ordered = tuple(sorted((left, right)))
    return ordered + (proto,)


def row_flow_key(row):
    return normalized_flow_key(
        row.get("src_ip"),
        row.get("src_port"),
        row.get("dst_ip"),
        row.get("dst_port"),
        row.get("proto"),
    )


def load_suricata_guard(path: Path):
    if path is None or not path.exists():
        return set(), set()

    guarded_ips = set()
    guarded_flows = set()
    for row in read_jsonl(path):
        if row.get("event_type") != "alert" or not should_guard_learning(row):
            continue
        for key in ("src_ip", "dest_ip"):
            value = row.get(key)
            if value:
                guarded_ips.add(value)

        if row.get("src_ip") or row.get("dest_ip"):
            guarded_flows.add(
                normalized_flow_key(
                    row.get("src_ip"),
                    row.get("src_port"),
                    row.get("dest_ip"),
                    row.get("dest_port"),
                    row.get("proto"),
                )
            )
    return guarded_ips, guarded_flows


def load_previously_anomalous(path: Path):
    if path is None or not path.exists():
        return set()

    anomalous = set()
    for row in read_jsonl(path):
        if row.get("is_anomaly"):
            anomalous.add(event_key(row))
    return anomalous


def atomic_pickle_dump(model, path: Path):
    tmp_path = path.with_name(f"{path.name}.tmp")
    backup_path = path.with_name(f"{path.name}.bak")

    with tmp_path.open("wb") as f:
        pickle.dump(model, f)
        f.flush()

    if backup_path.exists():
        backup_path.unlink()
    if path.exists():
        path.replace(backup_path)
    tmp_path.replace(path)


def load_pickle_model(path: Path):
    backup_path = path.with_name(f"{path.name}.bak")
    try:
        with path.open("rb") as f:
            return pickle.load(f)
    except (pickle.UnpicklingError, EOFError) as first_error:
        if backup_path.exists():
            try:
                with backup_path.open("rb") as f:
                    print(
                        f"[WARN] Modelo principal corrupto; usando backup {backup_path}",
                        file=sys.stderr,
                    )
                    return pickle.load(f)
            except (pickle.UnpicklingError, EOFError):
                pass
        raise SystemExit(
            f"[ERROR] No se puede cargar {path}: pickle corrupto o truncado. "
            "Reentrena con scripts/poc-train.ps1."
        ) from first_error


def load_optional_pickle(path: Path):
    if path is None or not path.exists():
        return None
    with path.open("rb") as f:
        return pickle.load(f)


def load_optional_json(path: Path):
    if path is None or not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def classify_attack(classifier, classifier_meta: dict, features: dict) -> dict:
    if classifier is None:
        return {
            "attack_prediction": "unavailable",
            "attack_confidence": 0.0,
            "attack_probabilities": {},
            "attack_detection_threshold": 0.0,
            "is_attack_classifier_detection": False,
        }

    probabilities = classifier.predict_proba_one(features) or {}
    probabilities = {str(label): float(value) for label, value in probabilities.items()}
    if probabilities:
        prediction, confidence = max(probabilities.items(), key=lambda item: item[1])
    else:
        prediction = classifier.predict_one(features) or "unknown"
        confidence = 0.0

    normal_label = str(classifier_meta.get("normal_label", "normal"))
    configured_class_thresholds = classifier_meta.get("class_thresholds") or {}
    class_thresholds = {
        str(label): float(value)
        for label, value in configured_class_thresholds.items()
    }
    threshold = float(
        class_thresholds.get(
            str(prediction),
            classifier_meta.get("detection_threshold", 0.60),
        )
    )
    is_detection = prediction != normal_label and confidence >= threshold
    return {
        "attack_prediction": str(prediction),
        "attack_confidence": float(confidence),
        "attack_probabilities": probabilities,
        "attack_detection_threshold": threshold,
        "is_attack_classifier_detection": bool(is_detection),
    }


def learning_block_reasons(row, score, threshold, learn_below, guarded_ips, guarded_flows, previous_anomalies):
    reasons = []
    if score >= threshold:
        reasons.append("score_above_threshold")
    elif score > learn_below:
        reasons.append("score_above_learn_below")

    src_ip = row.get("src_ip")
    dst_ip = row.get("dst_ip")
    if src_ip in guarded_ips or dst_ip in guarded_ips:
        reasons.append("suricata_alerted_ip")

    if row_flow_key(row) in guarded_flows:
        reasons.append("suricata_alerted_flow")

    if event_key(row) in previous_anomalies:
        reasons.append("already_marked_anomalous")

    return reasons


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--meta", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--append", action="store_true")
    parser.add_argument("--save-model", action="store_true")
    parser.add_argument("--no-learn", action="store_true")
    parser.add_argument("--learn-audit")
    parser.add_argument("--suricata-eve")
    parser.add_argument("--classifier-model")
    parser.add_argument("--classifier-meta")
    args = parser.parse_args()

    input_path = Path(args.input_path)
    model_path = Path(args.model)
    meta_path = Path(args.meta)
    out_path = Path(args.out)
    suricata_eve = Path(args.suricata_eve) if args.suricata_eve else None
    out_path.parent.mkdir(parents=True, exist_ok=True)

    model = load_pickle_model(model_path)
    classifier_model_path = Path(args.classifier_model) if args.classifier_model else model_path.with_name("attack_classifier.pkl")
    classifier_meta_path = Path(args.classifier_meta) if args.classifier_meta else meta_path.with_name("attack_classifier_meta.json")
    attack_classifier = load_optional_pickle(classifier_model_path)
    classifier_meta = load_optional_json(classifier_meta_path)

    with meta_path.open("r", encoding="utf-8") as f:
        meta = json.load(f)

    threshold = float(meta["threshold"])
    learn_below = float(meta["learn_below"])
    if learn_below <= 0.0 and threshold > 0.0:
        learn_below = threshold * 0.5
    guarded_ips, guarded_flows = load_suricata_guard(suricata_eve)
    previous_anomalies = load_previously_anomalous(out_path if args.append else None)

    mode = "a" if args.append else "w"
    written = 0
    learned_count = 0
    audit_fh = None

    if args.learn_audit:
        audit_path = Path(args.learn_audit)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_fh = audit_path.open("a", encoding="utf-8")

    try:
        with out_path.open(mode, encoding="utf-8") as wf:
            for row in read_jsonl(input_path):
                x = row["features"]
                baseline_x = select_baseline_features(x)
                score_parts = compose_anomaly_score(model.score_one(baseline_x), x)
                score = float(score_parts["score"])
                hybrid_score = float(score_parts["hybrid_score"])
                classifier_result = classify_attack(attack_classifier, classifier_meta, x)
                is_ml_anomaly = score >= threshold
                is_ml_attack_detection = bool(classifier_result["is_attack_classifier_detection"])
                is_ml_detection = is_ml_anomaly or is_ml_attack_detection
                if is_ml_attack_detection:
                    ml_label = classifier_result["attack_prediction"]
                    ml_detection_source = "classifier"
                elif is_ml_anomaly:
                    ml_label = "novel_anomaly"
                    ml_detection_source = "novelty"
                else:
                    ml_label = "normal"
                    ml_detection_source = "none"
                has_expert_signal = score_parts["behavioral_boost"] > 0.0
                block_reasons = learning_block_reasons(
                    row,
                    score,
                    threshold,
                    learn_below,
                    guarded_ips,
                    guarded_flows,
                    previous_anomalies,
                )
                if is_ml_attack_detection:
                    block_reasons.append("ml_classifier_detection")
                learned = False

                if not args.no_learn and not block_reasons:
                    model.learn_one(baseline_x)
                    learned = True
                    learned_count += 1

                out_row = {
                    **row,
                    "score": score,
                    "raw_score": score_parts["raw_score"],
                    "behavioral_boost": score_parts["behavioral_boost"],
                    "behavioral_factors": score_parts["behavioral_factors"],
                    "hybrid_score": hybrid_score,
                    "is_ml_anomaly": is_ml_anomaly,
                    "is_ml_detection": is_ml_detection,
                    "ml_label": ml_label,
                    "ml_detection_source": ml_detection_source,
                    "has_expert_signal": has_expert_signal,
                    **classifier_result,
                    "is_anomaly": is_ml_detection,
                    "learned": learned,
                    "learning_blocked_reasons": block_reasons,
                }
                wf.write(json.dumps(out_row) + "\n")

                if learned and audit_fh is not None:
                    audit_fh.write(
                        json.dumps(
                            {
                                "ts": row.get("ts"),
                                "uid": row.get("uid"),
                                "src_ip": row.get("src_ip"),
                                "dst_ip": row.get("dst_ip"),
                                "dst_port": row.get("dst_port"),
                                "score": score,
                            }
                        )
                        + "\n"
                    )

                if is_ml_detection:
                    previous_anomalies.add(event_key(out_row))

                written += 1
    finally:
        if audit_fh is not None:
            audit_fh.close()

    if args.save_model:
        atomic_pickle_dump(model, model_path)

    print(f"[OK] {written} eventos puntuados en {out_path}")
    print(f"[INFO] aprendidos={learned_count}, no_learn={args.no_learn}")
    if guarded_ips:
        print(f"[INFO] aprendizaje bloqueado para {len(guarded_ips)} IPs con alerta Suricata")
    if guarded_flows:
        print(f"[INFO] aprendizaje bloqueado para {len(guarded_flows)} flows alertados por Suricata")


if __name__ == "__main__":
    main()
