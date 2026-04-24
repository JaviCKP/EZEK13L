import argparse
import json
import pickle
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from pipeline.attack_classifier import fit_centroid_classifier
except ModuleNotFoundError:
    from attack_classifier import fit_centroid_classifier


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def parse_labeled_input(raw: str) -> tuple[str, Path]:
    if "=" not in raw:
        raise argparse.ArgumentTypeError("Formato esperado: etiqueta=ruta.jsonl")
    label, path = raw.split("=", 1)
    label = label.strip()
    if not label:
        raise argparse.ArgumentTypeError("La etiqueta no puede estar vacia")
    return label, Path(path)


def load_rows(inputs: list[tuple[str, Path]], max_per_class: int, seed: int):
    rng = random.Random(seed)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for label, path in inputs:
        for row in read_jsonl(path):
            features = row.get("features") or {}
            if features:
                grouped[label].append({"label": label, "features": features})

    rows = []
    class_counts = {}
    for label, label_rows in sorted(grouped.items()):
        rng.shuffle(label_rows)
        if max_per_class > 0:
            label_rows = label_rows[:max_per_class]
        class_counts[label] = len(label_rows)
        rows.extend(label_rows)

    rng.shuffle(rows)
    return rows, class_counts


def split_rows(rows: list[dict], test_ratio: float, seed: int):
    rng = random.Random(seed)
    shuffled = list(rows)
    rng.shuffle(shuffled)
    test_count = int(len(shuffled) * max(0.0, min(test_ratio, 0.5)))
    if len(shuffled) > 1:
        test_count = min(max(test_count, 1), len(shuffled) - 1)
    else:
        test_count = 0
    return shuffled[test_count:], shuffled[:test_count]


def empty_metrics(labels: list[str]) -> dict:
    return {
        "labels": labels,
        "accuracy": 0.0,
        "macro_precision": 0.0,
        "macro_recall": 0.0,
        "macro_f1": 0.0,
        "confusion": {label: Counter() for label in labels},
        "per_class": {},
    }


def evaluate(model, rows: list[dict], labels: list[str]) -> dict:
    metrics = empty_metrics(labels)
    if not rows:
        return metrics

    correct = 0
    for row in rows:
        y_true = row["label"]
        y_pred = model.predict_one(row["features"]) or "unknown"
        metrics["confusion"].setdefault(y_true, Counter())[y_pred] += 1
        if y_pred == y_true:
            correct += 1

    precisions = []
    recalls = []
    f1s = []
    for label in labels:
        tp = metrics["confusion"].get(label, Counter()).get(label, 0)
        fp = sum(counter.get(label, 0) for true_label, counter in metrics["confusion"].items() if true_label != label)
        fn = sum(count for pred_label, count in metrics["confusion"].get(label, Counter()).items() if pred_label != label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        metrics["per_class"][label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": sum(metrics["confusion"].get(label, Counter()).values()),
        }
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)

    metrics["accuracy"] = correct / len(rows)
    metrics["macro_precision"] = sum(precisions) / len(precisions) if precisions else 0.0
    metrics["macro_recall"] = sum(recalls) / len(recalls) if recalls else 0.0
    metrics["macro_f1"] = sum(f1s) / len(f1s) if f1s else 0.0
    metrics["confusion"] = {label: dict(counter) for label, counter in metrics["confusion"].items()}
    return metrics


def quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    q = max(0.0, min(float(q), 1.0))
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def predict_with_confidence(model, features: dict) -> tuple[str, float]:
    probabilities = model.predict_proba_one(features) or {}
    if probabilities:
        prediction, confidence = max(probabilities.items(), key=lambda item: item[1])
        return str(prediction), float(confidence)
    return str(model.predict_one(features) or "unknown"), 0.0


def calibrate_class_thresholds(
    model,
    rows: list[dict],
    labels: list[str],
    normal_label: str,
    global_threshold: float,
    threshold_quantile: float,
    threshold_margin: float,
    min_threshold: float,
) -> dict[str, float]:
    correct_confidences: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        label = row["label"]
        if label == normal_label:
            continue
        prediction, confidence = predict_with_confidence(model, row["features"])
        if prediction == label:
            correct_confidences[label].append(confidence)

    thresholds = {}
    for label in labels:
        if label == normal_label:
            continue
        values = correct_confidences.get(label) or []
        if not values:
            continue
        learned = quantile(values, threshold_quantile) - threshold_margin
        thresholds[label] = round(
            max(float(min_threshold), min(float(global_threshold), float(learned))),
            6,
        )
    return thresholds


def dump_pickle(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    with tmp_path.open("wb") as handle:
        pickle.dump(obj, handle)
        handle.flush()
    tmp_path.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", type=parse_labeled_input, required=True)
    parser.add_argument("--model-out", required=True)
    parser.add_argument("--meta-out", required=True)
    parser.add_argument("--max-per-class", type=int, default=1800)
    parser.add_argument("--test-ratio", type=float, default=0.25)
    parser.add_argument("--detection-threshold", type=float, default=0.45)
    parser.add_argument("--class-threshold-quantile", type=float, default=0.10)
    parser.add_argument("--class-threshold-margin", type=float, default=0.05)
    parser.add_argument("--min-class-threshold", type=float, default=0.20)
    parser.add_argument("--temperature", type=float, default=0.35)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rows, class_counts = load_rows(args.input, args.max_per_class, args.seed)
    if len(rows) < 2:
        raise SystemExit("[ERROR] No hay suficientes filas etiquetadas para entrenar clasificador")

    labels = sorted(class_counts)
    train_rows, test_rows = split_rows(rows, args.test_ratio, args.seed)
    model = fit_centroid_classifier(train_rows, temperature=args.temperature)

    metrics = evaluate(model, test_rows, labels)
    class_thresholds = calibrate_class_thresholds(
        model=model,
        rows=test_rows if test_rows else train_rows,
        labels=labels,
        normal_label="normal",
        global_threshold=args.detection_threshold,
        threshold_quantile=args.class_threshold_quantile,
        threshold_margin=args.class_threshold_margin,
        min_threshold=args.min_class_threshold,
    )

    model = fit_centroid_classifier(rows, temperature=args.temperature)

    model_out = Path(args.model_out)
    meta_out = Path(args.meta_out)
    dump_pickle(model, model_out)
    meta_out.parent.mkdir(parents=True, exist_ok=True)
    with meta_out.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "model": {
                    "type": "CentroidAttackClassifier",
                    "library": "local",
                    "temperature": args.temperature,
                    "seed": args.seed,
                },
                "labels": labels,
                "normal_label": "normal",
                "detection_threshold": args.detection_threshold,
                "class_thresholds": class_thresholds,
                "threshold_calibration": {
                    "strategy": "per_class_holdout_confidence",
                    "quantile": args.class_threshold_quantile,
                    "margin": args.class_threshold_margin,
                    "min_threshold": args.min_class_threshold,
                    "global_threshold": args.detection_threshold,
                    "calibration_rows": len(test_rows if test_rows else train_rows),
                },
                "rows": len(rows),
                "train_rows": len(train_rows),
                "test_rows": len(test_rows),
                "class_counts": class_counts,
                "metrics": metrics,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            },
            handle,
            indent=2,
        )

    print(f"[OK] Clasificador guardado en {model_out}")
    print(f"[OK] Meta clasificador guardada en {meta_out}")
    print(f"[INFO] rows={len(rows)}, train={len(train_rows)}, test={len(test_rows)}, macro_f1={metrics['macro_f1']:.3f}")
    print(f"[INFO] class_thresholds={class_thresholds}")


if __name__ == "__main__":
    main()
