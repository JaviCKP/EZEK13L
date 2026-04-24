import argparse
import hashlib
import json
import pickle
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import river
from river import anomaly, compose, preprocessing

try:
    from pipeline.anomaly_utils import compose_anomaly_score
    from pipeline.feature_selection import select_baseline_features
except ModuleNotFoundError:
    from anomaly_utils import compose_anomaly_score
    from feature_selection import select_baseline_features


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def build_model(n_trees: int, height: int, window_size: int, seed: int):
    return compose.Pipeline(
        preprocessing.MinMaxScaler(),
        anomaly.HalfSpaceTrees(
            n_trees=n_trees,
            height=height,
            window_size=window_size,
            seed=seed,
        ),
    )


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


def feature_schema(rows: list[dict]) -> list[str]:
    keys = set()
    for row in rows:
        keys.update((row.get("features") or {}).keys())
    return sorted(keys)


def schema_hash(keys: list[str]) -> str:
    payload = "\n".join(keys).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def score_distribution(scores: list[float]) -> dict:
    if not scores:
        return {}
    return {
        "min": float(np.min(scores)),
        "p50": float(np.quantile(scores, 0.50)),
        "p90": float(np.quantile(scores, 0.90)),
        "p95": float(np.quantile(scores, 0.95)),
        "max": float(np.max(scores)),
    }


def split_train_calibration(
    rows: list[dict],
    holdout_count: int,
    seed: int,
) -> tuple[list[dict], list[dict]]:
    if holdout_count <= 0:
        return rows, rows

    rng = np.random.default_rng(seed)
    holdout_indices = set(rng.choice(len(rows), size=holdout_count, replace=False).tolist())
    train_rows = [row for index, row in enumerate(rows) if index not in holdout_indices]
    calibration_rows = [row for index, row in enumerate(rows) if index in holdout_indices]
    return train_rows, calibration_rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--model-out", required=True)
    parser.add_argument("--meta-out", required=True)
    parser.add_argument("--holdout-ratio", type=float, default=0.2)
    parser.add_argument("--threshold-quantile", type=float, default=0.90)
    parser.add_argument("--min-threshold", type=float, default=0.95)
    parser.add_argument("--learn-quantile", type=float, default=0.60)
    parser.add_argument("--n-trees", type=int, default=50)
    parser.add_argument("--height", type=int, default=10)
    parser.add_argument("--window-size", type=int, default=512)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--calibration-seed", type=int, default=42)
    args = parser.parse_args()

    input_path = Path(args.input_path)
    model_out = Path(args.model_out)
    meta_out = Path(args.meta_out)

    model_out.parent.mkdir(parents=True, exist_ok=True)
    meta_out.parent.mkdir(parents=True, exist_ok=True)

    rows = list(read_jsonl(input_path))
    if not rows:
        raise SystemExit(f"[ERROR] No hay eventos de entrenamiento en {input_path}")
    schema = feature_schema(rows)
    baseline_schema = feature_schema(
        [{"features": select_baseline_features(row.get("features") or {})} for row in rows]
    )

    holdout_ratio = min(max(float(args.holdout_ratio), 0.0), 0.5)
    holdout_count = int(len(rows) * holdout_ratio)
    if len(rows) > 1:
        holdout_count = min(max(holdout_count, 1), len(rows) - 1)
    else:
        holdout_count = 0

    train_rows, calibration_rows = split_train_calibration(
        rows=rows,
        holdout_count=holdout_count,
        seed=args.calibration_seed,
    )

    model = build_model(args.n_trees, args.height, args.window_size, args.seed)

    count = 0
    for row in train_rows:
        model.learn_one(select_baseline_features(row["features"]))
        count += 1

    scores = []
    for row in calibration_rows:
        baseline_features = select_baseline_features(row["features"])
        score_parts = compose_anomaly_score(model.score_one(baseline_features), row["features"])
        scores.append(float(score_parts["score"]))

    if scores:
        threshold = max(float(np.quantile(scores, args.threshold_quantile)), float(args.min_threshold))
        learn_below = float(np.quantile(scores, args.learn_quantile))
    else:
        threshold = 0.8
        learn_below = 0.2

    for row in calibration_rows:
        model.learn_one(select_baseline_features(row["features"]))

    learn_below = min(learn_below, threshold)
    if learn_below <= 0.0 and threshold > 0.0:
        learn_below = threshold * 0.5

    atomic_pickle_dump(model, model_out)

    with meta_out.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "threshold": threshold,
                "learn_below": learn_below,
                "train_events": len(rows),
                "fit_events_before_calibration": count,
                "holdout_events": len(calibration_rows),
                "holdout_ratio": holdout_ratio,
                "calibration_strategy": "deterministic_random_holdout",
                "calibration_seed": args.calibration_seed,
                "threshold_quantile": args.threshold_quantile,
                "min_threshold": args.min_threshold,
                "learn_quantile": args.learn_quantile,
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "river_version": river.__version__,
                "feature_count": len(schema),
                "feature_schema_hash": schema_hash(schema),
                "baseline_feature_count": len(baseline_schema),
                "baseline_feature_schema_hash": schema_hash(baseline_schema),
                "baseline_feature_profile": "shape_ratios_no_raw_volume_or_window_counts_v1",
                "calibration_score_distribution": score_distribution(scores),
                "model": {
                    "type": "HalfSpaceTrees",
                    "n_trees": args.n_trees,
                    "height": args.height,
                    "window_size": args.window_size,
                    "seed": args.seed,
                },
                "score_mode": "ml_raw_plus_expert_layers_v2",
            },
            f,
            indent=2,
        )

    print(f"[OK] Modelo guardado en {model_out}")
    print(f"[OK] Meta guardada en {meta_out}")
    print(f"[INFO] train_rows={len(train_rows)}, holdout_rows={len(calibration_rows)}")
    print(f"[INFO] threshold={threshold:.6f}, learn_below={learn_below:.6f}")


if __name__ == "__main__":
    main()
