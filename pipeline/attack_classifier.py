from __future__ import annotations

import math
from collections import defaultdict


class CentroidAttackClassifier:
    def __init__(
        self,
        feature_names: list[str],
        means: dict[str, float],
        stds: dict[str, float],
        centroids: dict[str, dict[str, float]],
        temperature: float = 0.35,
    ):
        self.feature_names = feature_names
        self.means = means
        self.stds = stds
        self.centroids = centroids
        self.temperature = max(float(temperature), 1e-6)

    def _z(self, features: dict) -> dict[str, float]:
        values = {}
        for name in self.feature_names:
            raw = float(features.get(name, 0.0) or 0.0)
            values[name] = (raw - self.means.get(name, 0.0)) / self.stds.get(name, 1.0)
        return values

    def _distance(self, z_values: dict[str, float], centroid: dict[str, float]) -> float:
        if not self.feature_names:
            return 0.0
        total = 0.0
        for name in self.feature_names:
            diff = z_values.get(name, 0.0) - centroid.get(name, 0.0)
            total += diff * diff
        return math.sqrt(total / len(self.feature_names))

    def predict_proba_one(self, features: dict) -> dict[str, float]:
        if not self.centroids:
            return {}
        z_values = self._z(features)
        distances = {
            label: self._distance(z_values, centroid)
            for label, centroid in self.centroids.items()
        }
        min_distance = min(distances.values()) if distances else 0.0
        weights = {
            label: math.exp(-((distance - min_distance) / self.temperature))
            for label, distance in distances.items()
        }
        total = sum(weights.values())
        if total <= 0.0:
            share = 1.0 / len(weights)
            return {label: share for label in weights}
        return {label: weight / total for label, weight in weights.items()}

    def predict_one(self, features: dict) -> str | None:
        probabilities = self.predict_proba_one(features)
        if not probabilities:
            return None
        return max(probabilities.items(), key=lambda item: item[1])[0]


def fit_centroid_classifier(rows: list[dict], temperature: float = 0.35) -> CentroidAttackClassifier:
    feature_names = sorted({name for row in rows for name in (row.get("features") or {})})
    if not feature_names:
        return CentroidAttackClassifier([], {}, {}, {}, temperature=temperature)

    means = {}
    stds = {}
    for name in feature_names:
        values = [float((row.get("features") or {}).get(name, 0.0) or 0.0) for row in rows]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        means[name] = mean
        stds[name] = math.sqrt(variance) if variance > 1e-12 else 1.0

    grouped = defaultdict(list)
    for row in rows:
        grouped[row["label"]].append(row.get("features") or {})

    centroids = {}
    for label, feature_rows in grouped.items():
        centroid = {}
        for name in feature_names:
            total = 0.0
            for features in feature_rows:
                raw = float(features.get(name, 0.0) or 0.0)
                total += (raw - means[name]) / stds[name]
            centroid[name] = total / len(feature_rows)
        centroids[label] = centroid

    return CentroidAttackClassifier(
        feature_names=feature_names,
        means=means,
        stds=stds,
        centroids=centroids,
        temperature=temperature,
    )
