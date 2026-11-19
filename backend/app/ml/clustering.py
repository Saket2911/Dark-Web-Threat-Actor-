"""Actor clustering (K-Means and DBSCAN) with explanations.

Features are deliberately simple and interpretable: identifier count, handle
count, marketplace spread, timeline volume and threat category (one-hot).
Numerical features are standardised before clustering. Small datasets return
an explicit "insufficient data" result instead of raising.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

import numpy as np
from sqlalchemy.orm import Session

from app.models.entities import Actor

FEATURE_NOTE = (
    "Features: identifier count, handle count, distinct marketplaces, timeline event count "
    "and threat category (one-hot). Numeric features are standardised (z-score)."
)

LIMITATIONS = [
    "Clusters group actors by coarse observable attributes; they do not establish identity.",
    "Threat categories are analyst labels and may be inconsistent across sources.",
    "Cluster labels are arbitrary and change between runs when k or the data changes.",
]


def _feature_matrix(db: Session):
    actors = db.query(Actor).order_by(Actor.id).all()
    if not actors:
        return np.zeros((0, 0)), [], []

    categories = sorted({(a.threat_category or "unknown") for a in actors})
    rows: List[List[float]] = []
    for actor in actors:
        marketplaces = {(h.marketplace or "unknown") for h in actor.handles}
        row = [
            float(len(actor.identifiers)),
            float(len(actor.handles)),
            float(len(marketplaces)),
            float(len(actor.timeline_events)),
        ]
        row.extend([1.0 if (actor.threat_category or "unknown") == c else 0.0 for c in categories])
        rows.append(row)

    feature_names = [
        "identifier_count",
        "handle_count",
        "marketplace_count",
        "timeline_event_count",
    ] + [f"category:{c}" for c in categories]
    return np.array(rows, dtype=float), actors, feature_names


def _standardise(matrix: np.ndarray) -> np.ndarray:
    if matrix.size == 0:
        return matrix
    mean = matrix.mean(axis=0)
    std = matrix.std(axis=0)
    std[std == 0] = 1.0
    return (matrix - mean) / std


def _summaries(actors, labels) -> List[Dict]:
    grouped: Dict[int, List] = {}
    for actor, label in zip(actors, labels):
        grouped.setdefault(int(label), []).append(actor)
    summaries = []
    for label, members in sorted(grouped.items()):
        categories = Counter((m.threat_category or "unknown") for m in members)
        summaries.append(
            {
                "cluster": label,
                "size": len(members),
                "label": "noise" if label == -1 else f"cluster {label}",
                "members": [
                    {
                        "actor_id": m.id,
                        "handle": m.primary_handle,
                        "internal_id": m.internal_id,
                        "category": m.threat_category,
                    }
                    for m in sorted(members, key=lambda x: x.id)
                ],
                "dominant_categories": [
                    {"category": category, "count": count}
                    for category, count in categories.most_common(3)
                ],
            }
        )
    return summaries


def cluster_actors(db: Session, k: Optional[int] = None) -> Dict:
    """K-Means clustering over interpretable actor features."""
    matrix, actors, feature_names = _feature_matrix(db)
    if len(actors) < 3:
        return {
            "method": "kmeans",
            "clusters": 0,
            "assignments": [],
            "summaries": [],
            "silhouette": None,
            "status": "insufficient_data",
            "explanation": "K-Means needs at least 3 actors to form meaningful clusters.",
            "limitations": LIMITATIONS,
            "feature_note": FEATURE_NOTE,
        }

    scaled = _standardise(matrix)
    n_clusters = k or min(3, max(1, len(actors) // 4) + 1)
    n_clusters = max(2, min(n_clusters, len(actors) - 1))

    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score

    model = KMeans(n_clusters=n_clusters, n_init=10, random_state=42)
    labels = model.fit_predict(scaled)

    silhouette = None
    if 1 < len(set(labels)) < len(actors):
        try:
            silhouette = round(float(silhouette_score(scaled, labels)), 4)
        except Exception:
            silhouette = None

    inertia = round(float(model.inertia_), 4) if hasattr(model, "inertia_") else None

    return {
        "method": "kmeans",
        "clusters": int(len(set(labels))),
        "k": n_clusters,
        "assignments": [
            {
                "actor_id": int(actor.id),
                "handle": actor.primary_handle,
                "cluster": int(label),
            }
            for actor, label in zip(actors, labels)
        ],
        "summaries": _summaries(actors, labels),
        "silhouette": silhouette,
        "inertia": inertia,
        "status": "ok",
        "explanation": (
            f"K-Means with k={n_clusters} over {len(actors)} actors. "
            + (
                f"Silhouette score {silhouette} suggests moderate separation."
                if silhouette is not None and silhouette >= 0.5
                else "Silhouette score indicates weak or no cluster separation; treat groups as exploratory."
                if silhouette is not None
                else "Silhouette is not mathematically defined for this labelling."
            )
        ),
        "limitations": LIMITATIONS,
        "feature_note": FEATURE_NOTE,
        "features": feature_names,
    }


def cluster_behavioural(
    db: Session,
    eps: float = 0.5,
    min_samples: int = 2,
) -> Dict:
    """DBSCAN over normalised hourly activity vectors (cosine metric)."""
    from app.ml.behavioural import _activity_vector

    actors = db.query(Actor).order_by(Actor.id).all()
    if len(actors) < 3:
        return {
            "method": "dbscan",
            "clusters": 0,
            "assignments": [],
            "summaries": [],
            "status": "insufficient_data",
            "noise_count": 0,
            "explanation": "DBSCAN needs at least 3 actors with activity data.",
            "limitations": LIMITATIONS,
        }

    vectors = []
    used_actors = []
    for actor in actors:
        vector, _counts, total = _activity_vector(actor.id, db)
        if total > 0:
            vectors.append(vector)
            used_actors.append(actor)

    if len(used_actors) < 3:
        return {
            "method": "dbscan",
            "clusters": 0,
            "assignments": [],
            "summaries": [],
            "status": "insufficient_data",
            "noise_count": 0,
            "explanation": (
                "Fewer than 3 actors have dated timeline events, so behavioural "
                "clustering cannot be computed."
            ),
            "limitations": LIMITATIONS,
        }

    from sklearn.cluster import DBSCAN

    matrix = np.array(vectors, dtype=float)
    model = DBSCAN(eps=eps, min_samples=min_samples, metric="cosine")
    labels = model.fit_predict(matrix)

    noise_count = int(sum(1 for label in labels if label == -1))
    n_clusters = len({int(label) for label in labels if label != -1})

    explanation = (
        f"DBSCAN (eps={eps}, min_samples={min_samples}, cosine) grouped "
        f"{len(used_actors)} actors with activity data into {n_clusters} cluster(s); "
        f"{noise_count} actor(s) were classified as noise (-1)."
    )
    if n_clusters == 0:
        explanation += " No dense group was found; widen eps to explore looser groupings."

    return {
        "method": "dbscan",
        "clusters": n_clusters,
        "assignments": [
            {
                "actor_id": int(actor.id),
                "handle": actor.primary_handle,
                "cluster": int(label),
            }
            for actor, label in zip(used_actors, labels)
        ],
        "summaries": _summaries(used_actors, labels),
        "noise_count": noise_count,
        "eps": eps,
        "min_samples": min_samples,
        "status": "ok",
        "explanation": explanation,
        "limitations": LIMITATIONS
        + [
            "Noise points (-1) are actors that do not belong to any dense group; they are not 'clean' actors.",
        ],
    }
