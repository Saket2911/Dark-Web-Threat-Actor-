"""Explainable weighted attribution scoring.

The score is a *weighted mean over the evidence that is actually available*,
combined with an explicit coverage figure. Missing evidence therefore lowers
confidence instead of silently being treated as similarity zero.

The output is deliberately framed as an investigative hypothesis. Similarity
is never a probability of shared identity and the engine never returns a
"confirmed" verdict.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# Categories are decision-support bands, not identity conclusions.
CATEGORY_STRONG = "Strong evidence"
CATEGORY_MODERATE = "Moderate evidence"
CATEGORY_WEAK = "Weak evidence"
CATEGORY_INSUFFICIENT = "Insufficient evidence"

# Features whose supporting evidence overlaps. Only the highest weighted
# feature in a group contributes, so the same underlying observation cannot be
# counted twice in different guises.
FEATURE_LABELS = {
    "identifier": "Shared strong identifiers",
    "stylometric": "Writing-style similarity",
    "behavioural": "Hourly activity similarity",
    "temporal": "Overlapping activity dates",
    "infrastructure": "Shared infrastructure",
}

DEFAULT_WEIGHTS = {
    "identifier": 0.35,
    "stylometric": 0.2,
    "behavioural": 0.2,
    "temporal": 0.15,
    "infrastructure": 0.1,
}

LIMITATIONS = [
    "A similarity score is decision support only; it is not proof that two accounts share an operator.",
    "Copied text, shared templates and common vocabulary inflate stylometric similarity.",
    "Hourly activity patterns are coarse and can coincide for unrelated actors in the same timezone.",
    "Shared infrastructure can indicate a shared hosting provider, not a shared person.",
    "Absent evidence is not evidence of absence: coverage below 40% caps the result at Insufficient.",
]


def _normalise_weights(weights: Optional[Dict[str, float]]) -> Dict[str, float]:
    merged = dict(DEFAULT_WEIGHTS)
    if weights:
        for key, value in weights.items():
            if key in merged:
                try:
                    merged[key] = max(0.0, float(value))
                except (TypeError, ValueError):
                    continue
    total = sum(merged.values())
    if total <= 0:
        return dict(DEFAULT_WEIGHTS)
    return {k: v / total for k, v in merged.items()}


def final_score(
    id_sim: float,
    styl: float,
    beh: float,
    temp: float,
    infra: float,
    weights: Optional[Dict[str, float]] = None,
    availability: Optional[Dict[str, bool]] = None,
    identifiers: Optional[List[str]] = None,
    details: Optional[Dict[str, Dict]] = None,
) -> Dict:
    """Compute an explainable attribution score.

    Args:
        id_sim: similarity of shared identifiers (0..1).
        styl: writing-style similarity (0..1).
        beh: hourly behavioural similarity (0..1).
        temp: temporal overlap (0..1).
        infra: infrastructure similarity (0..1).
        weights: optional override for feature weights.
        availability: which features had usable evidence. Defaults to all True.
        identifiers: human-readable list of shared identifiers.
        details: optional per-feature diagnostics (counts, sample sizes).

    Returns:
        Dictionary with final score, category, contributions, coverage,
        missing evidence, explanation and limitations.
    """
    weights = _normalise_weights(weights)
    values = {
        "identifier": max(0.0, min(1.0, float(id_sim or 0.0))),
        "stylometric": max(0.0, min(1.0, float(styl or 0.0))),
        "behavioural": max(0.0, min(1.0, float(beh or 0.0))),
        "temporal": max(0.0, min(1.0, float(temp or 0.0))),
        "infrastructure": max(0.0, min(1.0, float(infra or 0.0))),
    }
    if availability is None:
        availability = {k: True for k in weights}
    details = details or {}

    available_weight = sum(w for k, w in weights.items() if availability.get(k))
    total_weight = sum(weights.values()) or 1.0
    coverage = available_weight / total_weight if total_weight else 0.0

    contributions = []
    weighted_sum = 0.0
    for feature, weight in weights.items():
        if not availability.get(feature):
            continue
        contribution = values[feature] * weight
        weighted_sum += contribution
        contributions.append(
            {
                "feature": feature,
                "label": FEATURE_LABELS.get(feature, feature),
                "value": round(values[feature], 4),
                "weight": round(weight, 4),
                "contribution": round(contribution / available_weight if available_weight else 0.0, 4),
                "detail": details.get(feature, {}),
            }
        )

    final = weighted_sum / available_weight if available_weight else 0.0

    if coverage < 0.4:
        category = CATEGORY_INSUFFICIENT
    elif final >= 0.75:
        category = CATEGORY_STRONG
    elif final >= 0.5:
        category = CATEGORY_MODERATE
    elif final >= 0.25:
        category = CATEGORY_WEAK
    else:
        category = CATEGORY_INSUFFICIENT

    missing = [
        FEATURE_LABELS.get(feature, feature)
        for feature, present in availability.items()
        if not present
    ]

    drivers = sorted(
        [c for c in contributions if c["value"] > 0],
        key=lambda c: c["contribution"],
        reverse=True,
    )
    if drivers:
        top = drivers[0]
        explanation = (
            f"Highest contributing evidence is {top['label'].lower()} "
            f"({top['value']:.2f} similarity, {top['contribution'] * 100:.1f}% of the weighted score)."
        )
    else:
        explanation = "No positive similarity evidence was available for this pair."

    if missing:
        explanation += f" Missing evidence: {', '.join(missing).lower()}."

    if identifiers:
        explanation += f" Shared identifiers: {', '.join(identifiers)}."

    return {
        "final": round(final, 4),
        "category": category,
        "hypothesis": (
            "Investigative hypothesis only. The score ranks analytical association; "
            "it must be reviewed by an analyst and is not a statement of real-world identity."
        ),
        "components": {k: round(v, 4) for k, v in values.items()},
        "weights": {k: round(v, 4) for k, v in weights.items()},
        "contributions": contributions,
        "coverage": round(coverage, 4),
        "available": availability,
        "missing_evidence": missing,
        "explanation": explanation,
        "limitations": LIMITATIONS,
    }
