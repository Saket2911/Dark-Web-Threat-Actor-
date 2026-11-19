"""Behavioural (hourly activity) similarity.

Activity is aggregated into a normalised 24-hour distribution per actor and
compared with cosine similarity. Missing or sparse data is reported explicitly
rather than silently converted into a similarity of zero.
"""

from __future__ import annotations

from typing import Dict, Tuple

import numpy as np
from sqlalchemy.orm import Session

from app.models.entities import TimelineEvent

DEFAULT_MIN_EVENTS = 3

HOUR_LABELS = [f"{h:02d}:00" for h in range(24)]


def _activity_vector(actor_id: int, db: Session):
    """Return (normalised 24-bin vector, raw counts, event count)."""
    counts = [0] * 24
    events = (
        db.query(TimelineEvent.event_date)
        .filter(TimelineEvent.actor_id == actor_id)
        .all()
    )
    for (event_date,) in events:
        if event_date is not None:
            counts[event_date.hour] += 1
    total = sum(counts)
    vector = np.array(counts, dtype=float) / total if total else np.zeros(24, dtype=float)
    return vector, counts, total


def _active_hours(counts, threshold: float = 0.1):
    total = sum(counts) or 1
    return [
        HOUR_LABELS[hour]
        for hour, value in enumerate(counts)
        if value / total >= threshold
    ]


def behavioural_similarity(
    actor_a_id: int,
    actor_b_id: int,
    db: Session,
    min_events: int = DEFAULT_MIN_EVENTS,
) -> Tuple[float, Dict]:
    """Compare hourly activity patterns of two actors."""
    va, counts_a, total_a = _activity_vector(actor_a_id, db)
    vb, counts_b, total_b = _activity_vector(actor_b_id, db)

    sufficient = total_a >= min_events and total_b >= min_events

    if total_a == 0 or total_b == 0:
        return 0.0, {
            "reason": "no activity data for one or both actors",
            "sufficient": False,
            "activity_count_a": total_a,
            "activity_count_b": total_b,
            "explanation": (
                "Hourly activity comparison needs timeline events for both actors. "
                "One or both actors have no dated events."
            ),
            "hours_a": counts_a,
            "hours_b": counts_b,
        }

    from sklearn.metrics.pairwise import cosine_similarity

    similarity = float(cosine_similarity([va], [vb])[0][0])

    active_a = _active_hours(counts_a)
    active_b = _active_hours(counts_b)
    overlap = sorted(set(active_a) & set(active_b))

    parts = [f"Cosine similarity of the 24-hour activity distributions is {similarity:.2f}."]
    if overlap:
        parts.append(f"Both actors are active around {', '.join(overlap[:6])}.")
    else:
        parts.append("The dominant active hours do not overlap.")

    warnings = []
    if not sufficient:
        warnings.append(
            f"Fewer than {min_events} dated events for at least one actor; the distribution is sparse."
        )
    if total_a < 10 or total_b < 10:
        warnings.append("Low event counts make hourly patterns unstable.")

    return round(similarity, 4), {
        "cosine": round(similarity, 4),
        "activity_count_a": total_a,
        "activity_count_b": total_b,
        "hours_a": counts_a,
        "hours_b": counts_b,
        "active_hours_a": active_a,
        "active_hours_b": active_b,
        "overlapping_hours": overlap,
        "sufficient": sufficient,
        "warnings": warnings,
        "explanation": " ".join(parts),
        "note": "Hourly activity similarity can reflect shared time zones or market schedules, not a shared operator.",
    }
