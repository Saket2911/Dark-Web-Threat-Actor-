"""Relationship generation engine.

Two kinds of links are produced, always with an explanation and a provenance
classification:

* **Direct** - two actors share an observable identifier value (same PGP
  fingerprint, wallet, verified email, domain or IP). This is a documented
  fact about the *identifier*, not proof that one person operates both
  accounts.
* **Inferred** - an analytical similarity result (stylometry, behaviour or a
  weighted attribution score) crosses the configured threshold. Inferred
  links are always classified ``inferred`` / ``unverified``.

The engine is idempotent: rebuilding relationships never creates duplicates,
never creates self-links and never deletes existing analyst-reviewed records.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import (
    AnalysisResult,
    Identifier,
    InfrastructureIndicator,
    Relationship,
)
from app.services.relationship_validator import (
    RelationshipValidationError,
    classify_existing_confidence,
    create_relationship,
)

# Identifier types that represent infrastructure rather than a persona secret.
INFRA_IDENTIFIER_TYPES = {"domain", "ip", "cert", "url", "infra"}

# Human-readable evidence phrases per identifier type.
IDENTIFIER_LABELS = {
    "pgp": "PGP fingerprint",
    "wallet": "cryptocurrency wallet",
    "email": "email address",
    "domain": "domain",
    "ip": "IP address",
    "username": "username",
    "cert": "certificate",
    "url": "URL",
    "infra": "infrastructure value",
}


def _pair_key(a: int, b: int) -> Tuple[int, int]:
    return (a, b) if a < b else (b, a)


def _existing_pair_keys(db: Session, rel_type: Optional[str] = None) -> set:
    """Return normalised keys of relationships that already exist.

    Handles both legacy actor-to-actor rows and polymorphic actor rows so the
    engine can never duplicate an edge it previously created in either form.
    """
    query = db.query(Relationship)
    if rel_type:
        query = query.filter(Relationship.rel_type == rel_type)
    keys = set()
    for rel in query.all():
        src = rel.source_actor_id or (
            rel.source_entity_id if rel.source_type == "actor" else None
        )
        tgt = rel.target_actor_id or (
            rel.target_entity_id if rel.target_type == "actor" else None
        )
        if src and tgt:
            keys.add(_pair_key(int(src), int(tgt)))
    return keys


def _existing_actor_indicator_edges(db: Session, rel_type: str) -> set:
    rows = (
        db.query(Relationship)
        .filter(Relationship.rel_type == rel_type)
        .all()
    )
    keys = set()
    for rel in rows:
        if (
            rel.source_type == "actor"
            and rel.target_type == "indicator"
            and rel.source_entity_id
            and rel.target_entity_id
        ):
            keys.add((int(rel.source_entity_id), int(rel.target_entity_id)))
    return keys


def collect_shared_identifiers(db: Session) -> Dict[Tuple[int, int], List[Tuple[str, str]]]:
    """Map actor pairs to the identifier (type, value) tuples they share."""
    owners: Dict[Tuple[str, str], set] = defaultdict(set)
    for ident in db.query(Identifier.id_type, Identifier.value, Identifier.actor_id).all():
        if ident.actor_id is None:
            continue
        owners[(ident.id_type, str(ident.value))].add(int(ident.actor_id))

    shared: Dict[Tuple[int, int], List[Tuple[str, str]]] = defaultdict(list)
    for (id_type, value), actor_ids in owners.items():
        if len(actor_ids) < 2:
            continue
        ordered = sorted(actor_ids)
        for i in range(len(ordered)):
            for j in range(i + 1, len(ordered)):
                shared[_pair_key(ordered[i], ordered[j])].append((id_type, value))
    return dict(shared)


def _evidence_for(shared: List[Tuple[str, str]]) -> str:
    parts = []
    for id_type, value in sorted(shared):
        label = IDENTIFIER_LABELS.get(id_type, id_type)
        parts.append(f"{label} {value}")
    return "Shared " + "; ".join(parts)


def build_direct_relationships(db: Session) -> Dict[str, int]:
    """Create SHARED_IDENTIFIER and HAS_IDENTIFIER relationships."""
    stats = {"created": 0, "skipped": 0, "failed": 0}
    existing_pairs = _existing_pair_keys(db, "SHARED_IDENTIFIER")

    for (a_id, b_id), shared in sorted(collect_shared_identifiers(db).items()):
        if (a_id, b_id) in existing_pairs:
            stats["skipped"] += 1
            continue
        # Only identifier types that legitimately identify an operator create an
        # actor-to-actor link. Shared usernames are weak and excluded.
        strong_types = {"pgp", "wallet", "email"}
        has_strong = any(t in strong_types for t, _ in shared)
        has_infra = any(t in INFRA_IDENTIFIER_TYPES for t, _ in shared)
        if not (has_strong or has_infra):
            stats["skipped"] += 1
            continue

        classification, confidence = classify_existing_confidence(
            None, 0.9, True, "SHARED_IDENTIFIER"
        )
        if not has_strong:
            # Shared infrastructure is an association, not a documented
            # identity fact: keep it explicit about the weaker basis.
            confidence = "limited"

        try:
            # Isolate each link in a savepoint: one bad pair must not roll back
            # links that were already created in this build.
            with db.begin_nested():
                create_relationship(
                    db=db,
                    source_type="actor",
                    source_entity_id=a_id,
                    target_type="actor",
                    target_entity_id=b_id,
                    rel_type="SHARED_IDENTIFIER",
                    evidence=_evidence_for(shared)
                    + ". Directly observed shared identifier; does not by itself prove common ownership.",
                    score=0.9 if has_strong else 0.6,
                    relationship_classification=classification,
                    confidence_level=confidence,
                    direct=True,
                    commit=False,
                )
            stats["created"] += 1
            existing_pairs.add((a_id, b_id))
        except (RelationshipValidationError, Exception):
            stats["failed"] += 1

    db.commit()
    stats.update(_build_actor_indicator_links(db))
    db.commit()
    return stats


def _build_actor_indicator_links(db: Session) -> Dict[str, int]:
    """Link actors to infrastructure indicators they demonstrably reference."""
    created = skipped = 0
    indicators = {
        (ind.indicator_type, str(ind.value)): ind
        for ind in db.query(InfrastructureIndicator).all()
    }
    if not indicators:
        return {"indicator_created": 0, "indicator_skipped": 0}

    existing = _existing_actor_indicator_edges(db, "ASSOCIATED_WITH_INFRASTRUCTURE")

    for identifier in db.query(Identifier.actor_id, Identifier.id_type, Identifier.value).all():
        if identifier.actor_id is None:
            continue
        ind = indicators.get((identifier.id_type, str(identifier.value)))
        if ind is None:
            continue
        key = (int(identifier.actor_id), int(ind.id))
        if key in existing:
            skipped += 1
            continue
        try:
            with db.begin_nested():
                create_relationship(
                    db=db,
                    source_type="actor",
                    source_entity_id=int(identifier.actor_id),
                    target_type="indicator",
                    target_entity_id=int(ind.id),
                    rel_type="ASSOCIATED_WITH_INFRASTRUCTURE",
                    evidence=(
                        f"Actor identifier {identifier.id_type} value {identifier.value} matches "
                        f"infrastructure indicator {ind.indicator_type} {ind.value} "
                        f"(source: {ind.source or 'unknown'})."
                    ),
                    score=0.7,
                    relationship_classification="documented",
                    confidence_level="limited",
                    direct=True,
                    commit=False,
                )
            created += 1
            existing.add(key)
        except Exception:
            skipped += 1

    return {"indicator_created": created, "indicator_skipped": skipped}


def build_inferred_relationships(
    db: Session,
    threshold: Optional[float] = None,
    analysis_types: Iterable[str] = ("attribution", "stylometric", "behavioural"),
) -> Dict[str, int]:
    """Create POTENTIALLY_SAME_PERSONA links from stored analysis results."""
    settings = get_settings()
    threshold = settings.inference_threshold if threshold is None else threshold
    stats = {"created": 0, "skipped": 0, "failed": 0, "threshold": threshold}

    existing_pairs = _existing_pair_keys(db, "POTENTIALLY_SAME_PERSONA")

    query = (
        db.query(AnalysisResult)
        .filter(AnalysisResult.score >= threshold)
        .filter(AnalysisResult.actor_a_id.isnot(None))
        .filter(AnalysisResult.actor_b_id.isnot(None))
        .filter(AnalysisResult.analysis_type.in_(list(analysis_types)))
        .order_by(AnalysisResult.score.desc())
    )

    seen_best: Dict[Tuple[int, int], AnalysisResult] = {}
    for result in query.all():
        a, b = int(result.actor_a_id), int(result.actor_b_id)
        if a == b:
            continue
        key = _pair_key(a, b)
        if key not in seen_best or (result.score or 0) > (seen_best[key].score or 0):
            seen_best[key] = result

    for key, result in seen_best.items():
        if key in existing_pairs:
            stats["skipped"] += 1
            continue
        best = seen_best[key]
        classification, confidence = classify_existing_confidence(
            None, float(best.score or 0), False, "POTENTIALLY_SAME_PERSONA"
        )
        try:
            with db.begin_nested():
                create_relationship(
                    db=db,
                    source_type="actor",
                    source_entity_id=key[0],
                    target_type="actor",
                    target_entity_id=key[1],
                    rel_type="POTENTIALLY_SAME_PERSONA",
                    evidence=(
                        f"Analytical similarity ({best.analysis_type}) score "
                        f"{float(best.score or 0):.3f} is at or above the inference threshold "
                        f"{threshold:.2f}. This is an investigative hypothesis, not proof of identity."
                    ),
                    score=float(best.score or 0),
                    relationship_classification=classification,
                    confidence_level=confidence,
                    direct=False,
                    commit=False,
                )
            stats["created"] += 1
            existing_pairs.add(key)
        except Exception:
            stats["failed"] += 1

    db.commit()
    return stats


def rebuild_all(db: Session, threshold: Optional[float] = None) -> Dict[str, object]:
    direct = build_direct_relationships(db)
    inferred = build_inferred_relationships(db, threshold=threshold)
    return {
        "direct": direct,
        "inferred": inferred,
        "created": direct.get("created", 0)
        + direct.get("indicator_created", 0)
        + inferred.get("created", 0),
        "skipped": direct.get("skipped", 0) + inferred.get("skipped", 0),
        "failed": direct.get("failed", 0) + inferred.get("failed", 0),
    }


def relationship_statistics(db: Session) -> Dict[str, object]:
    rows = (
        db.query(Relationship.rel_type, Relationship.relationship_classification)
        .all()
    )
    by_type: Dict[str, int] = defaultdict(int)
    by_classification: Dict[str, int] = defaultdict(int)
    for rel_type, classification in rows:
        by_type[rel_type or "unknown"] += 1
        by_classification[classification or "unresolved"] += 1
    return {
        "total": len(rows),
        "by_type": dict(by_type),
        "by_classification": dict(by_classification),
        "direct": sum(
            1 for r in db.query(Relationship).filter(Relationship.direct.is_(True)).all()
        ),
    }
