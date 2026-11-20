"""Infrastructure intelligence API (passive indicators only)."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.provenance import (
    hidden_actor_ids,
    hidden_indicator_ids,
    hide_demo_indicators,
    synthetic_visible,
)
from app.core.time import utcnow
from app.database.session import get_db
from app.models.entities import (
    Actor,
    Evidence,
    Identifier,
    InfrastructureIndicator,
    IntelligenceSource,
    Relationship,
)
from app.services.audit import audit
from app.services.identifiers import normalize_identifier

router = APIRouter(prefix="/infrastructure", tags=["infrastructure"])

INFRA_TYPES = {"domain", "ip", "cert", "url", "infra", "hash"}


def _serialize(indicator: InfrastructureIndicator) -> dict:
    return {
        "id": indicator.id,
        "type": indicator.indicator_type,
        "value": indicator.value,
        "metadata": indicator.metadata_json or {},
        "source": indicator.source,
        "reliability": indicator.reliability,
        "origin": indicator.origin,
        "last_observed": indicator.last_observed,
    }


@router.get("")
def list_infra(
    q: Optional[str] = None,
    type_filter: Optional[str] = Query(None, alias="type"),
    origin: Optional[str] = None,
    include_synthetic: bool = Query(False, description="Include labelled demonstration records (never in production)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    query = hide_demo_indicators(db.query(InfrastructureIndicator), include_synthetic)
    if q:
        term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                InfrastructureIndicator.value.ilike(term),
                InfrastructureIndicator.source.ilike(term),
            )
        )
    if type_filter:
        query = query.filter(InfrastructureIndicator.indicator_type == type_filter)
    if origin:
        query = query.filter(InfrastructureIndicator.origin == origin)

    total = query.count()
    rows = (
        query.order_by(InfrastructureIndicator.last_observed.desc(), InfrastructureIndicator.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    types = [
        {"type": row[0], "count": row[1]}
        for row in hide_demo_indicators(
            db.query(
                InfrastructureIndicator.indicator_type, func.count(InfrastructureIndicator.id)
            ),
            include_synthetic,
        )
        .group_by(InfrastructureIndicator.indicator_type)
        .all()
    ]
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "types": types,
        "items": [_serialize(row) for row in rows],
    }


@router.get("/{indicator_id}")
def get_indicator(
    indicator_id: int,
    include_synthetic: bool = Query(False, description="Include demonstration indicators (never in production)"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    indicator = db.query(InfrastructureIndicator).filter(InfrastructureIndicator.id == indicator_id).first()
    if not indicator:
        raise HTTPException(404, "Indicator not found")
    if not synthetic_visible(include_synthetic) and indicator.id in hidden_indicator_ids(db):
        raise HTTPException(404, "Indicator not found")

    associations, seen = [], set()
    hidden_actors = set() if synthetic_visible(include_synthetic) else hidden_actor_ids(db)

    # 1. Actors whose identifier value matches the indicator value.
    for identifier in db.query(Identifier).filter(
        Identifier.value == indicator.value,
        Identifier.id_type.in_(INFRA_TYPES),
    ).all():
        actor = db.query(Actor).filter(Actor.id == identifier.actor_id).first()
        if actor and actor.id not in seen and actor.id not in hidden_actors:
            seen.add(actor.id)
            associations.append(
                {
                    "actor_id": actor.id,
                    "handle": actor.primary_handle,
                    "internal_id": actor.internal_id,
                    "basis": f"actor identifier {identifier.id_type} matches indicator value",
                    "identifier_source": identifier.source,
                }
            )

    # 2. Explicit relationship-based associations (e.g. ASSOCIATED_WITH_INFRASTRUCTURE).
    relationships = (
        db.query(Relationship)
        .filter(
            or_(
                (Relationship.target_type == "indicator") & (Relationship.target_entity_id == indicator.id),
                (Relationship.source_type == "indicator") & (Relationship.source_entity_id == indicator.id),
            )
        )
        .all()
    )
    for rel in relationships:
        if rel.source_type == "actor" and rel.target_entity_id == indicator.id:
            actor = db.query(Actor).filter(Actor.id == rel.source_entity_id).first()
            if actor and actor.id not in seen and actor.id not in hidden_actors:
                seen.add(actor.id)
                associations.append(
                    {
                        "actor_id": actor.id,
                        "handle": actor.primary_handle,
                        "internal_id": actor.internal_id,
                        "basis": f"{rel.rel_type} relationship ({rel.relationship_classification})",
                        "identifier_source": None,
                    }
                )

    evidence_rows = (
        db.query(Evidence, IntelligenceSource)
        .outerjoin(IntelligenceSource, Evidence.source_id == IntelligenceSource.id)
        .filter(Evidence.entity_type == "indicator", Evidence.entity_id == indicator.id)
        .all()
    )

    malware_links = (
        db.query(Relationship)
        .filter(
            Relationship.source_type == "indicator",
            Relationship.source_entity_id == indicator.id,
            Relationship.target_type == "malware",
        )
        .all()
    )

    return {
        "indicator": _serialize(indicator),
        "associated_actors": associations,
        "evidence": [
            {
                "id": ev.id,
                "evidence_type": ev.evidence_type,
                "content": ev.content,
                "reference": ev.reference,
                "source": src.name if src else None,
                "is_synthetic": src.is_synthetic if src else None,
                "reliability": ev.reliability,
                "collected_at": ev.collected_at,
            }
            for ev, src in evidence_rows
        ],
        "malware_links": [
            {
                "relationship_id": rel.id,
                "malware_id": rel.target_entity_id,
                "rel_type": rel.rel_type,
                "evidence": rel.evidence,
            }
            for rel in malware_links
        ],
        "note": (
            "Associations are derived from recorded identifier matches and stored "
            "relationships. No active probing or scanning is performed."
        ),
    }


@router.get("/{indicator_id}/associations")
def indicator_associations(
    indicator_id: int,
    include_synthetic: bool = Query(False),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    detail = get_indicator(
        indicator_id, include_synthetic=include_synthetic, db=db, user=user
    )
    return {
        "indicator": detail["indicator"],
        "associated_actors": detail["associated_actors"],
        "note": detail["note"],
    }


@router.post("", status_code=201)
def create_indicator(body: dict, db: Session = Depends(get_db), user=Depends(get_current_user)):
    indicator_type = str(body.get("indicator_type") or body.get("type") or "").strip().lower()
    value = str(body.get("value") or "").strip()
    if indicator_type not in INFRA_TYPES:
        raise HTTPException(422, f"indicator_type must be one of {sorted(INFRA_TYPES)}")
    if not value:
        raise HTTPException(422, "value is required")

    normalized_value = value
    if indicator_type in ("domain", "ip"):
        try:
            _kind, normalized_value = normalize_identifier(indicator_type, value)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    duplicate = (
        db.query(InfrastructureIndicator)
        .filter(
            InfrastructureIndicator.indicator_type == indicator_type,
            InfrastructureIndicator.value == normalized_value,
        )
        .first()
    )
    if duplicate:
        raise HTTPException(409, f"Indicator already exists (id {duplicate.id})")

    indicator = InfrastructureIndicator(
        indicator_type=indicator_type,
        value=normalized_value,
        metadata_json=body.get("metadata") or {},
        source=body.get("source") or "analyst",
        origin="manual",
        reliability=float(body.get("reliability") or 0.5),
        last_observed=utcnow(),
    )
    db.add(indicator)
    db.commit()
    db.refresh(indicator)
    audit(db, user.username, "create_indicator", f"indicator {indicator.id}")
    return _serialize(indicator)
