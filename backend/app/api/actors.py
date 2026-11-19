from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload

from app.core.deps import get_current_user, require_admin
from app.core.time import utcnow
from app.database.session import get_db
from app.models.entities import (
    Actor,
    AnalystReview,
    Campaign,
    Evidence,
    Handle,
    Identifier,
    InfrastructureIndicator,
    IntelligenceSource,
    Malware,
    Relationship,
    Technique,
    TimelineEvent,
    Tool,
)
from app.schemas.schemas import (
    ActorCreate,
    ActorUpdate,
    EvidenceIn,
    HandleIn,
    IdentifierIn,
    TimelineEventIn,
)
from app.services.audit import audit
from app.services.evidence_validator import EvidenceValidationError, create_evidence
from app.services.identifiers import IDENTIFIER_TYPES, normalize_identifier

router = APIRouter(prefix="/actors", tags=["actors"])

VALID_ORIGINS = ["synthetic", "external", "manual"]
VALID_STATUSES = ["open", "review", "closed"]
ENTITY_MODELS = {
    "campaign": (Campaign, "name"),
    "malware": (Malware, "name"),
    "tool": (Tool, "name"),
    "technique": (Technique, "name"),
    "indicator": (InfrastructureIndicator, "value"),
}


def _serialize_actor(actor: Actor, include_counts: bool = False) -> dict:
    payload = {
        "id": actor.id,
        "internal_id": actor.internal_id,
        "primary_handle": actor.primary_handle,
        "threat_category": actor.threat_category,
        "investigation_status": actor.investigation_status,
        "last_observed": actor.last_observed,
        "notes": actor.notes,
        "created_at": actor.created_at,
        "origin": actor.origin,
        "external_id": actor.external_id,
        "source_url": actor.source_url,
    }
    if include_counts:
        payload["identifier_count"] = len(actor.identifiers)
        payload["handle_count"] = len(actor.handles)
        payload["timeline_count"] = len(actor.timeline_events)
    return payload


def _get_actor_or_404(db: Session, actor_id: int) -> Actor:
    actor = db.query(Actor).filter(Actor.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return actor


def _resolve_other_entity(db: Session, entity_type: Optional[str], entity_id: Optional[int]):
    if not entity_id:
        return None, None
    if entity_type == "actor":
        other = db.query(Actor).filter(Actor.id == entity_id).first()
        if other:
            return other.primary_handle or other.internal_id, other.internal_id
        return None, None
    model_info = ENTITY_MODELS.get(entity_type or "")
    if not model_info:
        return None, None
    model, field = model_info
    obj = db.query(model).filter(model.id == entity_id).first()
    if not obj:
        return None, None
    return getattr(obj, field, None), None


def _serialize_relationship(db: Session, rel: Relationship, actor_id: int) -> dict:
    if (rel.source_type == "actor" and rel.source_entity_id == actor_id) or rel.source_actor_id == actor_id:
        other_type = rel.target_type or "actor"
        other_id = rel.target_entity_id or rel.target_actor_id
    else:
        other_type = rel.source_type or "actor"
        other_id = rel.source_entity_id or rel.source_actor_id

    other_name, other_internal_id = _resolve_other_entity(db, other_type, other_id)
    reviews = (
        db.query(AnalystReview)
        .filter(AnalystReview.relationship_id == rel.id)
        .order_by(AnalystReview.reviewed_at.desc())
        .all()
    )
    return {
        "relationship_id": rel.id,
        "rel_type": rel.rel_type,
        "score": rel.score,
        "direct": rel.direct,
        "other_type": other_type,
        "other_id": other_id,
        "other_name": other_name,
        "other_handle": other_name if other_type == "actor" else None,
        "other_internal_id": other_internal_id,
        "evidence": rel.evidence,
        "relationship_classification": rel.relationship_classification,
        "confidence_level": rel.confidence_level,
        "source_confidence": rel.source_confidence,
        "created_at": rel.created_at,
        "review_decision": reviews[0].decision if reviews else None,
    }


@router.get("")
def list_actors(
    q: Optional[str] = None,
    category: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    origin: Optional[str] = Query(None, description="Filter by origin: synthetic, external, manual"),
    sort: str = Query("handle", pattern="^(handle|id|last_observed|category)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    query = db.query(Actor).options(
        joinedload(Actor.identifiers), joinedload(Actor.handles), joinedload(Actor.timeline_events)
    )
    if q:
        term = f"%{q.strip()}%"
        query = query.filter(
            or_(
                Actor.primary_handle.ilike(term),
                Actor.internal_id.ilike(term),
                Actor.external_id.ilike(term),
            )
        )
    if category:
        query = query.filter(Actor.threat_category == category)
    if status_filter:
        if status_filter not in VALID_STATUSES:
            raise HTTPException(400, f"Invalid status. Valid: {VALID_STATUSES}")
        query = query.filter(Actor.investigation_status == status_filter)
    if origin is not None:
        if origin not in VALID_ORIGINS:
            raise HTTPException(400, f"Invalid origin: '{origin}'. Valid: {VALID_ORIGINS}")
        query = query.filter(Actor.origin == origin)

    order = {
        "handle": Actor.primary_handle.asc(),
        "id": Actor.id.asc(),
        "last_observed": Actor.last_observed.desc(),
        "category": Actor.threat_category.asc(),
    }[sort]

    total = query.count()
    items = query.order_by(order).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "items": [_serialize_actor(a, include_counts=True) for a in items],
    }


@router.get("/categories")
def actor_categories(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(Actor.threat_category, func.count(Actor.id))
        .group_by(Actor.threat_category)
        .order_by(Actor.threat_category)
        .all()
    )
    return [{"category": row[0] or "unknown", "count": row[1]} for row in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_actor(body: ActorCreate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    import uuid

    actor = Actor(
        internal_id=f"TA{uuid.uuid4().hex[:8].upper()}",
        primary_handle=(body.primary_handle or "").strip() or None,
        threat_category=(body.threat_category or "").strip() or None,
        notes=body.notes,
        investigation_status=body.investigation_status or "open",
        origin="manual",
        last_observed=utcnow(),
    )
    db.add(actor)
    db.commit()
    db.refresh(actor)
    audit(db, user.username, "create_actor", f"actor {actor.id} ({actor.primary_handle})")
    return _serialize_actor(actor)


@router.get("/{actor_id}")
def get_actor(actor_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    actor = (
        db.query(Actor)
        .options(joinedload(Actor.handles), joinedload(Actor.identifiers))
        .filter(Actor.id == actor_id)
        .first()
    )
    if not actor:
        raise HTTPException(404, "Actor not found")
    return _serialize_actor(actor, include_counts=True)


@router.put("/{actor_id}")
@router.patch("/{actor_id}")
def update_actor(actor_id: int, body: ActorUpdate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    actor = _get_actor_or_404(db, actor_id)
    data = body.model_dump(exclude_unset=True)
    if not data:
        raise HTTPException(400, "No fields supplied")
    if "investigation_status" in data and data["investigation_status"] not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Valid: {VALID_STATUSES}")
    for field, value in data.items():
        setattr(actor, field, value)
    db.commit()
    db.refresh(actor)
    audit(db, user.username, "update_actor", f"actor {actor.id}: {', '.join(data)}")
    return _serialize_actor(actor)


@router.delete("/{actor_id}")
def delete_actor(actor_id: int, db: Session = Depends(get_db), user=Depends(require_admin)):
    actor = _get_actor_or_404(db, actor_id)
    handle = actor.primary_handle
    # Remove relationships and reviews that reference this actor to keep the
    # graph consistent (SQLite has no cascading polymorphic constraints).
    db.query(Relationship).filter(
        or_(
            Relationship.source_actor_id == actor_id,
            Relationship.target_actor_id == actor_id,
            (Relationship.source_type == "actor") & (Relationship.source_entity_id == actor_id),
            (Relationship.target_type == "actor") & (Relationship.target_entity_id == actor_id),
        )
    ).delete(synchronize_session=False)
    db.delete(actor)
    db.commit()
    audit(db, user.username, "delete_actor", f"actor {actor_id} ({handle})")
    return {"ok": True, "deleted_id": actor_id}


@router.get("/{actor_id}/profile")
def actor_profile(actor_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    actor = (
        db.query(Actor)
        .options(
            joinedload(Actor.handles),
            joinedload(Actor.identifiers),
            joinedload(Actor.timeline_events),
        )
        .filter(Actor.id == actor_id)
        .first()
    )
    if not actor:
        raise HTTPException(404, "Actor not found")

    relationships = (
        db.query(Relationship)
        .filter(
            or_(
                Relationship.source_actor_id == actor_id,
                Relationship.target_actor_id == actor_id,
                (Relationship.source_type == "actor") & (Relationship.source_entity_id == actor_id),
                (Relationship.target_type == "actor") & (Relationship.target_entity_id == actor_id),
            )
        )
        .order_by(Relationship.score.desc())
        .all()
    )

    evidence_rows = (
        db.query(Evidence, IntelligenceSource)
        .outerjoin(IntelligenceSource, Evidence.source_id == IntelligenceSource.id)
        .filter(or_(Evidence.actor_id == actor_id, (Evidence.entity_type == "actor") & (Evidence.entity_id == actor_id)))
        .order_by(Evidence.collected_at.desc())
        .limit(100)
        .all()
    )

    return {
        **_serialize_actor(actor),
        "handles": [
            {
                "id": h.id,
                "handle": h.handle,
                "marketplace": h.marketplace,
                "first_seen": h.first_seen,
                "last_seen": h.last_seen,
            }
            for h in sorted(actor.handles, key=lambda x: x.id)
        ],
        "identifiers": [
            {
                "id": i.id,
                "id_type": i.id_type,
                "type_label": IDENTIFIER_TYPES.get(i.id_type, i.id_type),
                "value": i.value,
                "source": i.source,
                "reliability": i.reliability,
                "origin": i.origin,
            }
            for i in sorted(actor.identifiers, key=lambda x: x.id)
        ],
        "timeline": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "description": e.description,
                "event_date": e.event_date,
                "source": e.source,
            }
            for e in sorted(
                actor.timeline_events,
                key=lambda x: (x.event_date is None, x.event_date or utcnow()),
            )
        ],
        "evidence": [
            {
                "id": ev.id,
                "evidence_type": ev.evidence_type,
                "content": ev.content,
                "reference": ev.reference,
                "source": source.name if source else None,
                "source_type": source.source_type if source else None,
                "is_synthetic": source.is_synthetic if source else None,
                "reliability": ev.reliability,
                "source_confidence": ev.source_confidence,
                "collected_at": ev.collected_at,
                "source_url": ev.source_url,
            }
            for ev, source in evidence_rows
        ],
        "related": [_serialize_relationship(db, rel, actor_id) for rel in relationships],
    }


@router.get("/{actor_id}/identifiers")
def list_identifiers(actor_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    _get_actor_or_404(db, actor_id)
    rows = db.query(Identifier).filter(Identifier.actor_id == actor_id).order_by(Identifier.id).all()
    return [
        {
            "id": row.id,
            "id_type": row.id_type,
            "type_label": IDENTIFIER_TYPES.get(row.id_type, row.id_type),
            "value": row.value,
            "source": row.source,
            "reliability": row.reliability,
            "origin": row.origin,
        }
        for row in rows
    ]


@router.post("/{actor_id}/identifiers", status_code=status.HTTP_201_CREATED)
def add_identifier(
    actor_id: int,
    body: IdentifierIn,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    actor = _get_actor_or_404(db, actor_id)
    try:
        kind, normalized = normalize_identifier(body.id_type, body.value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    duplicate = (
        db.query(Identifier)
        .filter(
            Identifier.actor_id == actor.id,
            Identifier.id_type == kind,
            Identifier.value == normalized,
        )
        .first()
    )
    if duplicate:
        raise HTTPException(
            status_code=409,
            detail=f"Identifier already recorded for this actor (id {duplicate.id})",
        )

    identifier = Identifier(
        actor_id=actor.id,
        id_type=kind,
        value=normalized,
        source=body.source,
        reliability=body.reliability,
        origin="manual",
    )
    db.add(identifier)
    db.commit()
    db.refresh(identifier)
    audit(db, user.username, "add_identifier", f"actor {actor.id} {kind}")
    return {
        "id": identifier.id,
        "actor_id": actor.id,
        "id_type": kind,
        "type_label": IDENTIFIER_TYPES.get(kind, kind),
        "value": normalized,
        "source": identifier.source,
        "reliability": identifier.reliability,
        "origin": identifier.origin,
    }


@router.delete("/{actor_id}/identifiers/{identifier_id}")
def delete_identifier(
    actor_id: int,
    identifier_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    identifier = (
        db.query(Identifier)
        .filter(Identifier.id == identifier_id, Identifier.actor_id == actor_id)
        .first()
    )
    if not identifier:
        raise HTTPException(404, "Identifier not found for this actor")
    db.delete(identifier)
    db.commit()
    audit(db, user.username, "delete_identifier", f"actor {actor_id} identifier {identifier_id}")
    return {"ok": True}


@router.post("/{actor_id}/handles", status_code=status.HTTP_201_CREATED)
def add_handle(actor_id: int, body: HandleIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    actor = _get_actor_or_404(db, actor_id)
    handle = (body.handle or "").strip()
    if not handle:
        raise HTTPException(422, "handle is required")
    duplicate = (
        db.query(Handle)
        .filter(
            Handle.actor_id == actor.id,
            Handle.handle == handle,
            Handle.marketplace == body.marketplace,
        )
        .first()
    )
    if duplicate:
        raise HTTPException(409, "Handle already recorded for this actor and marketplace")
    record = Handle(
        actor_id=actor.id,
        handle=handle,
        marketplace=body.marketplace,
        first_seen=body.first_seen,
        last_seen=body.last_seen or utcnow(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    audit(db, user.username, "add_handle", f"actor {actor.id} handle {handle}")
    return {
        "id": record.id,
        "handle": record.handle,
        "marketplace": record.marketplace,
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
    }


@router.get("/{actor_id}/evidence")
def list_evidence(actor_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    _get_actor_or_404(db, actor_id)
    rows = (
        db.query(Evidence, IntelligenceSource)
        .outerjoin(IntelligenceSource, Evidence.source_id == IntelligenceSource.id)
        .filter(or_(Evidence.actor_id == actor_id, (Evidence.entity_type == "actor") & (Evidence.entity_id == actor_id)))
        .order_by(Evidence.collected_at.desc())
        .all()
    )
    return [
        {
            "id": ev.id,
            "evidence_type": ev.evidence_type,
            "content": ev.content,
            "reference": ev.reference,
            "source": src.name if src else None,
            "is_synthetic": src.is_synthetic if src else None,
            "reliability": ev.reliability,
            "source_confidence": ev.source_confidence,
            "collected_at": ev.collected_at,
        }
        for ev, src in rows
    ]


@router.post("/{actor_id}/evidence", status_code=status.HTTP_201_CREATED)
def add_evidence(actor_id: int, body: EvidenceIn, db: Session = Depends(get_db), user=Depends(get_current_user)):
    actor = _get_actor_or_404(db, actor_id)
    source_name = (body.source or "Analyst observation").strip()
    source = db.query(IntelligenceSource).filter(IntelligenceSource.name == source_name).first()
    if not source:
        source = IntelligenceSource(
            name=source_name,
            source_type="analyst",
            reliability=body.reliability,
            is_synthetic=False,
            origin="manual",
        )
        db.add(source)
        db.commit()
        db.refresh(source)

    try:
        evidence = create_evidence(
            db=db,
            source_id=source.id,
            evidence_type=body.evidence_type,
            entity_type="actor",
            entity_id=actor.id,
            content=body.content,
            reference=body.reference,
            source_url=body.source_url,
            reliability=body.reliability,
            actor_id=actor.id,
        )
    except EvidenceValidationError as exc:
        raise HTTPException(422, str(exc)) from exc

    audit(db, user.username, "add_evidence", f"actor {actor.id} evidence {evidence.id}")
    return {
        "id": evidence.id,
        "actor_id": actor.id,
        "evidence_type": evidence.evidence_type,
        "source": source.name,
        "is_synthetic": source.is_synthetic,
        "reliability": evidence.reliability,
        "collected_at": evidence.collected_at,
    }


@router.post("/{actor_id}/timeline", status_code=status.HTTP_201_CREATED)
def add_timeline_event(
    actor_id: int,
    body: TimelineEventIn,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    _get_actor_or_404(db, actor_id)
    event = TimelineEvent(
        actor_id=actor_id,
        event_type=body.event_type,
        description=body.description,
        event_date=body.event_date or utcnow(),
        source=body.source,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    audit(db, user.username, "add_timeline_event", f"actor {actor_id} event {event.id}")
    return {
        "id": event.id,
        "actor_id": event.actor_id,
        "event_type": event.event_type,
        "description": event.description,
        "event_date": event.event_date,
        "source": event.source,
    }
