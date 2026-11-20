"""Investigation management and analyst review workflow."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_admin
from app.database.session import get_db
from app.models.entities import (
    Actor,
    AnalysisResult,
    AnalystReview,
    Evidence,
    Investigation,
    InvestigationEntity,
    Relationship,
)
from app.schemas.schemas import (
    InvestigationCreate,
    InvestigationEntityIn,
    InvestigationUpdate,
    ReviewIn,
)
from app.services.audit import audit

router = APIRouter(prefix="/investigations", tags=["investigations"])

DECISIONS = ("pending", "approved", "rejected")


def _get_investigation(db: Session, investigation_id: int) -> Investigation:
    investigation = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not investigation:
        raise HTTPException(404, "Investigation not found")
    return investigation


def _member_actor_ids(db: Session, investigation_id: int) -> List[int]:
    rows = (
        db.query(InvestigationEntity.actor_id)
        .filter(InvestigationEntity.investigation_id == investigation_id)
        .all()
    )
    return [int(row[0]) for row in rows if row[0] is not None]


def _serialize_relationship(db: Session, rel: Relationship) -> dict:
    source_id = rel.source_actor_id or (rel.source_entity_id if rel.source_type == "actor" else None)
    target_id = rel.target_actor_id or (rel.target_entity_id if rel.target_type == "actor" else None)
    source = db.query(Actor).filter(Actor.id == source_id).first() if source_id else None
    target = db.query(Actor).filter(Actor.id == target_id).first() if target_id else None
    return {
        "id": rel.id,
        "rel_type": rel.rel_type,
        "score": rel.score,
        "direct": rel.direct,
        "evidence": rel.evidence,
        "relationship_classification": rel.relationship_classification,
        "confidence_level": rel.confidence_level,
        "created_at": rel.created_at,
        "source_actor": {
            "id": source.id,
            "handle": source.primary_handle,
            "internal_id": source.internal_id,
        }
        if source
        else {"id": source_id, "handle": None, "internal_id": None},
        "target_actor": {
            "id": target.id,
            "handle": target.primary_handle,
            "internal_id": target.internal_id,
        }
        if target
        else {"id": target_id, "handle": None, "internal_id": None},
    }


def _review_counts(db: Session, investigation_id: int) -> dict:
    counts = {decision: 0 for decision in DECISIONS}
    for review in db.query(AnalystReview).filter(AnalystReview.investigation_id == investigation_id).all():
        if review.decision in counts:
            counts[review.decision] += 1
    counts["total"] = sum(counts.values())
    return counts


@router.get("")
def list_investigations(
    status_filter: Optional[str] = Query(None, alias="status"),
    include_synthetic: bool = Query(False, description="Include cases that only reference demonstration records"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from app.core.provenance import hide_synthetic_investigations

    query = hide_synthetic_investigations(db.query(Investigation), include_synthetic)
    if status_filter:
        query = query.filter(Investigation.status == status_filter)
    output = []
    for investigation in query.order_by(Investigation.created_at.desc(), Investigation.id.desc()).all():
        members = _member_actor_ids(db, investigation.id)
        counts = _review_counts(db, investigation.id)
        output.append(
            {
                "id": investigation.id,
                "title": investigation.title,
                "status": investigation.status,
                "created_at": investigation.created_at,
                "notes": investigation.notes,
                "entity_count": len(members),
                "reviews": counts,
            }
        )
    return output


@router.post("", status_code=201)
def create_investigation(
    body: InvestigationCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    investigation = Investigation(title=body.title, status=body.status, notes=body.notes)
    db.add(investigation)
    db.flush()

    added = []
    for actor_id in body.actor_ids:
        actor = db.query(Actor).filter(Actor.id == actor_id).first()
        if not actor:
            db.rollback()
            raise HTTPException(422, f"Actor {actor_id} does not exist")
        db.add(InvestigationEntity(investigation_id=investigation.id, actor_id=actor.id))
        added.append(actor.id)

    db.commit()
    db.refresh(investigation)
    audit(db, user.username, "create_investigation", f"investigation {investigation.id}")
    return {"id": investigation.id, "title": investigation.title, "entities": added}


@router.get("/{investigation_id}")
def get_investigation(
    investigation_id: int,
    include_synthetic: bool = Query(False, description="Include cases built only from demonstration records"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    from app.core.provenance import hidden_investigation_ids, synthetic_visible

    investigation = _get_investigation(db, investigation_id)
    if not synthetic_visible(include_synthetic) and investigation_id in hidden_investigation_ids(db):
        raise HTTPException(404, "Investigation not found")
    member_ids = _member_actor_ids(db, investigation_id)

    entities = []
    for actor_id in member_ids:
        actor = db.query(Actor).filter(Actor.id == actor_id).first()
        if not actor:
            continue
        entities.append(
            {
                "id": actor.id,
                "internal_id": actor.internal_id,
                "handle": actor.primary_handle,
                "category": actor.threat_category,
                "status": actor.investigation_status,
                "origin": actor.origin,
            }
        )

    relationships = []
    if member_ids:
        rows = (
            db.query(Relationship)
            .filter(
                or_(
                    Relationship.source_actor_id.in_(member_ids),
                    Relationship.target_actor_id.in_(member_ids),
                    (Relationship.source_type == "actor") & (Relationship.source_entity_id.in_(member_ids)),
                    (Relationship.target_type == "actor") & (Relationship.target_entity_id.in_(member_ids)),
                )
            )
            .order_by(Relationship.score.desc())
            .all()
        )
        seen = set()
        for rel in rows:
            if rel.id in seen:
                continue
            seen.add(rel.id)
            relationships.append(_serialize_relationship(db, rel))
    relationships = relationships[:200]

    reviews = (
        db.query(AnalystReview)
        .filter(AnalystReview.investigation_id == investigation_id)
        .order_by(AnalystReview.reviewed_at.desc(), AnalystReview.id.desc())
        .all()
    )

    evidence_count = 0
    if member_ids:
        evidence_count = (
            db.query(Evidence)
            .filter(
                or_(
                    Evidence.actor_id.in_(member_ids),
                    (Evidence.entity_type == "actor") & (Evidence.entity_id.in_(member_ids)),
                )
            )
            .count()
        )

    analyses = 0
    if member_ids:
        analyses = (
            db.query(AnalysisResult)
            .filter(
                or_(
                    AnalysisResult.actor_a_id.in_(member_ids),
                    AnalysisResult.actor_b_id.in_(member_ids),
                )
            )
            .count()
        )

    return {
        "id": investigation.id,
        "title": investigation.title,
        "status": investigation.status,
        "created_at": investigation.created_at,
        "notes": investigation.notes,
        "entities": entities,
        "relationships": relationships,
        "reviews": [
            {
                "id": review.id,
                "relationship_id": review.relationship_id,
                "analyst": review.analyst,
                "decision": review.decision,
                "notes": review.notes,
                "reviewed_at": review.reviewed_at,
            }
            for review in reviews
        ],
        "review_counts": _review_counts(db, investigation_id),
        "evidence_count": evidence_count,
        "analysis_count": analyses,
    }


@router.patch("/{investigation_id}")
@router.put("/{investigation_id}")
def update_investigation(
    investigation_id: int,
    body: InvestigationUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    investigation = _get_investigation(db, investigation_id)
    data = body.model_dump(exclude_unset=True)
    if "status" in data and data["status"] not in ("open", "review", "closed"):
        raise HTTPException(422, "status must be open, review or closed")
    for field, value in data.items():
        setattr(investigation, field, value)
    db.commit()
    audit(db, user.username, "update_investigation", f"investigation {investigation_id}")
    return {"id": investigation.id, "status": investigation.status, "title": investigation.title}


@router.post("/{investigation_id}/entities", status_code=201)
def add_entity(
    investigation_id: int,
    body: InvestigationEntityIn,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    _get_investigation(db, investigation_id)
    actor = db.query(Actor).filter(Actor.id == body.actor_id).first()
    if not actor:
        raise HTTPException(422, f"Actor {body.actor_id} does not exist")
    existing = (
        db.query(InvestigationEntity)
        .filter(
            InvestigationEntity.investigation_id == investigation_id,
            InvestigationEntity.actor_id == actor.id,
        )
        .first()
    )
    if existing:
        raise HTTPException(409, "Actor is already part of this investigation")
    link = InvestigationEntity(investigation_id=investigation_id, actor_id=actor.id)
    db.add(link)
    db.commit()
    audit(db, user.username, "add_investigation_entity", f"investigation {investigation_id} actor {actor.id}")
    return {"id": link.id, "actor_id": actor.id}


@router.delete("/{investigation_id}/entities/{actor_id}")
def remove_entity(
    investigation_id: int,
    actor_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    link = (
        db.query(InvestigationEntity)
        .filter(
            InvestigationEntity.investigation_id == investigation_id,
            InvestigationEntity.actor_id == actor_id,
        )
        .first()
    )
    if not link:
        raise HTTPException(404, "Actor is not part of this investigation")
    db.delete(link)
    db.commit()
    audit(db, user.username, "remove_investigation_entity", f"investigation {investigation_id} actor {actor_id}")
    return {"ok": True}


@router.post("/{investigation_id}/review", status_code=201)
def record_review(
    investigation_id: int,
    body: ReviewIn,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    _get_investigation(db, investigation_id)
    member_ids = set(_member_actor_ids(db, investigation_id))

    if body.relationship_id is not None:
        relationship = db.query(Relationship).filter(Relationship.id == body.relationship_id).first()
        if not relationship:
            raise HTTPException(422, f"Relationship {body.relationship_id} does not exist")
        source_id = relationship.source_actor_id or (
            relationship.source_entity_id if relationship.source_type == "actor" else None
        )
        target_id = relationship.target_actor_id or (
            relationship.target_entity_id if relationship.target_type == "actor" else None
        )
        if member_ids and not ({source_id, target_id} & member_ids):
            raise HTTPException(
                422,
                "Relationship does not involve any actor in this investigation",
            )

    review = AnalystReview(
        relationship_id=body.relationship_id,
        investigation_id=investigation_id,
        analyst=user.username,
        decision=body.decision,
        notes=body.notes,
    )
    db.add(review)
    db.commit()
    db.refresh(review)
    audit(
        db,
        user.username,
        "analyst_review",
        f"investigation {investigation_id} decision {body.decision}",
    )
    return {
        "id": review.id,
        "relationship_id": review.relationship_id,
        "decision": review.decision,
        "analyst": review.analyst,
        "notes": review.notes,
        "reviewed_at": review.reviewed_at,
    }


@router.get("/{investigation_id}/reviews")
def list_reviews(investigation_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    _get_investigation(db, investigation_id)
    rows = (
        db.query(AnalystReview)
        .filter(AnalystReview.investigation_id == investigation_id)
        .order_by(AnalystReview.reviewed_at.desc())
        .all()
    )
    return [
        {
            "id": row.id,
            "relationship_id": row.relationship_id,
            "analyst": row.analyst,
            "decision": row.decision,
            "notes": row.notes,
            "reviewed_at": row.reviewed_at,
        }
        for row in rows
    ]


@router.delete("/{investigation_id}")
def delete_investigation(
    investigation_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    investigation = _get_investigation(db, investigation_id)
    db.query(InvestigationEntity).filter(
        InvestigationEntity.investigation_id == investigation_id
    ).delete(synchronize_session=False)
    db.query(AnalystReview).filter(
        AnalystReview.investigation_id == investigation_id
    ).delete(synchronize_session=False)
    db.delete(investigation)
    db.commit()
    audit(db, user.username, "delete_investigation", f"investigation {investigation_id}")
    return {"ok": True}
