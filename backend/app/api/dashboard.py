"""Dashboard aggregates. Every value comes from the database."""

from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.provenance import (
    hidden_actor_ids,
    hidden_source_ids,
    hide_demo_indicators,
    hide_synthetic_analyses,
    hide_synthetic_evidence,
    hide_synthetic_investigations,
    hide_synthetic_relationships,
    hide_synthetic_sources,
    synthetic_visible,
)
from app.core.time import utcnow
from app.database.session import get_db
from app.models.entities import (
    Actor,
    AnalysisResult,
    AnalystReview,
    AuditLog,
    CollectionJob,
    Evidence,
    Identifier,
    InfrastructureIndicator,
    IntelligenceSource,
    Investigation,
    Relationship,
    TimelineEvent,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def stats(
    include_synthetic: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    show = synthetic_visible(include_synthetic)
    hidden_actors = set() if show else hidden_actor_ids(db)

    actor_query = db.query(Actor)
    if hidden_actors:
        actor_query = actor_query.filter(~Actor.id.in_(hidden_actors))

    rel_query = hide_synthetic_relationships(db.query(Relationship), include_synthetic)
    direct = rel_query.filter(Relationship.direct.is_(True)).count()
    inferred = rel_query.filter(Relationship.direct.is_(False)).count()
    synthetic = db.query(Actor).filter(Actor.origin == "synthetic").count()
    external = db.query(Actor).filter(Actor.origin == "external").count()
    manual = actor_query.filter(Actor.origin.in_(["manual", None])).count()

    evidence_query = hide_synthetic_evidence(db.query(Evidence), include_synthetic)

    investigation_query = hide_synthetic_investigations(
        db.query(Investigation), include_synthetic
    )
    analysis_query = hide_synthetic_analyses(db.query(AnalysisResult), include_synthetic)

    identifier_query = db.query(Identifier)
    indicator_query = hide_demo_indicators(db.query(InfrastructureIndicator), include_synthetic)
    timeline_query = db.query(TimelineEvent)
    if hidden_actors:
        identifier_query = identifier_query.filter(~Identifier.actor_id.in_(hidden_actors))
        timeline_query = timeline_query.filter(~TimelineEvent.actor_id.in_(hidden_actors))

    return {
        "actors": actor_query.count(),
        "identifiers": identifier_query.count(),
        "relationships": rel_query.count(),
        "direct_relationships": direct,
        "inferred_relationships": inferred,
        "infra": indicator_query.count(),
        "sources": hide_synthetic_sources(db.query(IntelligenceSource), include_synthetic).count(),
        "synthetic_sources": db.query(IntelligenceSource).filter(IntelligenceSource.is_synthetic.is_(True)).count(),
        "timeline_events": timeline_query.count(),
        "evidence": evidence_query.count(),
        "investigations": investigation_query.count(),
        "analyses": analysis_query.count(),
        "synthetic_hidden": not show,
        "investigations_review": db.query(AnalystReview)
        .filter(AnalystReview.decision == "pending")
        .count(),
        "actors_synthetic": synthetic,
        "actors_external": external,
        "actors_manual": manual,
        "last_collection": (
            db.query(CollectionJob)
            .order_by(CollectionJob.started_at.desc())
            .first()
            .started_at
            if db.query(CollectionJob).count()
            else None
        ),
    }


@router.get("/charts/category")
def category_chart(include_synthetic: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    query = db.query(Actor.threat_category, func.count(Actor.id))
    if not synthetic_visible(include_synthetic):
        hidden = hidden_actor_ids(db)
        if hidden:
            query = query.filter(~Actor.id.in_(hidden))
    rows = (
        query.group_by(Actor.threat_category)
        .order_by(func.count(Actor.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/activity")
def activity_chart(days: int = 90, include_synthetic: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    cutoff = utcnow() - timedelta(days=max(1, min(days, 3650)))
    query = db.query(TimelineEvent.event_date)
    if not synthetic_visible(include_synthetic):
        hidden = hidden_actor_ids(db)
        if hidden:
            query = query.filter(
                TimelineEvent.actor_id.is_(None) | (~TimelineEvent.actor_id.in_(hidden))
            )
    rows = (
        query
        .filter(TimelineEvent.event_date.isnot(None))
        .filter(TimelineEvent.event_date >= cutoff)
        .all()
    )
    counts = Counter(row[0].date().isoformat() for row in rows if row[0])
    return [{"date": day, "count": count} for day, count in sorted(counts.items())]


@router.get("/charts/sources")
def sources_chart(include_synthetic: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    query = db.query(IntelligenceSource.name, func.count(IntelligenceSource.id))
    if not synthetic_visible(include_synthetic):
        query = query.filter(
            (IntelligenceSource.is_synthetic.is_(False)) | (IntelligenceSource.is_synthetic.is_(None))
        )
    rows = (
        query.group_by(IntelligenceSource.name)
        .order_by(func.count(IntelligenceSource.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/identifiers")
def identifier_chart(include_synthetic: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    query = db.query(Identifier.id_type, func.count(Identifier.id))
    if not synthetic_visible(include_synthetic):
        hidden = hidden_actor_ids(db)
        if hidden:
            query = query.filter(~Identifier.actor_id.in_(hidden))
    rows = (
        query
        .group_by(Identifier.id_type)
        .order_by(func.count(Identifier.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/relationships")
def relationship_chart(include_synthetic: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    query = db.query(Relationship.rel_type, func.count(Relationship.id))
    query = hide_synthetic_relationships(query, include_synthetic)
    rows = (
        query.group_by(Relationship.rel_type)
        .order_by(func.count(Relationship.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/origin")
def origin_chart(include_synthetic: bool = False, db: Session = Depends(get_db), user=Depends(get_current_user)):
    query = db.query(Actor.origin, func.count(Actor.id))
    if not synthetic_visible(include_synthetic):
        hidden = hidden_actor_ids(db)
        if hidden:
            query = query.filter(~Actor.id.in_(hidden))
    rows = (
        query.group_by(Actor.origin)
        .all()
    )
    return [{"name": row[0] or "manual", "value": row[1]} for row in rows]


@router.get("/recent")
def recent(db: Session = Depends(get_db), user=Depends(get_current_user)):
    jobs = (
        db.query(CollectionJob)
        .order_by(CollectionJob.started_at.desc(), CollectionJob.id.desc())
        .limit(10)
        .all()
    )
    return [
        {
            "id": job.id,
            "source": job.source_name,
            "status": job.status,
            "records": job.records_imported,
            "started": job.started_at,
            "finished": job.finished_at,
        }
        for job in jobs
    ]


@router.get("/activity-log")
def activity_log(limit: int = 20, db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(max(1, min(limit, 100)))
        .all()
    )
    return [
        {
            "id": row.id,
            "user": row.user,
            "action": row.action,
            "details": row.details,
            "created_at": row.created_at,
        }
        for row in rows
    ]
