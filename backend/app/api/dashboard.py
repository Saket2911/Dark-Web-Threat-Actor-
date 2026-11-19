"""Dashboard aggregates. Every value comes from the database."""

from collections import Counter
from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
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
def stats(db: Session = Depends(get_db), user=Depends(get_current_user)):
    direct = db.query(Relationship).filter(Relationship.direct.is_(True)).count()
    inferred = db.query(Relationship).filter(Relationship.direct.is_(False)).count()
    synthetic = db.query(Actor).filter(Actor.origin == "synthetic").count()
    external = db.query(Actor).filter(Actor.origin == "external").count()
    manual = db.query(Actor).filter(Actor.origin == "manual").count()
    return {
        "actors": db.query(Actor).count(),
        "identifiers": db.query(Identifier).count(),
        "relationships": db.query(Relationship).count(),
        "direct_relationships": direct,
        "inferred_relationships": inferred,
        "infra": db.query(InfrastructureIndicator).count(),
        "sources": db.query(IntelligenceSource).count(),
        "synthetic_sources": db.query(IntelligenceSource).filter(IntelligenceSource.is_synthetic.is_(True)).count(),
        "timeline_events": db.query(TimelineEvent).count(),
        "evidence": db.query(Evidence).count(),
        "investigations": db.query(Investigation).count(),
        "analyses": db.query(AnalysisResult).count(),
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
def category_chart(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(Actor.threat_category, func.count(Actor.id))
        .group_by(Actor.threat_category)
        .order_by(func.count(Actor.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/activity")
def activity_chart(days: int = 90, db: Session = Depends(get_db), user=Depends(get_current_user)):
    cutoff = utcnow() - timedelta(days=max(1, min(days, 3650)))
    rows = (
        db.query(TimelineEvent.event_date)
        .filter(TimelineEvent.event_date.isnot(None))
        .filter(TimelineEvent.event_date >= cutoff)
        .all()
    )
    counts = Counter(row[0].date().isoformat() for row in rows if row[0])
    return [{"date": day, "count": count} for day, count in sorted(counts.items())]


@router.get("/charts/sources")
def sources_chart(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(IntelligenceSource.name, func.count(IntelligenceSource.id))
        .group_by(IntelligenceSource.name)
        .order_by(func.count(IntelligenceSource.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/identifiers")
def identifier_chart(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(Identifier.id_type, func.count(Identifier.id))
        .group_by(Identifier.id_type)
        .order_by(func.count(Identifier.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/relationships")
def relationship_chart(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(Relationship.rel_type, func.count(Relationship.id))
        .group_by(Relationship.rel_type)
        .order_by(func.count(Relationship.id).desc())
        .all()
    )
    return [{"name": row[0] or "unknown", "value": row[1]} for row in rows]


@router.get("/charts/origin")
def origin_chart(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(Actor.origin, func.count(Actor.id))
        .group_by(Actor.origin)
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
