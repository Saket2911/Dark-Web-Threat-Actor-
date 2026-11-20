"""Investigation timeline API."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.provenance import hidden_actor_ids, synthetic_visible
from app.core.time import end_of_day, parse_datetime
from app.database.session import get_db
from app.models.entities import Actor, TimelineEvent
from app.schemas.schemas import TimelineEventIn

router = APIRouter(prefix="/timeline", tags=["timeline"])


def _parse_bound(value: Optional[str], name: str) -> Optional[datetime]:
    if not value:
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        raise HTTPException(422, f"Invalid {name} date '{value}'. Use ISO-8601 (YYYY-MM-DD).")
    return parsed


@router.get("")
def list_timeline(
    actor_id: Optional[int] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    event_type: Optional[str] = None,
    order: str = Query("asc", pattern="^(asc|desc)$"),
    limit: int = Query(500, ge=1, le=2000),
    include_synthetic: bool = Query(False, description="Include labelled demonstration records (never in production)"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    start_dt = _parse_bound(start, "start")
    end_dt = _parse_bound(end, "end")
    if end_dt is not None and len(str(end)) <= 10:
        end_dt = end_of_day(end_dt)

    query = db.query(TimelineEvent, Actor.primary_handle).outerjoin(
        Actor, TimelineEvent.actor_id == Actor.id
    )
    if not synthetic_visible(include_synthetic):
        hidden = hidden_actor_ids(db)
        if hidden:
            query = query.filter(
                (TimelineEvent.actor_id.is_(None)) | (~TimelineEvent.actor_id.in_(hidden))
            )
    if actor_id:
        query = query.filter(TimelineEvent.actor_id == actor_id)
    if event_type:
        query = query.filter(TimelineEvent.event_type == event_type)
    if start_dt:
        query = query.filter(TimelineEvent.event_date >= start_dt)
    if end_dt:
        query = query.filter(TimelineEvent.event_date <= end_dt)

    if order == "desc":
        query = query.order_by(TimelineEvent.event_date.desc(), TimelineEvent.id.desc())
    else:
        query = query.order_by(TimelineEvent.event_date.asc(), TimelineEvent.id.asc())

    rows = query.limit(limit).all()
    return [
        {
            "id": event.id,
            "actor_id": event.actor_id,
            "actor_handle": handle,
            "event_type": event.event_type,
            "description": event.description,
            "event_date": event.event_date,
            "source": event.source,
        }
        for event, handle in rows
    ]


@router.get("/summary")
def timeline_summary(
    actor_id: Optional[int] = None,
    include_synthetic: bool = Query(False),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    query = db.query(TimelineEvent)
    hidden = set() if synthetic_visible(include_synthetic) else hidden_actor_ids(db)
    if hidden:
        query = query.filter(
            TimelineEvent.actor_id.is_(None) | (~TimelineEvent.actor_id.in_(hidden))
        )
    if actor_id:
        query = query.filter(TimelineEvent.actor_id == actor_id)
    events = query.all()

    by_day: dict = {}
    by_type: dict = {}
    for event in events:
        day = event.event_date.date().isoformat() if event.event_date else "unknown"
        by_day[day] = by_day.get(day, 0) + 1
        by_type[event.event_type or "unknown"] = by_type.get(event.event_type or "unknown", 0) + 1

    actor_query = (
        db.query(TimelineEvent.actor_id, Actor.primary_handle, func.count(TimelineEvent.id))
        .outerjoin(Actor, TimelineEvent.actor_id == Actor.id)
        .group_by(TimelineEvent.actor_id, Actor.primary_handle)
    )
    if hidden:
        actor_query = actor_query.filter(
            TimelineEvent.actor_id.is_(None) | (~TimelineEvent.actor_id.in_(hidden))
        )

    return {
        "total": len(events),
        "by_day": [{"date": day, "count": count} for day, count in sorted(by_day.items())],
        "by_type": [{"type": key, "count": value} for key, value in sorted(by_type.items())],
        "actors": [
            {"actor_id": row[0], "handle": row[1], "count": row[2]}
            for row in actor_query.all()
        ],
    }


@router.post("", status_code=201)
def create_event(body: TimelineEventIn, actor_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    actor = db.query(Actor).filter(Actor.id == actor_id).first()
    if not actor:
        raise HTTPException(404, "Actor not found")
    event = TimelineEvent(
        actor_id=actor.id,
        event_type=body.event_type,
        description=body.description,
        event_date=body.event_date,
        source=body.source,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {
        "id": event.id,
        "actor_id": event.actor_id,
        "event_type": event.event_type,
        "description": event.description,
        "event_date": event.event_date,
        "source": event.source,
    }
