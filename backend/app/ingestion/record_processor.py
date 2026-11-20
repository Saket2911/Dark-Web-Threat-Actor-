"""Shared record ingestion pipeline for CSV, JSON and single-record imports.

Idempotency rules:

* an actor is reused when handle + origin already match;
* a handle is not stored twice for the same actor/marketplace;
* identifiers are canonicalised; an identical (actor, type, value) is skipped;
* evidence is deduplicated on (actor, source, evidence type, content);
* timeline events are deduplicated on (actor, timestamp, description).

Invalid identifier values raise ``RecordRejected`` so the caller can report a
rejected row instead of silently dropping data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.time import parse_datetime, utcnow
from app.models.entities import (
    Actor,
    Evidence,
    Handle,
    Identifier,
    IntelligenceSource,
    TimelineEvent,
)
from app.schemas.schemas import IngestRecord
from app.services.evidence_validator import create_evidence
from app.services.identifiers import normalize_identifier
from app.services.relationship_validator import (
    validate_origin,
    validate_source_consistency,
)

IDENTIFIER_FIELDS = (
    ("pgp", "pgp"),
    ("wallet", "wallet"),
    ("domain", "domain"),
    ("infra", "infra"),
    ("email", "email"),
    ("ip", "ip"),
    ("username", "username"),
)


class RecordRejected(ValueError):
    """Raised when a record cannot be imported and must be reported."""


@dataclass
class ProcessResult:
    actor_id: int
    created_actor: bool = False
    identifiers_added: int = 0
    handles_added: int = 0
    evidence_added: int = 0
    events_added: int = 0
    warnings: List[str] = field(default_factory=list)

    @property
    def duplicate(self) -> bool:
        return not (
            self.created_actor
            or self.identifiers_added
            or self.handles_added
            or self.evidence_added
            or self.events_added
        )

    def as_dict(self) -> Dict:
        return {
            "actor_id": self.actor_id,
            "created_actor": self.created_actor,
            "identifiers_added": self.identifiers_added,
            "handles_added": self.handles_added,
            "evidence_added": self.evidence_added,
            "events_added": self.events_added,
            "duplicate": self.duplicate,
            "warnings": self.warnings,
        }


def resolve_source(db: Session, rec: IngestRecord) -> IntelligenceSource:
    """Find or create the intelligence source, enforcing origin consistency."""
    name = (rec.source or "").strip()
    if not name:
        raise RecordRejected("record is missing a source name")

    origin = validate_origin("synthetic" if rec.is_synthetic else "external")
    validate_source_consistency(rec.is_synthetic, origin)

    source = (
        db.query(IntelligenceSource)
        .filter(IntelligenceSource.name == name)
        .order_by(IntelligenceSource.id)
        .first()
    )
    if source:
        if bool(source.is_synthetic) != bool(rec.is_synthetic):
            # Existing source keeps its recorded provenance; never silently
            # relabel real intelligence as synthetic or vice versa.
            raise RecordRejected(
                f"source '{name}' already exists with is_synthetic={source.is_synthetic}; "
                f"the record declares is_synthetic={rec.is_synthetic}"
            )
        return source

    source = IntelligenceSource(
        name=name,
        source_type="import",
        reliability=rec.source_reliability,
        is_synthetic=rec.is_synthetic,
        origin=origin,
    )
    db.add(source)
    db.flush()
    return source


def process_record(db: Session, rec: IngestRecord) -> ProcessResult:
    """Import a single record inside the caller's transaction."""
    settings = get_settings()
    if rec.is_synthetic and settings.environment == "production":
        raise RecordRejected(
            "Synthetic records cannot be ingested while ENVIRONMENT=production. "
            "Mark the record as real intelligence with traceable provenance, or run "
            "the application in a development environment."
        )
    source = resolve_source(db, rec)
    origin = source.origin or "external"

    handle = (rec.handle or "").strip()
    if not handle:
        raise RecordRejected("record is missing a handle")

    actor = (
        db.query(Actor)
        .filter(Actor.primary_handle == handle, Actor.origin == origin)
        .order_by(Actor.id)
        .first()
    )
    result = ProcessResult(actor_id=actor.id if actor else 0)
    if actor is None:
        actor = Actor(
            internal_id=_new_internal_id(db),
            primary_handle=handle,
            threat_category=(rec.threat_category or "").strip() or None,
            last_observed=utcnow(),
            origin=origin,
        )
        db.add(actor)
        db.flush()
        result.actor_id = actor.id
        result.created_actor = True
    elif rec.threat_category and not actor.threat_category:
        actor.threat_category = rec.threat_category

    if handle:
        exists = (
            db.query(Handle)
            .filter(
                Handle.actor_id == actor.id,
                Handle.handle == handle,
                Handle.marketplace == rec.marketplace,
            )
            .first()
        )
        if not exists:
            db.add(
                Handle(
                    actor_id=actor.id,
                    handle=handle,
                    marketplace=rec.marketplace,
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                )
            )
            result.handles_added += 1

    for field_name, id_type in IDENTIFIER_FIELDS:
        raw_value = getattr(rec, field_name, None)
        if not raw_value:
            continue
        try:
            kind, normalized = normalize_identifier(id_type, raw_value)
        except ValueError as exc:
            raise RecordRejected(str(exc)) from exc
        exists = (
            db.query(Identifier)
            .filter(
                Identifier.actor_id == actor.id,
                Identifier.id_type == kind,
                Identifier.value == normalized,
            )
            .first()
        )
        if exists:
            continue
        db.add(
            Identifier(
                actor_id=actor.id,
                id_type=kind,
                value=normalized,
                source=source.name,
                reliability=rec.source_reliability,
                origin=origin,
            )
        )
        result.identifiers_added += 1

    if rec.text_sample:
        duplicate = (
            db.query(Evidence)
            .filter(
                Evidence.source_id == source.id,
                Evidence.evidence_type == "text_sample",
                Evidence.content == rec.text_sample,
                (Evidence.actor_id == actor.id)
                | ((Evidence.entity_type == "actor") & (Evidence.entity_id == actor.id)),
            )
            .first()
        )
        if duplicate is None:
            create_evidence(
                db=db,
                source_id=source.id,
                entity_type="actor",
                entity_id=actor.id,
                evidence_type="text_sample",
                content=rec.text_sample,
                reference=rec.evidence_reference or source.name,
                source_url=source.url,
                source_description=f"Imported from {source.name}",
                reliability=rec.source_reliability,
                raw_payload={
                    "source": source.name,
                    "handle": handle,
                    "is_synthetic": bool(source.is_synthetic),
                },
                actor_id=actor.id,
                commit=False,
            )
            result.evidence_added += 1

    for raw_date in rec.activity_dates or []:
        event_date = parse_datetime(raw_date)
        if event_date is None:
            result.warnings.append(f"unparsed activity date: {raw_date}")
            continue
        duplicate = (
            db.query(TimelineEvent)
            .filter(
                TimelineEvent.actor_id == actor.id,
                TimelineEvent.event_date == event_date,
                TimelineEvent.event_type == "activity",
            )
            .first()
        )
        if duplicate:
            continue
        db.add(
            TimelineEvent(
                actor_id=actor.id,
                event_type="activity",
                description=f"Activity observed on {event_date.date().isoformat()}",
                event_date=event_date,
                source=source.name,
            )
        )
        result.events_added += 1

    return result


def _new_internal_id(db: Session) -> str:
    import uuid

    while True:
        candidate = f"TA{uuid.uuid4().hex[:8].upper()}"
        if not db.query(Actor.id).filter(Actor.internal_id == candidate).first():
            return candidate


def summarize(processed: int, results: List[ProcessResult], rejected: int, errors: List[str]) -> Dict:
    imported = sum(
        1 for r in results if not r.duplicate
    )
    duplicates = sum(1 for r in results if r.duplicate)
    return {
        "processed": processed,
        "imported": imported,
        "duplicates": duplicates,
        "rejected": rejected,
        "skipped": processed - len(results) - rejected,
        "identifiers_added": sum(r.identifiers_added for r in results),
        "handles_added": sum(r.handles_added for r in results),
        "evidence_added": sum(r.evidence_added for r in results),
        "events_added": sum(r.events_added for r in results),
        "errors": errors[:100],
    }
