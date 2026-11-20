"""Collection job bookkeeping shared by every intelligence connector.

A job is created before a connector touches the network and updated with the
real counts afterwards. Statistics always distinguish what the source returned
from what was actually written, so a job can never look successful when zero
records were stored.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.time import utcnow
from app.models.entities import CollectionJob, IntelligenceSource

MAX_STORED_ERRORS = 50


def create_job(
    db: Session,
    source_name: str,
    *,
    source_key: Optional[str] = None,
    source_url: Optional[str] = None,
) -> CollectionJob:
    job = CollectionJob(
        source_name=(source_name or "unknown")[:255],
        source_key=(source_key or "")[:100] or None,
        source_url=(source_url or "")[:500] or None,
        status="running",
        records_fetched=0,
        records_validated=0,
        records_imported=0,
        records_updated=0,
        records_skipped=0,
        records_rejected=0,
        relationships_created=0,
        error_count=0,
        started_at=utcnow(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def finish_job(
    db: Session,
    job: CollectionJob,
    *,
    status: str,
    stats: Optional[Dict[str, Any]] = None,
    errors: Optional[List[str]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> CollectionJob:
    """Persist the final state of a job. Never marks an empty import as success."""

    stats = stats or {}
    errors = [str(error) for error in (errors or [])]
    stored_errors = errors[:MAX_STORED_ERRORS]

    imported = int(stats.get("records_imported", stats.get("imported", 0)) or 0)
    updated = int(stats.get("records_updated", 0) or 0)
    relationships_created = int(stats.get("relationships_created", 0) or 0)
    fetched = int(stats.get("records_fetched", stats.get("fetched", 0)) or 0)
    skipped = int(stats.get("records_skipped", stats.get("duplicates", 0)) or 0)
    rejected = int(stats.get("records_rejected", stats.get("rejected", 0)) or 0)

    written = imported + updated + relationships_created
    if status == "completed":
        if fetched > 0 and written == 0 and rejected == 0 and skipped > 0:
            # Everything the source returned was already stored: a successful
            # no-op, not an empty import.
            status = "completed_no_changes"
        elif fetched > 0 and written == 0:
            # The source answered but nothing usable was stored.
            status = "completed_empty"
    if errors and status in ("completed", "completed_no_changes"):
        status = "completed_with_errors"

    job.status = status
    job.records_fetched = int(stats.get("records_fetched", stats.get("fetched", 0)) or 0)
    job.records_validated = int(stats.get("records_validated", 0) or 0)
    job.records_imported = imported
    job.records_updated = updated
    job.records_skipped = skipped
    job.records_rejected = rejected
    job.relationships_created = relationships_created
    job.error_count = len(errors)
    job.errors = json.dumps(errors) if errors else None
    job.details = details
    job.finished_at = utcnow()
    db.commit()
    db.refresh(job)
    return job


def fail_job(db: Session, job: CollectionJob, error: str, **details: Any) -> CollectionJob:
    return finish_job(
        db,
        job,
        status="failed",
        stats={},
        errors=[error],
        details=details or None,
    )


def record_source_success(db: Session, source: IntelligenceSource, object_count: int, etag: Optional[str] = None) -> None:
    source.last_success_at = utcnow()
    source.last_error = None
    source.last_error_at = None
    source.last_object_count = object_count
    if etag is not None:
        source.last_etag = etag
    db.commit()


def record_source_failure(db: Session, source: IntelligenceSource, error: str) -> None:
    source.last_error = str(error)[:2000]
    source.last_error_at = utcnow()
    db.commit()


def serialize_job(job: CollectionJob) -> Dict[str, Any]:
    errors: List[str] = []
    if job.errors:
        try:
            parsed = json.loads(job.errors)
            errors = parsed if isinstance(parsed, list) else [str(parsed)]
        except (TypeError, ValueError):
            errors = [job.errors]
    return {
        "id": job.id,
        "source": job.source_name,
        "source_key": job.source_key,
        "source_url": job.source_url,
        "status": job.status,
        "fetched": job.records_fetched or 0,
        "validated": job.records_validated or 0,
        "records": job.records_imported or 0,
        "imported": job.records_imported or 0,
        "updated": job.records_updated or 0,
        "skipped": job.records_skipped or 0,
        "rejected": job.records_rejected or 0,
        "relationships_created": job.relationships_created or 0,
        "error_count": job.error_count or 0,
        "errors": errors,
        "details": job.details or {},
        "started": job.started_at,
        "finished": job.finished_at,
    }
