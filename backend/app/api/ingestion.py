"""Intelligence ingestion API.

Supports single records, CSV, JSON, STIX 2.1 bundles and the documented public
external feeds (MITRE ATT&CK, APTnotes, URLhaus, ThreatFox). Every import
creates a ``CollectionJob`` and returns an explicit summary of processed,
imported, duplicate and rejected records, so partial failures are visible.
"""

import csv
import io
import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, require_admin
from app.core.time import utcnow
from app.database.session import get_db
from app.ingestion.feeds import (
    FEED_REGISTRY,
    FeedAuthRequired,
    FeedUnavailableError,
    get_feed_status,
    ingest_feed,
)
from app.ingestion.jobs import create_job, fail_job as mark_job_failed, finish_job, serialize_job
from app.ingestion.record_processor import (
    ProcessResult,
    RecordRejected,
    process_record,
    summarize,
)
from app.ingestion.stix_import import StixImportError, ingest_stix_bundle
from app.models.entities import CollectionJob
from app.schemas.schemas import FeedRequest, IngestRecord
from app.services.audit import audit

router = APIRouter(prefix="/ingestion", tags=["ingestion"])

CSV_FIELDS = {
    "handle",
    "marketplace",
    "pgp",
    "wallet",
    "domain",
    "infra",
    "email",
    "ip",
    "username",
    "text_sample",
    "threat_category",
    "source",
    "source_reliability",
    "is_synthetic",
    "activity_dates",
    "evidence_reference",
}


def _blank(value) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _read_upload(content: bytes, filename: str) -> None:
    limit = get_settings().max_upload_bytes
    if not content:
        raise HTTPException(status_code=400, detail=f"Empty file: {filename}")
    if len(content) > limit:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {limit} byte upload limit",
        )


def _new_job(db: Session, name: str, source_key: Optional[str] = None, source_url: Optional[str] = None) -> CollectionJob:
    return create_job(db, name, source_key=source_key, source_url=source_url)


def _finish_job(db: Session, job: CollectionJob, imported: int, rejected: int) -> None:
    finish_job(
        db,
        job,
        status="completed",
        stats={"records_imported": imported, "records_fetched": imported, "records_rejected": rejected},
    )


@router.post("/record")
def ingest_record(rec: IngestRecord, db: Session = Depends(get_db), user=Depends(get_current_user)):
    job = _new_job(db, rec.source or "single_record")
    try:
        with db.begin_nested():
            result = process_record(db, rec)
    except RecordRejected as exc:
        db.rollback()
        job = db.query(CollectionJob).filter(CollectionJob.id == job.id).first()
        job.status = "failed"
        job.finished_at = utcnow()
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        job = db.query(CollectionJob).filter(CollectionJob.id == job.id).first()
        job.status = "failed"
        job.finished_at = utcnow()
        db.commit()
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {exc}") from exc

    db.commit()
    imported = 0 if result.duplicate else 1
    _finish_job(db, job, imported, 0)
    audit(db, user.username, "ingest_record", f"actor {result.actor_id}")
    return {
        "job_id": job.id,
        "processed": 1,
        "imported": imported,
        "duplicates": 1 if result.duplicate else 0,
        "rejected": 0,
        "skipped": 0,
        "identifiers_added": result.identifiers_added,
        "handles_added": result.handles_added,
        "evidence_added": result.evidence_added,
        "events_added": result.events_added,
        "errors": result.warnings,
        "actor_id": result.actor_id,
    }


@router.post("/csv")
async def ingest_csv(file: UploadFile = File(...), db: Session = Depends(get_db), user=Depends(get_current_user)):
    content = await file.read()
    _read_upload(content, file.filename or "upload.csv")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded") from exc

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV has no header row")
    if "handle" not in {field.strip() for field in reader.fieldnames}:
        raise HTTPException(status_code=400, detail="CSV must include a 'handle' column")

    job = _new_job(db, file.filename or "csv_import")
    results: List[ProcessResult] = []
    errors: List[str] = []
    rejected = 0
    processed = 0

    for index, row in enumerate(reader, start=2):
        processed += 1
        row = {(k or "").strip(): v for k, v in row.items()}
        if not _blank(row.get("handle")):
            rejected += 1
            errors.append(f"row {index}: missing handle")
            continue
        try:
            snapshot = dict(row)
            rec = IngestRecord(
                handle=_blank(snapshot.get("handle")),
                marketplace=_blank(snapshot.get("marketplace")),
                pgp=_blank(snapshot.get("pgp")),
                wallet=_blank(snapshot.get("wallet")),
                domain=_blank(snapshot.get("domain")),
                infra=_blank(snapshot.get("infra")),
                email=_blank(snapshot.get("email")),
                ip=_blank(snapshot.get("ip")),
                username=_blank(snapshot.get("username")),
                text_sample=_blank(snapshot.get("text_sample")),
                threat_category=_blank(snapshot.get("threat_category")),
                source=_blank(snapshot.get("source")) or "csv_import",
                source_reliability=_float(snapshot.get("source_reliability"), 0.5),
                is_synthetic=str(snapshot.get("is_synthetic") or "false").strip().lower()
                in ("true", "1", "yes", "y"),
                activity_dates=[
                    part.strip()
                    for part in (snapshot.get("activity_dates") or "").split(";")
                    if part.strip()
                ],
                evidence_reference=_blank(snapshot.get("evidence_reference")),
            )
            with db.begin_nested():
                result = process_record(db, rec)
            results.append(result)
        except (RecordRejected, ValidationError, ValueError) as exc:
            rejected += 1
            errors.append(f"row {index}: {exc}")
        except Exception as exc:  # unexpected per-row failure
            rejected += 1
            errors.append(f"row {index}: unexpected error: {exc}")

    db.commit()
    summary = summarize(processed, results, rejected, errors)
    _finish_job(db, job, summary["imported"], rejected)
    audit(db, user.username, "ingest_csv", f"{file.filename}: {summary['imported']} imported")
    return {**summary, "job_id": job.id, "source": file.filename}


@router.post("/json")
async def ingest_json(file: UploadFile = File(...), db: Session = Depends(get_db), user=Depends(get_current_user)):
    content = await file.read()
    _read_upload(content, file.filename or "upload.json")
    try:
        data = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    if isinstance(data, dict):
        records = data.get("records", data.get("items"))
        if records is None and "handle" in data:
            records = [data]
    else:
        records = data
    if not isinstance(records, list):
        raise HTTPException(
            status_code=400,
            detail="JSON must be a list of records, or an object containing a 'records' list",
        )

    job = _new_job(db, file.filename or "json_import")
    results: List[ProcessResult] = []
    errors: List[str] = []
    rejected = 0

    for index, raw in enumerate(records, start=1):
        if not isinstance(raw, dict):
            rejected += 1
            errors.append(f"record {index}: expected an object")
            continue
        if not _blank(raw.get("handle")):
            rejected += 1
            errors.append(f"record {index}: missing handle")
            continue
        try:
            rec = IngestRecord(**raw)
            with db.begin_nested():
                result = process_record(db, rec)
            results.append(result)
        except (RecordRejected, ValidationError, ValueError) as exc:
            rejected += 1
            errors.append(f"record {index}: {exc}")
        except Exception as exc:
            rejected += 1
            errors.append(f"record {index}: unexpected error: {exc}")

    db.commit()
    summary = summarize(len(records), results, rejected, errors)
    _finish_job(db, job, summary["imported"], rejected)
    audit(db, user.username, "ingest_json", f"{file.filename}: {summary['imported']} imported")
    return {**summary, "job_id": job.id, "source": file.filename}


@router.post("/stix")
async def ingest_stix(
    file: UploadFile = File(...),
    source_name: str = "stix_upload",
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    content = await file.read()
    _read_upload(content, file.filename or "bundle.json")
    try:
        bundle = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    job = _new_job(db, f"{source_name}:{file.filename or 'bundle.json'}")
    try:
        result = ingest_stix_bundle(db, bundle, source_name=source_name)
        db.commit()
    except StixImportError as exc:
        db.rollback()
        job = db.query(CollectionJob).filter(CollectionJob.id == job.id).first()
        job.status = "failed"
        job.finished_at = utcnow()
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    _finish_job(db, job, result.get("records_imported", 0), len(result.get("errors", [])))
    audit(db, user.username, "ingest_stix", f"{file.filename}: {result.get('records_imported', 0)}")
    return {**result, "job_id": job.id}


@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return get_feed_status(db)


@router.post("/feeds/{source}")
def ingest_external_feed(
    source: str,
    body: Optional[FeedRequest] = Body(default=None),
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    key = source.strip().lower()
    if key not in FEED_REGISTRY:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown feed '{source}'. Available: {', '.join(sorted(FEED_REGISTRY))}",
        )
    request = body or FeedRequest()
    job = _new_job(db, f"feed:{key}", source_key=key, source_url=request.url)
    try:
        result = ingest_feed(
            db, key, url=request.url, limit=request.limit, job_id=job.id
        )
        db.commit()
    except FeedAuthRequired as exc:
        db.rollback()
        mark_job_failed(db, job, str(exc))
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FeedUnavailableError as exc:
        db.rollback()
        mark_job_failed(db, job, str(exc))
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        mark_job_failed(db, job, f"Feed ingestion failed: {exc}")
        raise HTTPException(status_code=500, detail=f"Feed ingestion failed: {exc}") from exc

    finish_job(
        db,
        job,
        status="completed",
        stats={
            "records_fetched": result.get("fetched", 0),
            "records_validated": result.get("processed", 0),
            "records_imported": result.get("imported", 0),
            "records_skipped": result.get("duplicates", 0),
            "records_rejected": result.get("rejected", 0),
            "relationships_created": result.get("relationships_created", 0),
        },
        errors=result.get("errors", []),
        details={"source_url": result.get("source_url")},
    )
    audit(db, user.username, "ingest_feed", f"{key}: {result.get('imported', 0)} records")
    return {**result, "job_id": job.id, "job": serialize_job(job)}


@router.post("/mitre-attack")
def ingest_mitre_attack(
    stix_url: Optional[str] = None,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Fetch and import the official MITRE ATT&CK Enterprise STIX bundle."""
    from app.ingestion.mitre_attack import MitreAttackAdapter

    adapter = MitreAttackAdapter(db=db, stix_url=stix_url) if stix_url else MitreAttackAdapter(db=db)
    try:
        result = adapter.run()
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"MITRE ATT&CK ingestion failed: {exc}") from exc

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=502,
            detail=(
                "MITRE ATT&CK ingestion failed. "
                f"First error: {(result.get('errors') or ['unknown'])[0]}"
            ),
        )
    audit(db, user.username, "ingest_mitre", f"{result.get('records_imported', 0)} records")
    return result


@router.get("/jobs")
def list_jobs(limit: int = 50, db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(CollectionJob)
        .order_by(CollectionJob.started_at.desc(), CollectionJob.id.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [serialize_job(job) for job in rows]


@router.get("/jobs/{job_id}")
def get_job(job_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    job = db.query(CollectionJob).filter(CollectionJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Collection job not found")
    return serialize_job(job)


def _float(value, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))
