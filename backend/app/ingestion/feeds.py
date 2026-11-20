"""Genuine external intelligence feed connectors.

Implemented against documented public interfaces only:

* **APTnotes** - public JSON index of APT research reports (GitHub, no key).
* **URLhaus** - abuse.ch malicious-URL API. abuse.ch now requires a free
  Auth-Key for API access; without one the connector reports
  ``blocked_missing_credentials`` instead of pretending the feed works.
* **ThreatFox** - abuse.ch IOC API, same free Auth-Key requirement.
* **MITRE ATT&CK** - official STIX 2.1 bundle (see ``mitre_attack.py``).

Nothing here invents records. Only fields present in the source payload are
stored; missing fields stay empty. Every record is deduplicated on the source's
own identifier and keeps its provenance (source, external id, URL, timestamps,
raw payload) in ``evidence``.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.time import parse_datetime, utcnow
from app.ingestion.jobs import (
    create_job,
    fail_job,
    finish_job,
    record_source_failure,
    record_source_success,
)
from app.models.entities import (
    Actor,
    CollectionJob,
    Evidence,
    InfrastructureIndicator,
    IntelligenceSource,
    Malware,
    Relationship,
)
from app.services.evidence_validator import create_evidence
from app.services.relationship_validator import create_relationship

logger = logging.getLogger(__name__)

ABUSE_CH_KEY_HELP = (
    "abuse.ch requires a free Auth-Key for URLhaus and ThreatFox API access. "
    "Create one at https://auth.abuse.ch/ and set ABUSE_CH_AUTH_KEY in the "
    "environment (.env). Until then this feed is intentionally disabled and no "
    "records are fabricated."
)


class FeedError(RuntimeError):
    """Base class for feed failures."""


class FeedUnavailableError(FeedError):
    """The feed could not be reached or returned an unusable response."""


class FeedAuthRequired(FeedError):
    """The feed requires credentials that are not configured or were rejected."""


FEED_REGISTRY: Dict[str, Dict[str, Any]] = {
    "aptnotes": {
        "name": "APTnotes",
        "description": "Public index of APT campaign reports (GitHub, no key required).",
        "requires_key": False,
        "docs": "https://github.com/aptnotes/data",
        "produces": "report metadata as evidence, linked to a tracked group only when the title names it",
    },
    "urlhaus": {
        "name": "URLhaus",
        "description": "Recent malicious URLs from abuse.ch (free Auth-Key required).",
        "requires_key": True,
        "docs": "https://urlhaus-api.abuse.ch/",
        "produces": "URL infrastructure indicators with evidence and malware links",
    },
    "threatfox": {
        "name": "ThreatFox",
        "description": "IOC sharing API from abuse.ch (free Auth-Key required).",
        "requires_key": True,
        "docs": "https://threatfox-api.abuse.ch/api/",
        "produces": "IP/domain/URL/hash indicators linked to malware families",
    },
}


def _auth_key() -> str:
    settings = get_settings()
    return (settings.abuse_ch_auth_key or "").strip()


def _http_json(
    url: str,
    *,
    method: str = "GET",
    json_body: Optional[dict] = None,
    headers: Optional[dict] = None,
    conditional_headers: Optional[dict] = None,
) -> Tuple[Any, Optional[str]]:
    """Fetch JSON with bounded retries. Returns (payload, etag)."""

    settings = get_settings()
    last_error: Optional[Exception] = None
    attempts = max(1, settings.feed_max_retries + 1)
    request_headers = dict(headers or {})
    request_headers.setdefault("User-Agent", "CN-Project-CTI/1.0 (public feed client)")
    request_headers.update(conditional_headers or {})

    for attempt in range(attempts):
        try:
            response = requests.request(
                method,
                url,
                json=json_body,
                headers=request_headers,
                timeout=settings.feed_timeout_seconds,
                allow_redirects=True,
            )
            if response.status_code == 304:
                return {"query_status": "not_modified"}, request_headers.get("If-None-Match")
            if response.status_code in (401, 403):
                raise FeedAuthRequired(
                    f"{url} rejected the request ({response.status_code}). {ABUSE_CH_KEY_HELP}"
                )
            if response.status_code == 429:
                retry_after = float(response.headers.get("Retry-After", "2") or 2)
                time.sleep(min(retry_after, 30))
                last_error = FeedUnavailableError("rate limited by feed")
                continue
            if response.status_code == 410:
                raise FeedUnavailableError(
                    f"{url} is gone (HTTP 410). The provider retired this endpoint; "
                    "check its documentation for the current interface."
                )
            response.raise_for_status()
            payload = response.json()
            return payload, response.headers.get("ETag")
        except FeedAuthRequired:
            raise
        except requests.exceptions.RequestException as exc:
            last_error = exc
            if attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))
        except ValueError as exc:
            raise FeedUnavailableError(f"Feed returned non-JSON content: {exc}") from exc
    raise FeedUnavailableError(f"Feed request failed after {attempts} attempt(s): {last_error}")


def _get_source(db: Session, name: str, url: str, reliability: float) -> IntelligenceSource:
    source = (
        db.query(IntelligenceSource)
        .filter(IntelligenceSource.name == name, IntelligenceSource.is_synthetic.is_(False))
        .order_by(IntelligenceSource.id)
        .first()
    )
    if source:
        return source
    source = IntelligenceSource(
        name=name,
        source_type="public_feed",
        reliability=reliability,
        url=url,
        is_synthetic=False,
        origin="external",
        collected_at=utcnow(),
    )
    db.add(source)
    db.flush()
    return source


def _evidence_exists(db: Session, source_id: int, external_id: str) -> Optional[Evidence]:
    return (
        db.query(Evidence)
        .filter(Evidence.source_id == source_id, Evidence.external_record_id == external_id)
        .first()
    )


def _word_match(term: str, text: str) -> bool:
    if len(term) < 3:
        return False
    return re.search(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", text, re.IGNORECASE) is not None


def _external_actors(db: Session) -> List[Actor]:
    """Only real, externally sourced groups may receive external evidence."""

    return db.query(Actor).filter(Actor.origin == "external").order_by(Actor.id).all()


# ---------------------------------------------------------------------------
# APTnotes
# ---------------------------------------------------------------------------
def _first(record: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return None


def parse_aptnotes_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise one APTnotes index entry using the feed's real field names.

    The published JSON uses ``Filename``/``Title``/``Source``/``Link``/``Date``
    (older exports may use lowercase). Anything absent stays ``None``.
    """

    filename = _first(record, "Filename", "filename")
    title = _first(record, "Title", "title")
    publisher = _first(record, "Source", "source")
    link = _first(record, "Link", "link", "url", "URL")
    sha1 = _first(record, "SHA-1", "SHA1", "sha1")
    date_raw = _first(record, "Date", "date")
    year = _first(record, "Year", "year")

    external_id = filename or sha1 or link
    if not external_id:
        raise FeedUnavailableError("APTnotes entry has no Filename/Link identifier")

    published = parse_datetime(date_raw)
    if published is None and year and year.isdigit():
        published = parse_datetime(f"{year}-01-01")

    return {
        "external_id": external_id,
        "title": title,
        "publisher": publisher,
        "link": link,
        "sha1": sha1,
        "published": published,
        "year": year,
    }


def ingest_aptnotes(
    db: Session,
    url: Optional[str] = None,
    limit: int = 2000,
    job_id: Optional[int] = None,
) -> Dict[str, Any]:
    settings = get_settings()
    feed_url = url or settings.aptnotes_url
    data, _etag = _http_json(feed_url)
    records = data if isinstance(data, list) else data.get("reports") or data.get("records") or []
    if not isinstance(records, list):
        raise FeedUnavailableError("APTnotes feed did not return a list of reports")

    source = _get_source(db, "APTnotes", feed_url, 0.7)
    actors = _external_actors(db)

    fetched = len(records)
    processed = imported = duplicates = skipped = rejected = 0
    linked = 0
    errors: List[str] = []

    for record in records[:limit]:
        processed += 1
        if not isinstance(record, dict):
            rejected += 1
            errors.append("record is not an object")
            continue
        try:
            parsed = parse_aptnotes_record(record)
        except FeedUnavailableError as exc:
            rejected += 1
            errors.append(str(exc))
            continue

        if _evidence_exists(db, source.id, parsed["external_id"]):
            duplicates += 1
            continue
        if not parsed["title"] and not parsed["link"]:
            rejected += 1
            errors.append(f"{parsed['external_id']}: no title or link published")
            continue

        matched: Optional[Actor] = None
        title_text = f"{parsed['title'] or ''} {parsed['external_id'] or ''}"
        for actor in actors:
            names = [actor.primary_handle or ""]
            names.extend(str(alias) for alias in (actor.aliases or []) if alias)
            if any(_word_match(name.strip(), title_text) for name in names if name and len(name.strip()) >= 3):
                matched = actor
                break

        content_parts = [part for part in (parsed["title"], parsed["publisher"]) if part]
        try:
            create_evidence(
                db=db,
                source_id=source.id,
                entity_type="actor" if matched else None,
                entity_id=matched.id if matched else None,
                evidence_type="report",
                content=" — ".join(content_parts) or parsed["external_id"],
                reference=parsed["link"] or parsed["external_id"],
                external_record_id=parsed["external_id"],
                source_url=parsed["link"],
                source_published_at=parsed["published"],
                source_description=(
                    "APTnotes public report index entry"
                    + (f"; title names tracked group {matched.primary_handle}" if matched else "")
                ),
                reliability=source.reliability,
                raw_payload=record,
                import_job_id=job_id,
                commit=False,
            )
            imported += 1
            if matched:
                linked += 1
        except Exception as exc:  # validation/persistence failure for one record
            rejected += 1
            errors.append(f"{parsed['external_id']}: {exc}")

    db.flush()
    if imported == 0 and rejected and not duplicates:
        record_source_failure(db, source, f"no APTnotes records imported ({rejected} rejected)")
    else:
        record_source_success(db, source, imported)
    return {
        "feed": "aptnotes",
        "source": source.name,
        "source_url": feed_url,
        "fetched": fetched,
        "processed": processed,
        "imported": imported,
        "duplicates": duplicates,
        "skipped": skipped,
        "rejected": rejected,
        "linked_to_actor": linked,
        "relationships_created": 0,
        "job_id": job_id,
        "errors": errors[:50],
        "note": (
            "Report metadata is stored exactly as published. A report is linked to a group only "
            "when its title contains that group's name or alias as a whole word."
        ),
    }


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------
URLHAUS_TYPE_BY_IOC = {
    "url": "url",
    "domain": "domain",
    "ip": "ip",
    "md5": "hash",
    "sha256": "hash",
}


def ingest_urlhaus(
    db: Session,
    url: Optional[str] = None,
    limit: int = 200,
    job_id: Optional[int] = None,
) -> Dict[str, Any]:
    settings = get_settings()
    feed_url = url or settings.urlhaus_recent_url
    key = _auth_key()
    headers = {"Auth-Key": key} if key else {}
    data, _etag = _http_json(feed_url, method="POST", headers=headers)
    if not isinstance(data, dict):
        raise FeedUnavailableError("URLhaus returned an unexpected payload")
    status = data.get("query_status")
    if status == "no_results":
        records: List[Any] = []
    elif status and status != "ok":
        raise FeedUnavailableError(f"URLhaus query_status={status}")
    else:
        records = data.get("urls") or []

    source = _get_source(db, "URLhaus", feed_url, 0.6)
    processed = imported = duplicates = skipped = rejected = 0
    linked_malware = 0
    errors: List[str] = []

    for record in records[:limit]:
        processed += 1
        if not isinstance(record, dict):
            rejected += 1
            continue
        value = str(record.get("url") or "").strip()
        if not value:
            rejected += 1
            errors.append("URL entry without a url value")
            continue
        external_id = str(record.get("id") or value)

        existing = (
            db.query(InfrastructureIndicator)
            .filter(
                InfrastructureIndicator.value == value,
                InfrastructureIndicator.source == source.name,
            )
            .first()
        )
        if existing:
            duplicates += 1
            continue

        indicator = InfrastructureIndicator(
            indicator_type="url",
            value=value,
            metadata_json={
                "url_status": record.get("url_status"),
                "threat": record.get("threat"),
                "tags": record.get("tags"),
                "reporter": record.get("reporter"),
                "host": record.get("host"),
                "date_added": record.get("date_added"),
                "reference": record.get("urlhaus_link"),
                "external_id": external_id,
            },
            source=source.name,
            external_id=external_id,
            origin="external",
            reliability=source.reliability,
            last_observed=parse_datetime(record.get("date_added")) or utcnow(),
        )
        db.add(indicator)
        db.flush()

        if not _evidence_exists(db, source.id, external_id):
            create_evidence(
                db=db,
                source_id=source.id,
                entity_type="indicator",
                entity_id=indicator.id,
                evidence_type="indicator",
                content=f"URLhaus reports {value} as {record.get('threat') or 'malicious'}",
                reference=str(record.get("urlhaus_link") or value),
                external_record_id=external_id,
                source_url=feed_url,
                source_published_at=parse_datetime(record.get("date_added")),
                source_description="URLhaus recent URL entry",
                reliability=source.reliability,
                raw_payload=record,
                import_job_id=job_id,
                commit=False,
            )

        threat = record.get("threat")
        if threat and isinstance(threat, str):
            malware = db.query(Malware).filter(Malware.name == threat).first()
            if malware is None:
                malware = Malware(
                    name=threat,
                    description=f"Malware family referenced by URLhaus ({threat})",
                    source_url=str(record.get("urlhaus_link") or ""),
                    origin="external",
                )
                db.add(malware)
                db.flush()
            exists = (
                db.query(Relationship.id)
                .filter(
                    Relationship.source_type == "indicator",
                    Relationship.source_entity_id == indicator.id,
                    Relationship.target_type == "malware",
                    Relationship.target_entity_id == malware.id,
                    Relationship.rel_type == "INDICATES",
                )
                .first()
            )
            if not exists:
                try:
                    create_relationship(
                        db=db,
                        source_type="indicator",
                        source_entity_id=indicator.id,
                        target_type="malware",
                        target_entity_id=malware.id,
                        rel_type="INDICATES",
                        evidence=f"URLhaus classifies {value} as {threat}.",
                        score=0.6,
                        relationship_classification="documented",
                        confidence_level="limited",
                        direct=True,
                        commit=False,
                    )
                    linked_malware += 1
                except Exception as exc:
                    errors.append(f"malware link for {value}: {exc}")

        imported += 1

    db.flush()
    record_source_success(db, source, imported)
    return {
        "feed": "urlhaus",
        "source": source.name,
        "source_url": feed_url,
        "fetched": len(records),
        "processed": processed,
        "imported": imported,
        "duplicates": duplicates,
        "skipped": skipped,
        "rejected": rejected,
        "malware_links": linked_malware,
        "relationships_created": linked_malware,
        "job_id": job_id,
        "errors": errors[:50],
        "note": "Indicators are stored exactly as published by URLhaus (origin='external').",
    }


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------
THREATFOX_TYPE_MAP = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash",
    "sha256_hash": "hash",
    "sha1_hash": "hash",
}


def ingest_threatfox(
    db: Session,
    url: Optional[str] = None,
    limit: int = 200,
    job_id: Optional[int] = None,
) -> Dict[str, Any]:
    settings = get_settings()
    key = _auth_key()
    if not key:
        raise FeedAuthRequired(
            "ThreatFox is blocked_missing_credentials: no abuse.ch Auth-Key is configured. "
            + ABUSE_CH_KEY_HELP
        )

    feed_url = url or settings.threatfox_url
    data, _etag = _http_json(
        feed_url,
        method="POST",
        json_body={"query": "get_iocs", "days": 1},
        headers={"Auth-Key": key},
    )
    if not isinstance(data, dict):
        raise FeedUnavailableError("ThreatFox returned an unexpected payload")
    if data.get("query_status") == "no_result":
        records: List[Any] = []
    elif data.get("query_status") not in (None, "ok"):
        raise FeedUnavailableError(f"ThreatFox query_status={data.get('query_status')}")
    else:
        records = data.get("data") or []

    source = _get_source(db, "ThreatFox", feed_url, 0.65)
    processed = imported = duplicates = skipped = rejected = linked_malware = 0
    errors: List[str] = []

    for record in records[:limit]:
        processed += 1
        if not isinstance(record, dict):
            rejected += 1
            continue
        raw_value = str(record.get("ioc") or "").strip()
        external_id = str(record.get("id") or raw_value)
        if not raw_value:
            rejected += 1
            continue

        ioc_type = THREATFOX_TYPE_MAP.get(str(record.get("ioc_type")), "other")
        value = raw_value.split(":")[0] if ioc_type == "ip" else raw_value
        if not value:
            rejected += 1
            continue

        existing = (
            db.query(InfrastructureIndicator)
            .filter(
                InfrastructureIndicator.value == value,
                InfrastructureIndicator.source == source.name,
            )
            .first()
        )
        if existing:
            duplicates += 1
            continue

        indicator = InfrastructureIndicator(
            indicator_type=ioc_type,
            value=value,
            metadata_json={
                "confidence_level": record.get("confidence_level"),
                "threat_type": record.get("threat_type"),
                "malware": record.get("malware_printable"),
                "malware_alias": record.get("malware_alias"),
                "tags": record.get("tags"),
                "reporter": record.get("reporter"),
                "first_seen": record.get("first_seen"),
                "last_seen": record.get("last_seen"),
                "reference": record.get("reference"),
                "external_id": external_id,
            },
            source=source.name,
            external_id=external_id,
            origin="external",
            reliability=source.reliability,
            last_observed=parse_datetime(record.get("last_seen"))
            or parse_datetime(record.get("first_seen"))
            or utcnow(),
        )
        db.add(indicator)
        db.flush()

        if not _evidence_exists(db, source.id, external_id):
            create_evidence(
                db=db,
                source_id=source.id,
                entity_type="indicator",
                entity_id=indicator.id,
                evidence_type="indicator",
                content=(
                    f"ThreatFox IOC {value} ({ioc_type}) associated with "
                    f"{record.get('malware_printable') or 'unknown malware'}"
                ),
                reference=str(record.get("reference") or ""),
                external_record_id=external_id,
                source_url=feed_url,
                source_published_at=parse_datetime(record.get("first_seen")),
                source_modified_at=parse_datetime(record.get("last_seen")),
                source_description="ThreatFox IOC entry",
                source_confidence=str(record.get("confidence_level") or "") or None,
                reliability=source.reliability,
                raw_payload=record,
                import_job_id=job_id,
                commit=False,
            )

        malware_name = record.get("malware_printable")
        if malware_name:
            malware = db.query(Malware).filter(Malware.name == malware_name).first()
            if malware is None:
                malware = Malware(
                    name=malware_name,
                    description=f"Malware family reported by ThreatFox ({malware_name})",
                    origin="external",
                )
                db.add(malware)
                db.flush()
            exists = (
                db.query(Relationship.id)
                .filter(
                    Relationship.source_type == "indicator",
                    Relationship.source_entity_id == indicator.id,
                    Relationship.target_type == "malware",
                    Relationship.target_entity_id == malware.id,
                    Relationship.rel_type == "INDICATES",
                )
                .first()
            )
            if not exists:
                try:
                    create_relationship(
                        db=db,
                        source_type="indicator",
                        source_entity_id=indicator.id,
                        target_type="malware",
                        target_entity_id=malware.id,
                        rel_type="INDICATES",
                        evidence=f"ThreatFox associates {value} with {malware_name}.",
                        score=0.7,
                        relationship_classification="documented",
                        confidence_level="limited",
                        direct=True,
                        commit=False,
                    )
                    linked_malware += 1
                except Exception as exc:
                    errors.append(f"malware link for {value}: {exc}")

        imported += 1

    db.flush()
    record_source_success(db, source, imported)
    return {
        "feed": "threatfox",
        "source": source.name,
        "source_url": feed_url,
        "fetched": len(records),
        "processed": processed,
        "imported": imported,
        "duplicates": duplicates,
        "skipped": skipped,
        "rejected": rejected,
        "malware_links": linked_malware,
        "relationships_created": linked_malware,
        "job_id": job_id,
        "errors": errors[:50],
        "note": "ThreatFox data is external intelligence, stored with origin='external'.",
    }


FEED_IMPLEMENTATIONS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "aptnotes": ingest_aptnotes,
    "urlhaus": ingest_urlhaus,
    "threatfox": ingest_threatfox,
}


def _default_feed_url(key: str) -> Optional[str]:
    settings = get_settings()
    return {
        "aptnotes": settings.aptnotes_url,
        "urlhaus": settings.urlhaus_recent_url,
        "threatfox": settings.threatfox_url,
    }.get(key)


def _feed_job_stats(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "records_fetched": result.get("fetched", 0),
        "records_validated": result.get("processed", 0),
        "records_imported": result.get("imported", 0),
        "records_skipped": result.get("duplicates", 0),
        "records_rejected": result.get("rejected", 0),
        "relationships_created": result.get("relationships_created", 0),
    }


def ingest_feed(
    db: Session,
    key: str,
    url: Optional[str] = None,
    limit: int = 200,
    job_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Run one external connector under collection-job tracking.

    API and CLI callers create the job first and pass ``job_id`` so evidence rows
    can point at it. A direct call without a job still gets a real job record, so
    no genuine import path can run untracked.
    """

    implementation = FEED_IMPLEMENTATIONS.get(key)
    if implementation is None:
        raise FeedError(f"Unknown feed '{key}'")
    if key in ("threatfox", "urlhaus") and not _auth_key():
        raise FeedAuthRequired(
            f"{FEED_REGISTRY[key]['name']} is blocked_missing_credentials. " + ABUSE_CH_KEY_HELP
        )

    own_job: Optional[CollectionJob] = None
    if job_id is None:
        own_job = create_job(
            db,
            f"feed:{key}",
            source_key=key,
            source_url=url or _default_feed_url(key),
        )
        job_id = own_job.id

    try:
        result = implementation(db, url=url, limit=limit, job_id=job_id)
    except Exception as exc:
        if own_job is not None:
            db.rollback()
            stored = (
                db.query(CollectionJob).filter(CollectionJob.id == own_job.id).first()
            )
            if stored is not None:
                fail_job(db, stored, f"feed ingestion failed: {exc}")
        raise

    result["job_id"] = job_id
    if own_job is not None:
        finish_job(
            db,
            own_job,
            status="completed",
            stats=_feed_job_stats(result),
            errors=result.get("errors", []),
            details={"source_url": result.get("source_url")},
        )
    return result


def get_feed_status(db: Optional[Session] = None) -> List[Dict[str, Any]]:
    """Describe every connector, including whether it can actually authenticate."""

    settings = get_settings()
    key_configured = bool(_auth_key())
    statuses: List[Dict[str, Any]] = []

    urls = {
        "aptnotes": settings.aptnotes_url,
        "urlhaus": settings.urlhaus_recent_url,
        "threatfox": settings.threatfox_url,
    }

    for key, meta in FEED_REGISTRY.items():
        requires_key = bool(meta.get("requires_key"))
        configured = key_configured if requires_key else True
        if requires_key and not configured:
            status = "blocked_missing_credentials"
            reason = "Requires a free abuse.ch Auth-Key (ABUSE_CH_AUTH_KEY); not configured."
        else:
            status = "available"
            reason = "Ready to import."
        entry = {
            "key": key,
            **meta,
            "configured": configured,
            "status": status,
            "reason": reason,
            "url": urls[key],
        }
        if db is not None:
            source = (
                db.query(IntelligenceSource)
                .filter(IntelligenceSource.name == meta["name"], IntelligenceSource.is_synthetic.is_(False))
                .order_by(IntelligenceSource.id)
                .first()
            )
            entry["source_record"] = _source_health(source) if source else None
            entry["last_job"] = _last_job(db, key)
        statuses.append(entry)

    mitre = {
        "key": "mitre_attack",
        "name": "MITRE ATT&CK",
        "description": "Official Enterprise ATT&CK STIX 2.1 bundle (public).",
        "requires_key": False,
        "configured": True,
        "status": "available",
        "reason": "Public STIX bundle; no credentials required.",
        "docs": "https://attack.mitre.org/resources/attack-data-and-tools/",
        "url": settings.mitre_attack_url,
        "produces": "groups, campaigns, malware, tools, tactics, techniques and their relationships",
    }
    if db is not None:
        source = (
            db.query(IntelligenceSource)
            .filter(
                IntelligenceSource.name == "mitre-attack-enterprise",
                IntelligenceSource.is_synthetic.is_(False),
            )
            .order_by(IntelligenceSource.id)
            .first()
        )
        mitre["source_record"] = _source_health(source) if source else None
        mitre["last_job"] = _last_job(db, "mitre_attack")
    statuses.append(mitre)
    return statuses


def _source_health(source: IntelligenceSource) -> Dict[str, Any]:
    return {
        "id": source.id,
        "name": source.name,
        "url": source.url,
        "reliability": source.reliability,
        "last_success_at": source.last_success_at,
        "last_error": source.last_error,
        "last_error_at": source.last_error_at,
        "last_object_count": source.last_object_count,
    }


def _last_job(db: Session, key: str) -> Optional[Dict[str, Any]]:
    from app.ingestion.jobs import serialize_job
    from app.models.entities import CollectionJob

    job = (
        db.query(CollectionJob)
        .filter(
            (CollectionJob.source_key == key)
            | CollectionJob.source_name.in_(
                {
                    "mitre_attack": ["mitre-attack-enterprise", "mitre_attack", "mitre-attack"],
                    "aptnotes": ["aptnotes", "feed:aptnotes"],
                    "urlhaus": ["urlhaus", "feed:urlhaus"],
                    "threatfox": ["threatfox", "feed:threatfox"],
                }.get(key, [key])
            )
        )
        .order_by(CollectionJob.started_at.desc(), CollectionJob.id.desc())
        .first()
    )
    return serialize_job(job) if job else None
