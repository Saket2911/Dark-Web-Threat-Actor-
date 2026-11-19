"""External intelligence feed integrations.

Implemented against documented public interfaces only:

* **MITRE ATT&CK** - official STIX bundle (see ``mitre_attack.py``).
* **APTnotes** - public JSON index of public APT report PDFs on GitHub.
* **URLhaus** - public recent-URL feed (abuse.ch).
* **ThreatFox** - abuse.ch IOC API; requires a free abuse.ch Auth-Key. When no
  key is configured the adapter reports that explicitly instead of pretending
  the feed works.

All requests use timeouts, bounded retries with backoff and rate-limit
awareness. Every import records a collection timestamp and source provenance,
and deduplicates on the feed's own record identifier.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional

import requests
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.time import parse_datetime, utcnow
from app.models.entities import (
    Actor,
    Evidence,
    IntelligenceSource,
    InfrastructureIndicator,
    Malware,
    Relationship,
)
from app.services.evidence_validator import create_evidence
from app.services.relationship_validator import create_relationship

logger = logging.getLogger(__name__)


class FeedError(RuntimeError):
    """Base class for feed failures."""


class FeedUnavailableError(FeedError):
    """The feed could not be reached or returned an unusable response."""


class FeedAuthRequired(FeedError):
    """The feed requires credentials that are not configured."""


FEED_REGISTRY: Dict[str, Dict[str, Any]] = {
    "aptnotes": {
        "name": "APTnotes",
        "description": "Public index of APT campaign reports (GitHub, no key required).",
        "requires_key": False,
        "docs": "https://github.com/aptnotes/data",
        "produces": "report evidence (and links to known actors when the title names one)",
    },
    "urlhaus": {
        "name": "URLhaus",
        "description": "Recent malicious URLs from abuse.ch (public, no key required).",
        "requires_key": False,
        "docs": "https://urlhaus-api.abuse.ch/",
        "produces": "URL infrastructure indicators with evidence",
    },
    "threatfox": {
        "name": "ThreatFox",
        "description": "IOC sharing API from abuse.ch (free Auth-Key required).",
        "requires_key": True,
        "docs": "https://threatfox-api.abuse.ch/api/",
        "produces": "IP/domain/URL/hash indicators linked to malware families",
    },
}


def _http_json(
    url: str,
    *,
    method: str = "GET",
    json_body: Optional[dict] = None,
    headers: Optional[dict] = None,
) -> Any:
    settings = get_settings()
    last_error: Optional[Exception] = None
    attempts = max(1, settings.feed_max_retries + 1)
    for attempt in range(attempts):
        try:
            response = requests.request(
                method,
                url,
                json=json_body,
                headers=headers,
                timeout=settings.feed_timeout_seconds,
                allow_redirects=True,
            )
            if response.status_code == 429:
                retry_after = float(response.headers.get("Retry-After", "2") or 2)
                time.sleep(min(retry_after, 30))
                last_error = FeedUnavailableError("rate limited by feed")
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as exc:
            last_error = exc
            if attempt < attempts - 1:
                time.sleep(1.5 * (attempt + 1))
        except ValueError as exc:
            raise FeedUnavailableError(f"Feed returned non-JSON content: {exc}") from exc
    raise FeedUnavailableError(f"Feed request failed after {attempts} attempt(s): {last_error}")


def _get_source(db: Session, name: str, url: str, reliability: float) -> IntelligenceSource:
    source = db.query(IntelligenceSource).filter(IntelligenceSource.name == name).first()
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


def _evidence_exists(db: Session, source_id: int, external_id: str) -> bool:
    return (
        db.query(Evidence.id)
        .filter(Evidence.source_id == source_id, Evidence.external_record_id == external_id)
        .first()
        is not None
    )


# ---------------------------------------------------------------------------
# APTnotes
# ---------------------------------------------------------------------------
def ingest_aptnotes(db: Session, url: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    settings = get_settings()
    feed_url = url or settings.aptnotes_url
    data = _http_json(feed_url)
    if isinstance(data, dict):
        records = data.get("reports", data.get("records", []))
    else:
        records = data
    if not isinstance(records, list):
        raise FeedUnavailableError("APTnotes feed did not return a list of reports")

    source = _get_source(db, "APTnotes", feed_url, 0.7)
    actors = db.query(Actor).order_by(Actor.id).all()

    processed = imported = duplicates = skipped = 0
    errors: List[str] = []

    for record in records[:limit]:
        processed += 1
        if not isinstance(record, dict):
            skipped += 1
            errors.append("record is not an object")
            continue
        external_id = str(record.get("filename") or record.get("url") or "").strip()
        if not external_id:
            skipped += 1
            errors.append("record has no filename/url identifier")
            continue
        if _evidence_exists(db, source.id, external_id):
            duplicates += 1
            continue

        title = str(record.get("title") or record.get("filename") or "Unnamed report")
        url_value = record.get("url") or record.get("link")
        published = parse_datetime(record.get("date"))

        matched_actor = None
        lowered = title.lower()
        for actor in actors:
            handle = (actor.primary_handle or "").strip().lower()
            if len(handle) >= 4 and re.search(rf"\b{re.escape(handle)}\b", lowered):
                matched_actor = actor
                break

        try:
            create_evidence(
                db=db,
                source_id=source.id,
                entity_type="actor" if matched_actor else None,
                entity_id=matched_actor.id if matched_actor else None,
                evidence_type="report",
                content=title,
                reference=str(url_value) if url_value else external_id,
                external_record_id=external_id,
                source_url=str(url_value) if url_value else None,
                source_published_at=published,
                source_description="APTnotes public report index entry",
                reliability=source.reliability,
                raw_payload=record,
                commit=False,
            )
            imported += 1
        except Exception as exc:
            errors.append(f"{external_id}: {exc}")

    db.flush()
    return {
        "feed": "aptnotes",
        "source": source.name,
        "fetched": len(records),
        "processed": processed,
        "imported": imported,
        "duplicates": duplicates,
        "skipped": skipped,
        "errors": errors[:50],
        "note": (
            "Each report is stored as evidence. A report is only linked to an actor when the "
            "title explicitly names an actor already tracked in the platform."
        ),
    }


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------
def ingest_urlhaus(db: Session, url: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    settings = get_settings()
    feed_url = url or settings.urlhaus_recent_url
    data = _http_json(feed_url)
    if not isinstance(data, dict):
        raise FeedUnavailableError("URLhaus returned an unexpected payload")
    status = data.get("query_status")
    if status and status != "ok":
        raise FeedUnavailableError(f"URLhaus query_status={status}")
    records = data.get("urls") or []

    source = _get_source(db, "URLhaus", feed_url, 0.6)
    processed = imported = duplicates = skipped = 0
    errors: List[str] = []
    linked_malware = 0

    for record in records[:limit]:
        processed += 1
        if not isinstance(record, dict):
            skipped += 1
            continue
        value = str(record.get("url") or "").strip()
        external_id = str(record.get("id") or value)
        if not value:
            skipped += 1
            errors.append("URL entry without a url value")
            continue

        existing = (
            db.query(InfrastructureIndicator)
            .filter(InfrastructureIndicator.value == value)
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
                "reference": record.get("urlhaus_link"),
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
                source_url=str(record.get("urlhaus_link") or ""),
                source_published_at=parse_datetime(record.get("date_added")),
                source_description="URLhaus recent URL entry",
                reliability=source.reliability,
                raw_payload=record,
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
    return {
        "feed": "urlhaus",
        "source": source.name,
        "fetched": len(records),
        "processed": processed,
        "imported": imported,
        "duplicates": duplicates,
        "skipped": skipped,
        "malware_links": linked_malware,
        "errors": errors[:50],
        "note": "Indicators are stored as observed external intelligence (origin='external').",
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


def ingest_threatfox(db: Session, url: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    settings = get_settings()
    if not settings.abuse_ch_auth_key:
        raise FeedAuthRequired(
            "ThreatFox requires a free abuse.ch Auth-Key. Set ABUSE_CH_AUTH_KEY in the "
            "environment (Sites/desktop env file or .env) and retry. The endpoint "
            "remains unavailable until a key is configured."
        )

    feed_url = url or settings.threatfox_url
    data = _http_json(
        feed_url,
        method="POST",
        json_body={"query": "get_iocs", "days": 1},
        headers={"Auth-Key": settings.abuse_ch_auth_key},
    )
    if not isinstance(data, dict):
        raise FeedUnavailableError("ThreatFox returned an unexpected payload")
    if data.get("query_status") not in (None, "ok"):
        raise FeedUnavailableError(f"ThreatFox query_status={data.get('query_status')}")
    records = data.get("data") or []

    source = _get_source(db, "ThreatFox", feed_url, 0.65)
    processed = imported = duplicates = skipped = linked_malware = 0
    errors: List[str] = []

    for record in records[:limit]:
        processed += 1
        if not isinstance(record, dict):
            skipped += 1
            continue
        raw_value = str(record.get("ioc") or "").strip()
        external_id = str(record.get("id") or raw_value)
        if not raw_value:
            skipped += 1
            continue

        ioc_type = THREATFOX_TYPE_MAP.get(str(record.get("ioc_type")), "other")
        value = raw_value
        if ioc_type == "ip":
            value = raw_value.split(":")[0]
        if not value:
            skipped += 1
            continue

        existing = (
            db.query(InfrastructureIndicator)
            .filter(InfrastructureIndicator.value == value)
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
                "tags": record.get("tags"),
                "reporter": record.get("reporter"),
                "first_seen": record.get("first_seen"),
                "reference": record.get("reference"),
            },
            source=source.name,
            external_id=external_id,
            origin="external",
            reliability=source.reliability,
            last_observed=parse_datetime(record.get("first_seen")) or utcnow(),
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
                source_url=str(record.get("reference") or ""),
                source_published_at=parse_datetime(record.get("first_seen")),
                source_description="ThreatFox IOC entry",
                source_confidence=str(record.get("confidence_level") or "") or None,
                reliability=source.reliability,
                raw_payload=record,
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
    return {
        "feed": "threatfox",
        "source": source.name,
        "fetched": len(records),
        "processed": processed,
        "imported": imported,
        "duplicates": duplicates,
        "skipped": skipped,
        "malware_links": linked_malware,
        "errors": errors[:50],
        "note": "ThreatFox data is external intelligence, stored with origin='external'.",
    }


FEED_IMPLEMENTATIONS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "aptnotes": ingest_aptnotes,
    "urlhaus": ingest_urlhaus,
    "threatfox": ingest_threatfox,
}


def ingest_feed(db: Session, key: str, url: Optional[str] = None, limit: int = 200) -> Dict[str, Any]:
    implementation = FEED_IMPLEMENTATIONS.get(key)
    if implementation is None:
        raise FeedError(f"Unknown feed '{key}'")
    if key == "threatfox" and not get_settings().abuse_ch_auth_key:
        raise FeedAuthRequired(
            "ThreatFox requires a free abuse.ch Auth-Key (ABUSE_CH_AUTH_KEY). "
            "No key is configured, so the feed is intentionally disabled."
        )
    return implementation(db, url=url, limit=limit)


def get_feed_status() -> List[Dict[str, Any]]:
    settings = get_settings()
    statuses = []
    for key, meta in FEED_REGISTRY.items():
        configured = True
        reason = "Public feed; no credentials required."
        if key == "threatfox":
            configured = bool(settings.abuse_ch_auth_key)
            reason = (
                "Auth-Key configured."
                if configured
                else "Requires a free abuse.ch Auth-Key (ABUSE_CH_AUTH_KEY); not configured."
            )
        statuses.append(
            {
                "key": key,
                **meta,
                "configured": configured,
                "status": "available" if configured else "blocked_missing_credentials",
                "reason": reason,
                "url": {
                    "aptnotes": settings.aptnotes_url,
                    "urlhaus": settings.urlhaus_recent_url,
                    "threatfox": settings.threatfox_url,
                }[key],
            }
        )
    statuses.append(
        {
            "key": "mitre_attack",
            "name": "MITRE ATT&CK",
            "description": "Official Enterprise ATT&CK STIX 2.1 bundle (public).",
            "requires_key": False,
            "configured": True,
            "status": "available",
            "reason": "Public STIX bundle; no credentials required.",
            "docs": "https://attack.mitre.org/resources/attack-data-and-tools/",
            "url": settings.mitre_attack_url,
            "produces": "actors (intrusion sets), campaigns, malware, tools, tactics, techniques and relationships",
        }
    )
    return statuses
