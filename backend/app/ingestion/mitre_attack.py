"""MITRE ATT&CK Enterprise STIX 2.1 ingestion.

Official source:
https://github.com/mitre-attack/attack-stix-data

The adapter downloads the published Enterprise bundle, imports the supported
object types (groups/intrusion sets, campaigns, malware, tools, tactics,
techniques and their relationships), preserves the original STIX identifiers,
timestamps, aliases and external references, and records honest statistics.

Notes on interpretation
-----------------------
* MITRE ATT&CK group entries are catalogued intrusion sets. They are imported
  with ``origin='external'`` and are *not* treated as independently verified
  real-world identities. Relationships MITRE documents are stored with
  ``relationship_classification='documented'`` and
  ``confidence_level='limited'`` because ATT&CK itself states that group
  attribution is not definitive.
* Revoked and deprecated objects are not imported as active intelligence; they
  are counted and reported so the omission is visible.
* Re-imports are idempotent: entities are matched on their STIX ID, evidence on
  (source, STIX ID, entity) and relationships on their endpoints and type.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

from app.core.time import utcnow
from app.ingestion.base import BaseIngestionAdapter, FetchError, ParseError
from app.ingestion.jobs import (
    create_job,
    fail_job,
    finish_job,
    record_source_failure,
    record_source_success,
)
from app.ingestion.normalizer import normalize_stix_object
from app.ingestion.validator import SUPPORTED_STIX_TYPES, validate_stix_object
from app.models.entities import (
    Actor,
    Campaign,
    CollectionJob,
    Evidence,
    IntelligenceSource,
    Malware,
    Relationship,
    Tactic,
    Technique,
    Tool,
)
from app.services.evidence_validator import create_evidence
from app.services.relationship_validator import create_relationship

logger = logging.getLogger(__name__)

MITRE_ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

STIX_RELATIONSHIP_MAP: Dict[str, str] = {
    "related-to": "RELATED_TO",
    "attributed-to": "ATTRIBUTED_TO",
    "targets": "USES",
    "uses": "USES",
    "delivers": "DELIVERS",
    "drops": "DELIVERS",
    "mitigates": "ASSOCIATED_WITH",
    "detects": "ASSOCIATED_WITH",
    "variant-of": "ASSOCIATED_WITH",
    "imitates": "ASSOCIATED_WITH",
    "subtechnique-of": "ASSOCIATED_WITH",
    "targets-infrastructure": "ASSOCIATED_WITH_INFRASTRUCTURE",
    "hosts": "ASSOCIATED_WITH_INFRASTRUCTURE",
}

SUPPORTED_PREFIXES: Dict[str, str] = {
    "intrusion-set--": "actor",
    "campaign--": "campaign",
    "malware--": "malware",
    "tool--": "tool",
    "x-mitre-tactic--": "tactic",
    "attack-pattern--": "technique",
}

MAX_STORED_ERRORS = 50


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
        # SQLite stores naive datetimes; normalise to naive UTC for comparisons.
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (ValueError, TypeError):
        return None


def _first_reference_url(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            return str(ref["url"])
    return None


class MitreAttackAdapter(BaseIngestionAdapter):
    """Fetch, normalise and persist the official Enterprise ATT&CK bundle."""

    source_name = "mitre-attack-enterprise"
    source_type = "stix_bundle"
    reliability = 0.9
    is_synthetic = False
    origin = "external"

    def __init__(
        self,
        db,
        stix_url: str = MITRE_ATTACK_ENTERPRISE_URL,
        batch_size: int = 100,
        source_name: Optional[str] = None,
        force: bool = False,
    ):
        super().__init__(db=db, source_name=source_name)
        self.stix_url = stix_url
        self.batch_size = batch_size
        self.force = force
        self.bundle_version: Optional[str] = None
        self._entity_id_map: Dict[str, Tuple[str, int]] = {}
        self._source: Optional[IntelligenceSource] = None
        self._etag: Optional[str] = None
        self._not_modified = False
        self._updated = 0
        self._evidence_added = 0
        self._relationships_created = 0
        self._relationships_skipped = 0
        self._revoked_skipped = 0
        self._unsupported = 0
        self._rejected = 0
        self._error_count = 0

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------
    def fetch(self) -> List[Dict[str, Any]]:
        headers = {"User-Agent": "CN-Project-CTI/1.0 (MITRE ATT&CK importer)"}
        if self._etag:
            headers["If-None-Match"] = self._etag
        try:
            response = requests.get(self.stix_url, timeout=120, headers=headers)
        except requests.exceptions.RequestException as exc:
            raise FetchError(f"Failed to fetch MITRE ATT&CK bundle: {exc}") from exc

        if response.status_code == 304:
            self._not_modified = True
            return []
        if response.status_code == 404:
            raise FetchError(f"MITRE ATT&CK bundle not found at {self.stix_url}")
        try:
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise FetchError(f"MITRE ATT&CK download failed: {exc}") from exc

        try:
            bundle = response.json()
        except ValueError as exc:
            raise ParseError(f"MITRE ATT&CK bundle is not valid JSON: {exc}") from exc

        self._etag = response.headers.get("ETag") or self._etag
        self.bundle_version = bundle.get("spec_version") or None
        objects = bundle.get("objects") or []
        if not objects:
            raise ParseError("MITRE ATT&CK bundle contained no objects")
        logger.info("Fetched MITRE ATT&CK bundle with %d objects", len(objects))
        return [bundle]

    def parse(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not raw_data:
            return []
        bundle = raw_data[0]
        if not isinstance(bundle, dict):
            raise ParseError("MITRE ATT&CK payload is not a JSON object")

        objects = bundle.get("objects") or []
        if not isinstance(objects, list):
            raise ParseError("MITRE ATT&CK bundle 'objects' is not a list")

        parsed: List[Dict[str, Any]] = []
        for obj in objects:
            if not isinstance(obj, dict):
                self._unsupported += 1
                continue
            stix_type = obj.get("type")
            if stix_type not in SUPPORTED_STIX_TYPES:
                self._unsupported += 1
                continue
            try:
                validate_stix_object(obj)
            except Exception as exc:
                self._rejected += 1
                self._append_error(f"{obj.get('id', 'unknown')}: {exc}")
                continue
            parsed.append(obj)
        return parsed

    def validate(self, record: Dict[str, Any]) -> bool:
        candidate = record if "type" in record else {
            "type": record.get("stix_type"),
            "id": record.get("stix_id") or record.get("external_id"),
            "name": record.get("name"),
        }
        try:
            validate_stix_object(candidate)
            return True
        except Exception:
            return False

    def normalize(self, record: Dict[str, Any]) -> Dict[str, Any]:
        return normalize_stix_object(record)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _persist_record(self, normalized_record: Dict[str, Any]) -> bool:
        """Create/update one entity. Returns True when the row was created."""

        model_type = normalized_record.get("model_type")
        external_id = normalized_record.get("external_id") or ""
        model_class = {
            "Actor": Actor,
            "Campaign": Campaign,
            "Malware": Malware,
            "Tool": Tool,
            "Tactic": Tactic,
            "Technique": Technique,
        }.get(model_type or "")
        if model_class is None or not external_id:
            self._rejected += 1
            return False

        raw = normalized_record.get("raw_payload") or {}
        name = (normalized_record.get("name") or external_id).strip()
        description = normalized_record.get("description") or ""
        source_url = _first_reference_url(raw)
        created_dt = _parse_iso_datetime(normalized_record.get("created"))
        modified_dt = _parse_iso_datetime(normalized_record.get("modified"))

        defaults: Dict[str, Any] = {
            "source_url": source_url,
            "origin": self.origin,
        }
        if model_type == "Actor":
            defaults.update(
                {
                    "primary_handle": name,
                    "notes": description,
                    "internal_id": external_id,
                    "aliases": normalized_record.get("aliases") or None,
                    "last_observed": modified_dt,
                }
            )
        elif model_type == "Tactic":
            defaults.update({"name": name, "description": description})
        else:
            defaults.update(
                {
                    "name": name,
                    "description": description,
                    "first_seen": created_dt,
                    "last_seen": modified_dt,
                }
            )

        existing = (
            self.db.query(model_class)
            .filter(model_class.external_id == external_id)
            .first()
        )
        created = existing is None
        if existing is None:
            entity = model_class(external_id=external_id, **defaults)
            self.db.add(entity)
            self.db.flush()
        else:
            entity = existing
            # Refresh source-published fields; never invent values.
            if model_type == "Actor":
                if name and entity.primary_handle != name:
                    entity.primary_handle = name
                if normalized_record.get("aliases"):
                    entity.aliases = normalized_record["aliases"]
                if description:
                    entity.notes = description
                if modified_dt and (entity.last_observed is None or modified_dt > entity.last_observed):
                    entity.last_observed = modified_dt
            elif model_type == "Tactic":
                if name and entity.name != name:
                    entity.name = name
                if description:
                    entity.description = description
            else:
                if name and entity.name != name:
                    entity.name = name
                if description:
                    entity.description = description
                if modified_dt and (entity.last_seen is None or modified_dt > entity.last_seen):
                    entity.last_seen = modified_dt
            if source_url and not entity.source_url:
                entity.source_url = source_url
            if not entity.origin:
                entity.origin = self.origin
            self.db.flush()
            self._updated += 1

        self._entity_id_map[external_id] = (model_type.lower(), entity.id)

        already = (
            self.db.query(Evidence.id)
            .filter(
                Evidence.source_id == self._source.id,
                Evidence.external_record_id == external_id,
                Evidence.entity_type == model_type.lower(),
                Evidence.entity_id == entity.id,
            )
            .first()
        )
        if not already:
            try:
                create_evidence(
                    db=self.db,
                    source_id=self._source.id,
                    entity_type=model_type.lower(),
                    entity_id=entity.id,
                    evidence_type="stix_object",
                    content=description or name,
                    reference=source_url,
                    external_record_id=external_id,
                    source_url=self.stix_url,
                    source_published_at=created_dt,
                    source_modified_at=modified_dt,
                    source_description=f"MITRE ATT&CK {normalized_record.get('stix_type')}: {name}",
                    reliability=self.reliability,
                    raw_payload=raw,
                    import_job_id=self.collection_job_id,
                    commit=False,
                )
                self._evidence_added += 1
            except Exception as exc:
                self._append_error(f"evidence for {external_id}: {exc}")
        return created

    def _persist_relationships_bulk(self, relationships: List[Dict[str, Any]]) -> None:
        """Insert documented relationships in batches without per-row probes.

        Endpoints are guaranteed to exist because they come from entities this
        run persisted; validation here is structural (types, relationship
        vocabulary, self-reference) and duplicates are removed against an
        in-memory set of existing keys.
        """

        from app.services.relationship_validator import (
            SUPPORTED_ENTITY_TYPES,
            VALID_RELATIONSHIP_TYPES,
        )

        existing = {
            (row[0], row[1], row[2], row[3], row[4])
            for row in self.db.query(
                Relationship.source_type,
                Relationship.source_entity_id,
                Relationship.target_type,
                Relationship.target_entity_id,
                Relationship.rel_type,
            ).all()
        }

        pending = 0
        for rel in relationships:
            payload = rel.get("raw_payload") or {}
            source_ref = payload.get("source_ref") or ""
            target_ref = payload.get("target_ref") or ""
            stix_rel_type = (payload.get("relationship_type") or "related-to").lower()
            stix_rel_id = rel.get("external_id") or payload.get("id") or ""

            source_info = self._entity_id_map.get(source_ref)
            target_info = self._entity_id_map.get(target_ref)
            if not source_info or not target_info:
                self._relationships_skipped += 1
                continue

            source_type, source_id = source_info
            target_type, target_id = target_info
            internal_type = STIX_RELATIONSHIP_MAP.get(stix_rel_type, "RELATED_TO")

            if (
                source_type not in SUPPORTED_ENTITY_TYPES
                or target_type not in SUPPORTED_ENTITY_TYPES
                or internal_type not in VALID_RELATIONSHIP_TYPES
                or (source_type == target_type and source_id == target_id)
            ):
                self._relationships_skipped += 1
                continue

            key = (source_type, source_id, target_type, target_id, internal_type)
            if key in existing:
                self._relationships_skipped += 1
                continue
            existing.add(key)

            self.db.add(
                Relationship(
                    source_actor_id=source_id if source_type == "actor" else None,
                    target_actor_id=target_id if target_type == "actor" else None,
                    source_type=source_type,
                    source_entity_id=source_id,
                    target_type=target_type,
                    target_entity_id=target_id,
                    rel_type=internal_type,
                    evidence=(
                        f"MITRE ATT&CK documents STIX relationship '{stix_rel_type}' "
                        f"between {source_ref} and {target_ref} (relationship {stix_rel_id}). "
                        "ATT&CK group attribution is a catalogued assessment, not independently "
                        "verified identity."
                    ),
                    score=0.8,
                    relationship_classification="documented",
                    confidence_level="limited",
                    source_confidence=None,
                    direct=True,
                )
            )
            self._relationships_created += 1
            pending += 1
            if pending >= 1000:
                self.db.commit()
                pending = 0
        self.db.commit()

    def _persist_relationship(self, norm_rel: Dict[str, Any]) -> bool:
        payload = norm_rel.get("raw_payload") or {}
        source_ref = payload.get("source_ref") or ""
        target_ref = payload.get("target_ref") or ""
        stix_rel_type = (payload.get("relationship_type") or "related-to").lower()
        stix_rel_id = norm_rel.get("external_id") or payload.get("id") or ""

        source_info = self._entity_id_map.get(source_ref)
        target_info = self._entity_id_map.get(target_ref)
        if not source_info or not target_info:
            self._relationships_skipped += 1
            return False

        source_type, source_id = source_info
        target_type, target_id = target_info
        internal_type = STIX_RELATIONSHIP_MAP.get(stix_rel_type, "RELATED_TO")

        existing = (
            self.db.query(Relationship.id)
            .filter(
                Relationship.source_type == source_type,
                Relationship.source_entity_id == source_id,
                Relationship.target_type == target_type,
                Relationship.target_entity_id == target_id,
                Relationship.rel_type == internal_type,
            )
            .first()
        )
        if existing:
            self._relationships_skipped += 1
            return False

        evidence_text = (
            f"MITRE ATT&CK documents STIX relationship '{stix_rel_type}' "
            f"between {source_ref} and {target_ref} (relationship {stix_rel_id}). "
            "ATT&CK group attribution is a catalogued assessment, not independently "
            "verified identity."
        )
        try:
            create_relationship(
                db=self.db,
                source_type=source_type,
                source_entity_id=source_id,
                target_type=target_type,
                target_entity_id=target_id,
                rel_type=internal_type,
                evidence=evidence_text,
                score=0.8,
                relationship_classification="documented",
                confidence_level="limited",
                source_confidence=None,
                direct=True,
                commit=False,
            )
            self._relationships_created += 1
            return True
        except Exception as exc:
            self._relationships_skipped += 1
            self._append_error(f"relationship {stix_rel_id}: {exc}")
            return False

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        self._records_imported = 0
        self._updated = 0
        self._evidence_added = 0
        self._relationships_created = 0
        self._relationships_skipped = 0
        self._revoked_skipped = 0
        self._unsupported = 0
        self._rejected = 0
        self._error_count = 0
        self._errors: List[str] = []

        source_id = self._create_or_get_source()
        self._source = self.db.query(IntelligenceSource).filter(IntelligenceSource.id == source_id).one()
        if self.stix_url and not self._source.url:
            self._source.url = self.stix_url
            self.db.commit()
        self._etag = None if self.force else self._source.last_etag

        job: CollectionJob = create_job(
            self.db,
            self.source_name,
            source_key="mitre_attack",
            source_url=self.stix_url,
        )
        self.collection_job_id = job.id

        try:
            raw = self.fetch()
        except Exception as exc:
            logger.exception("MITRE ATT&CK fetch failed: %s", exc)
            self._append_error(str(exc))
            record_source_failure(self.db, self._source, str(exc))
            fail_job(self.db, job, str(exc))
            return self._result(job, fetched=0, status="failed")

        if self._not_modified or not raw:
            record_source_success(self.db, self._source, 0, etag=self._etag)
            finish_job(
                self.db,
                job,
                status="not_modified",
                stats={"records_fetched": 0},
                details={"reason": "The official bundle is unchanged since the last import (HTTP 304)."},
            )
            return self._result(job, fetched=0, status="not_modified")

        try:
            objects = self.parse(raw)
        except Exception as exc:
            record_source_failure(self.db, self._source, str(exc))
            fail_job(self.db, job, str(exc))
            return self._result(job, fetched=0, status="failed")

        fetched = len((raw[0] or {}).get("objects") or [])
        entities: List[Dict[str, Any]] = []
        relationships: List[Dict[str, Any]] = []
        for obj in objects:
            normalized = normalize_stix_object(obj)
            if normalized.get("revoked") or normalized.get("deprecated"):
                self._revoked_skipped += 1
                continue
            if normalized.get("model_type") == "Relationship":
                relationships.append(normalized)
            else:
                entities.append(normalized)

        for entity in entities:
            savepoint = self.db.begin_nested()
            try:
                created = self._persist_record(entity)
                savepoint.commit()
                if created:
                    self._records_imported += 1
            except Exception as exc:
                savepoint.rollback()
                self._rejected += 1
                self._append_error(f"{entity.get('external_id', 'unknown')}: {exc}")

        self.db.commit()

        self._persist_relationships_bulk(relationships)

        stats = {
            "records_fetched": fetched,
            "records_validated": len(entities) + len(relationships),
            "records_imported": self._records_imported,
            "records_updated": self._updated,
            "records_skipped": self._relationships_skipped + self._revoked_skipped,
            "records_rejected": self._rejected,
            "revoked_or_deprecated_skipped": self._revoked_skipped,
            "unsupported_objects_skipped": self._unsupported,
            "relationships_created": self._relationships_created,
            "relationships_skipped": self._relationships_skipped,
            "evidence_added": self._evidence_added,
        }
        wrote_something = bool(
            self._records_imported or self._updated or self._relationships_created
        )
        # A run that created documented relationships is a successful import even
        # when every entity already existed. finish_job distinguishes an
        # idempotent no-op from an empty import using the real counters.
        status = "completed" if (wrote_something or self._rejected) else "completed_empty"
        finish_job(self.db, job, status=status, stats=stats, errors=self._errors, details={
            "bundle_url": self.stix_url,
            "spec_version": self.bundle_version,
            "revoked_or_deprecated_skipped": self._revoked_skipped,
            "unsupported_objects_skipped": self._unsupported,
        })
        record_source_success(self.db, self._source, fetched, etag=self._etag)

        return self._result(job, fetched=fetched, status=status, stats=stats)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _append_error(self, message: str) -> None:
        self._error_count += 1
        if len(self._errors) < MAX_STORED_ERRORS:
            self._errors.append(message)

    def _result(self, job: CollectionJob, *, fetched: int, status: str, stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        stats = stats or {}
        return {
            "source_name": self.source_name,
            "source_key": "mitre_attack",
            "source_type": self.source_type,
            "source_url": self.stix_url,
            "status": status,
            "job_id": job.id,
            "retrieved_at": utcnow().isoformat(),
            "records_fetched": fetched,
            "records_parsed": stats.get("records_validated", 0),
            "records_validated": stats.get("records_validated", 0),
            "records_normalized": stats.get("records_validated", 0),
            "records_imported": stats.get("records_imported", 0),
            "records_updated": stats.get("records_updated", 0),
            "records_skipped": stats.get("records_skipped", 0),
            "records_rejected": stats.get("records_rejected", 0),
            "relationships_created": stats.get("relationships_created", 0),
            "relationships_skipped": stats.get("relationships_skipped", 0),
            "revoked_or_deprecated_skipped": stats.get("revoked_or_deprecated_skipped", self._revoked_skipped),
            "unsupported_objects_skipped": stats.get("unsupported_objects_skipped", self._unsupported),
            "evidence_added": stats.get("evidence_added", self._evidence_added),
            "error_count": self._error_count,
            "errors": self._errors,
            "bundle_version": self.bundle_version,
        }
