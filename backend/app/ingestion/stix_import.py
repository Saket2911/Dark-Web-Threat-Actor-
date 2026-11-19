"""STIX 2.1 bundle import.

Validates a STIX 2.1 bundle, normalizes supported objects, persists entities and
relationships with provenance, and reports records it could not import instead
of dropping them silently.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.time import parse_datetime, utcnow
from app.ingestion.deduplicator import Deduplicator
from app.ingestion.normalizer import normalize_stix_bundle
from app.ingestion.validator import validate_stix_bundle
from app.models.entities import (
    Actor,
    Campaign,
    Evidence,
    IntelligenceSource,
    Malware,
    Tactic,
    Technique,
    Tool,
)
from app.services.evidence_validator import create_evidence
from app.services.relationship_validator import create_relationship

STIX_RELATIONSHIP_MAP = {
    "related-to": "RELATED_TO",
    "attributed-to": "ATTRIBUTED_TO",
    "targets": "USES",
    "uses": "USES",
    "mitigates": "ASSOCIATED_WITH",
    "detects": "ASSOCIATED_WITH",
    "variant-of": "ASSOCIATED_WITH",
    "imitates": "ASSOCIATED_WITH",
    "targets-infrastructure": "ASSOCIATED_WITH_INFRASTRUCTURE",
    "hosts": "ASSOCIATED_WITH_INFRASTRUCTURE",
}

MODEL_MAP = {
    "Actor": Actor,
    "Campaign": Campaign,
    "Malware": Malware,
    "Tool": Tool,
    "Tactic": Tactic,
    "Technique": Technique,
}

GROUP_MAP = {
    "actors": "Actor",
    "campaigns": "Campaign",
    "malware": "Malware",
    "tools": "Tool",
    "tactics": "Tactic",
    "techniques": "Technique",
}


class StixImportError(ValueError):
    """Raised when a bundle cannot be imported at all."""


def _entity_type_for_stix_id(stix_id: str) -> Optional[str]:
    for prefix, entity_type in (
        ("intrusion-set--", "actor"),
        ("campaign--", "campaign"),
        ("malware--", "malware"),
        ("tool--", "tool"),
        ("x-mitre-tactic--", "tactic"),
        ("attack-pattern--", "technique"),
    ):
        if stix_id.startswith(prefix):
            return entity_type
    return None


def _get_or_create_source(db: Session, source_name: str) -> IntelligenceSource:
    source = db.query(IntelligenceSource).filter(IntelligenceSource.name == source_name).first()
    if source:
        return source
    source = IntelligenceSource(
        name=source_name,
        source_type="stix_bundle",
        reliability=0.8,
        is_synthetic=False,
        origin="external",
        collected_at=utcnow(),
    )
    db.add(source)
    db.flush()
    return source


def _source_url(normalized: Dict[str, Any]) -> Optional[str]:
    refs = normalized.get("external_references") or []
    for ref in refs:
        if isinstance(ref, dict) and ref.get("url"):
            return str(ref["url"])
    return None


def ingest_stix_bundle(db: Session, bundle: Any, source_name: str = "stix_upload") -> Dict[str, Any]:
    """Import a STIX 2.1 bundle into the platform."""
    if not isinstance(bundle, dict):
        raise StixImportError("STIX bundle must be a JSON object")

    validation = validate_stix_bundle(bundle)
    if validation["supported_object_count"] == 0:
        detail = "; ".join(validation["errors"][:3]) or "no supported STIX objects"
        raise StixImportError(f"No supported STIX objects found: {detail}")

    normalized = normalize_stix_bundle(bundle)
    source = _get_or_create_source(db, source_name)
    dedup = Deduplicator(db)

    entity_map: Dict[str, tuple] = {}
    errors: List[str] = list(validation.get("errors", []))[:50]
    imported = 0
    skipped = 0
    evidence_added = 0

    for group, model_type in GROUP_MAP.items():
        model_class = MODEL_MAP[model_type]
        for obj in normalized.get(group, []):
            external_id = obj.get("external_id") or ""
            if not external_id:
                errors.append(f"{model_type}: object without an external id skipped")
                continue
            name_field = "primary_handle" if model_type == "Actor" else "name"
            desc_field = "notes" if model_type == "Actor" else "description"
            url = _source_url(obj)
            defaults = {
                name_field: obj.get("name") or external_id,
                desc_field: obj.get("description") or "",
                "source_url": url,
                "origin": "external",
            }
            if model_type == "Actor":
                defaults["internal_id"] = external_id
                defaults["last_observed"] = parse_datetime(obj.get("modified"))
            elif model_type in ("Campaign", "Malware", "Tool", "Technique"):
                defaults["first_seen"] = parse_datetime(obj.get("created"))
                defaults["last_seen"] = parse_datetime(obj.get("modified"))

            try:
                entity, created = dedup.find_or_create_entity(
                    model_class=model_class,
                    external_id=external_id,
                    defaults=defaults,
                )
            except Exception as exc:
                errors.append(f"{model_type} {external_id}: {exc}")
                continue

            entity_map[external_id] = (model_type.lower(), entity.id)
            if created:
                imported += 1
            else:
                skipped += 1

            already = (
                db.query(Evidence.id)
                .filter(
                    Evidence.source_id == source.id,
                    Evidence.external_record_id == external_id,
                    Evidence.entity_type == model_type.lower(),
                    Evidence.entity_id == entity.id,
                )
                .first()
            )
            if already:
                continue
            try:
                create_evidence(
                    db=db,
                    source_id=source.id,
                    entity_type=model_type.lower(),
                    entity_id=entity.id,
                    evidence_type="stix_import",
                    content=obj.get("description") or obj.get("name"),
                    reference=url,
                    external_record_id=external_id,
                    source_url=url,
                    source_published_at=parse_datetime(obj.get("created")),
                    source_description=obj.get("name"),
                    reliability=source.reliability,
                    raw_payload=obj.get("raw_payload"),
                    commit=False,
                )
                evidence_added += 1
            except Exception as exc:
                errors.append(f"evidence for {external_id}: {exc}")

    relationships_created = 0
    relationships_skipped = 0
    for rel in normalized.get("relationships", []):
        payload = rel.get("raw_payload") or {}
        source_ref = payload.get("source_ref")
        target_ref = payload.get("target_ref")
        stix_rel_type = payload.get("relationship_type") or "related-to"

        source_info = entity_map.get(source_ref) or _lookup_existing(db, source_ref)
        target_info = entity_map.get(target_ref) or _lookup_existing(db, target_ref)
        if not source_info or not target_info:
            relationships_skipped += 1
            errors.append(
                f"relationship {rel.get('external_id')}: endpoint not imported "
                f"({source_ref} -> {target_ref})"
            )
            continue

        source_entity_type, source_entity_id = source_info
        target_entity_type, target_entity_id = target_info

        existing = dedup.find_relationship(
            source_type=source_entity_type,
            source_entity_id=source_entity_id,
            target_type=target_entity_type,
            target_entity_id=target_entity_id,
            rel_type=STIX_RELATIONSHIP_MAP.get(stix_rel_type, "RELATED_TO"),
        )
        if existing:
            relationships_skipped += 1
            continue

        try:
            create_relationship(
                db=db,
                source_type=source_entity_type,
                source_entity_id=source_entity_id,
                target_type=target_entity_type,
                target_entity_id=target_entity_id,
                rel_type=STIX_RELATIONSHIP_MAP.get(stix_rel_type, "RELATED_TO"),
                evidence=(
                    f"STIX relationship '{stix_rel_type}' imported from {source_name} "
                    f"({rel.get('external_id')})."
                ),
                score=0.8,
                relationship_classification="documented",
                confidence_level="strong",
                direct=True,
                commit=False,
            )
            relationships_created += 1
        except Exception as exc:
            relationships_skipped += 1
            errors.append(f"relationship {rel.get('external_id')}: {exc}")

    db.flush()

    return {
        "source_name": source_name,
        "records_imported": imported,
        "records_skipped": skipped,
        "evidence_added": evidence_added,
        "relationships_created": relationships_created,
        "relationships_skipped": relationships_skipped,
        "objects_in_bundle": validation.get("object_count", 0),
        "supported_objects": validation.get("supported_object_count", 0),
        "unsupported_objects": validation.get("unsupported_object_count", 0),
        "validation_warnings": validation.get("warnings", [])[:20],
        "errors": errors[:100],
        "note": (
            "Imported STIX objects are real external intelligence and are stored with "
            "origin='external'; they are not synthetic demonstration data."
        ),
    }


def _lookup_existing(db: Session, stix_id: Optional[str]):
    if not stix_id:
        return None
    entity_type = _entity_type_for_stix_id(stix_id)
    if not entity_type:
        return None
    model_type = {
        "actor": "Actor",
        "campaign": "Campaign",
        "malware": "Malware",
        "tool": "Tool",
        "tactic": "Tactic",
        "technique": "Technique",
    }[entity_type]
    model = MODEL_MAP[model_type]
    entity = db.query(model).filter(model.external_id == stix_id).first()
    if not entity:
        return None
    return entity_type, entity.id
