"""Centralized validation and creation service for Evidence records.

Provides application-level validation for evidence creation since SQLite
does not support conditional/polymorphic foreign key constraints on the
entity_type/entity_id fields.

All API endpoints and ingestion adapters that create Evidence records
must call create_evidence() so that validation rules are consistently applied.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.database.session import SessionLocal
from app.models.entities import (
    Actor,
    Campaign,
    Evidence,
    InfrastructureIndicator,
    IntelligenceSource,
    Malware,
    Tool,
    Tactic,
    Technique,
)

# Entity types that Evidence can reference
EVIDENCE_ENTITY_TYPES: List[str] = [
    "actor",
    "campaign",
    "malware",
    "tool",
    "technique",
    "tactic",
    "indicator",
]

# Entity type -> model class mapping for existence checks
EVIDENCE_ENTITY_MODEL_MAP: Dict[str, Any] = {
    "actor": Actor,
    "campaign": Campaign,
    "malware": Malware,
    "tool": Tool,
    "technique": Technique,
    "tactic": Tactic,
    "indicator": InfrastructureIndicator,
}


class EvidenceValidationError(ValueError):
    """Raised when evidence creation validation fails."""


def validate_evidence_entity(
    db: SessionLocal,
    entity_type: str,
    entity_id: int,
) -> None:
    """Validate that an entity type and ID reference an existing entity.

    Args:
        db: SQLAlchemy database session.
        entity_type: Type of the referenced entity.
        entity_id: ID of the referenced entity.

    Raises:
        EvidenceValidationError: If the entity type is unsupported or
            the entity does not exist.
    """
    if entity_type not in EVIDENCE_ENTITY_TYPES:
        raise EvidenceValidationError(
            f"Unsupported evidence entity type: '{entity_type}'. "
            f"Supported types: {EVIDENCE_ENTITY_TYPES}"
        )

    model = EVIDENCE_ENTITY_MODEL_MAP[entity_type]
    entity = db.query(model).filter(model.id == entity_id).first()
    if entity is None:
        raise EvidenceValidationError(
            f"Evidence entity not found: {entity_type} id {entity_id}"
        )


def validate_intelligence_source(db: SessionLocal, source_id: int) -> IntelligenceSource:
    """Validate that an IntelligenceSource ID references an existing source.

    Args:
        db: SQLAlchemy database session.
        source_id: ID of the IntelligenceSource.

    Returns:
        The IntelligenceSource object if it exists.

    Raises:
        EvidenceValidationError: If the source does not exist.
    """
    source = db.query(IntelligenceSource).filter(IntelligenceSource.id == source_id).first()
    if source is None:
        raise EvidenceValidationError(
            f"IntelligenceSource not found: id {source_id}"
        )
    return source


def create_evidence(
    db: SessionLocal,
    source_id: int,
    evidence_type: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    content: Optional[str] = None,
    reference: Optional[str] = None,
    external_record_id: Optional[str] = None,
    source_url: Optional[str] = None,
    source_published_at: Optional[datetime] = None,
    source_description: Optional[str] = None,
    source_confidence: Optional[str] = None,
    reliability: float = 0.5,
    raw_payload: Optional[dict] = None,
    actor_id: Optional[int] = None,
    commit: bool = True,
) -> Evidence:
    """Create and persist a validated Evidence record.

    This is the single creation entry point for all Evidence records.
    Every caller (ingestion adapters, investigation tools, API endpoints)
    must use this function so that validation rules are consistently applied.

    Args:
        db: SQLAlchemy database session.
        source_id: ID of the IntelligenceSource this evidence comes from.
        evidence_type: Type of evidence (text_sample, indicator, report, etc.).
        entity_type: Optional type of the referenced entity (polymorphic).
        entity_id: Optional ID of the referenced entity (polymorphic).
        content: Optional evidence content text.
        reference: Optional reference text/URL.
        external_record_id: Optional external system record ID.
        source_url: Optional original source URL.
        source_published_at: Optional original publication timestamp (distinct from collection time).
        source_description: Optional original source description.
        source_confidence: Optional source-provided confidence value.
        reliability: Internal reliability score (0.0 to 1.0).
        raw_payload: Optional safely stored original source fields as JSON.
        actor_id: Optional legacy actor ID for backward-compatible actor evidence.
        commit: Whether to commit the transaction immediately. When False,
            the record is added and flushed but not committed, allowing the
            caller to batch multiple creations in a single transaction.

    Returns:
        The persisted Evidence object.

    Raises:
        EvidenceValidationError: If validation fails.
        ValueError: If database persistence fails.

    Transaction ownership:
        - commit=True (default): The function commits after adding the record.
          The caller does not need to call db.commit().
        - commit=False: The function calls db.add() and db.flush() but does
          NOT commit. The caller is responsible for calling db.commit() to
          persist all batched changes, or db.rollback() to discard them.
    """
    # Validate the IntelligenceSource exists
    source = validate_intelligence_source(db, source_id)

    # Validate polymorphic entity reference if provided
    if entity_type is not None or entity_id is not None:
        if entity_type is None or entity_id is None:
            raise EvidenceValidationError(
                "Both entity_type and entity_id must be provided together "
                "for polymorphic evidence references"
            )
        validate_evidence_entity(db, entity_type, entity_id)

    # Map legacy actor_id for backward compatibility
    if actor_id is not None and entity_type is None:
        entity_type = "actor"
        entity_id = actor_id

    ev = Evidence(
        actor_id=actor_id,
        source_id=source.id,
        entity_type=entity_type,
        entity_id=entity_id,
        evidence_type=evidence_type,
        content=content,
        reference=reference,
        external_record_id=external_record_id,
        source_url=source_url,
        source_published_at=source_published_at,
        source_description=source_description,
        source_confidence=source_confidence,
        reliability=reliability,
        raw_payload=raw_payload,
    )

    db.add(ev)
    if commit:
        db.commit()
        db.refresh(ev)
    else:
        db.flush()
    return ev
