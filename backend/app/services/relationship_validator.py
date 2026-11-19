"""Centralized validation service for polymorphic relationships.

Provides application-level validation for relationship creation since SQLite
does not support conditional/polymorphic foreign key constraints.

All API endpoints and ingestion adapters that create Relationship records
must call validate_relationship() before inserting.
"""

from typing import Any, Dict, List, Optional, Tuple

from app.database.session import SessionLocal
from app.models.entities import (
    Actor,
    Campaign,
    Evidence,
    InfrastructureIndicator,
    IntelligenceSource,
    Malware,
    Relationship,
    Tool,
    Tactic,
    Technique,
)

# Entity types supported for polymorphic relationships
SUPPORTED_ENTITY_TYPES: List[str] = [
    "actor",
    "campaign",
    "malware",
    "tool",
    "technique",
    "tactic",
    "indicator",
]

# Entity type -> model class mapping for existence checks
ENTITY_MODEL_MAP: Dict[str, Any] = {
    "actor": Actor,
    "campaign": Campaign,
    "malware": Malware,
    "tool": Tool,
    "technique": Technique,
    "tactic": Tactic,
    "indicator": InfrastructureIndicator,
}

# Valid relationship types (documented vocabulary)
VALID_RELATIONSHIP_TYPES: List[str] = [
    "USES",
    "ATTRIBUTED_TO",
    "ASSOCIATED_WITH",
    "OBSERVED_IN",
    "INDICATES",
    "DELIVERS",
    "RELATED_TO",
    "SHARES_PGP_KEY",
    "ASSOCIATED_WITH_WALLET",
    "ACTIVE_ON",
    "ASSOCIATED_WITH_DOMAIN",
    "ASSOCIATED_WITH_INFRASTRUCTURE",
    "SHARED_IDENTIFIER",
    "POTENTIALLY_SAME_PERSONA",
    "HAS_IDENTIFIER",
]


class RelationshipValidationError(ValueError):
    """Raised when a relationship fails validation."""


def validate_relationship(
    db: SessionLocal,
    source_type: str,
    source_entity_id: int,
    target_type: str,
    target_entity_id: int,
    rel_type: str,
    relationship_classification: Optional[str] = None,
    confidence_level: Optional[str] = None,
) -> None:
    """Validate a polymorphic relationship before creation.

    Args:
        db: SQLAlchemy database session.
        source_type: Entity type of the source.
        source_entity_id: ID of the source entity.
        target_type: Entity type of the target.
        target_entity_id: ID of the target entity.
        rel_type: Relationship type.
        relationship_classification: Optional classification.
        confidence_level: Optional confidence level.

    Raises:
        RelationshipValidationError: If any validation check fails.
    """
    # Validate entity types
    if source_type not in SUPPORTED_ENTITY_TYPES:
        raise RelationshipValidationError(
            f"Unsupported source entity type: '{source_type}'. "
            f"Supported types: {SUPPORTED_ENTITY_TYPES}"
        )
    if target_type not in SUPPORTED_ENTITY_TYPES:
        raise RelationshipValidationError(
            f"Unsupported target entity type: '{target_type}'. "
            f"Supported types: {SUPPORTED_ENTITY_TYPES}"
        )

    # Validate relationship type
    if rel_type not in VALID_RELATIONSHIP_TYPES:
        raise RelationshipValidationError(
            f"Invalid relationship type: '{rel_type}'. "
            f"Supported types: {VALID_RELATIONSHIP_TYPES}"
        )

    # Validate relationship classification if provided
    if relationship_classification is not None:
        valid_classifications = ["documented", "inferred", "unresolved"]
        if relationship_classification not in valid_classifications:
            raise RelationshipValidationError(
                f"Invalid relationship_classification: '{relationship_classification}'. "
                f"Valid values: {valid_classifications}"
            )

    # Validate confidence level if provided
    if confidence_level is not None:
        valid_confidence_levels = ["strong", "limited", "insufficient", "conflicting", "unverified"]
        if confidence_level not in valid_confidence_levels:
            raise RelationshipValidationError(
                f"Invalid confidence_level: '{confidence_level}'. "
                f"Valid values: {valid_confidence_levels}"
            )

    # Check self-reference (source and target are the same entity)
    if source_type == target_type and source_entity_id == target_entity_id:
        raise RelationshipValidationError(
            "Self-referencing relationships are not permitted "
            f"({source_type} id {source_entity_id} -> {target_type} id {target_entity_id})"
        )

    # Check that source entity exists
    source_model = ENTITY_MODEL_MAP[source_type]
    source_entity = db.query(source_model).filter(source_model.id == source_entity_id).first()
    if source_entity is None:
        raise RelationshipValidationError(
            f"Source entity not found: {source_type} id {source_entity_id}"
        )

    # Check that target entity exists
    target_model = ENTITY_MODEL_MAP[target_type]
    target_entity = db.query(target_model).filter(target_model.id == target_entity_id).first()
    if target_entity is None:
        raise RelationshipValidationError(
            f"Target entity not found: {target_type} id {target_entity_id}"
        )


def classify_existing_confidence(
    confidence: Optional[str],
    score: float,
    direct: bool,
    rel_type: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Map legacy confidence value to separated classification and confidence_level.

    Conservative mapping: does not fabricate confidence where none existed.
    Existing relationships with NULL confidence are mapped to 'unresolved'/'insufficient'
    unless the relationship type and direct flag provide clear evidence.

    Args:
        confidence: Legacy confidence string (may be None).
        score: Numeric similarity score.
        direct: Whether the relationship is a direct identifier match.
        rel_type: Relationship type.

    Returns:
        Tuple of (relationship_classification, confidence_level).
    """
    # If legacy confidence was explicitly set, preserve it as classification
    # and set confidence_level to unverified (we don't know the source strength)
    if confidence is not None:
        valid_classifications = ["documented", "inferred", "unresolved"]
        valid_confidence_levels = ["strong", "limited", "insufficient", "conflicting", "unverified"]
        if confidence in valid_classifications:
            return confidence, "unverified"
        if confidence in valid_confidence_levels:
            # Old confidence was actually a level, not classification
            return "unresolved", confidence

    # No legacy confidence: derive from relationship type and direct flag
    if rel_type == "SHARED_IDENTIFIER" and direct:
        # Same PGP key/wallet/domain genuinely shared by two accounts = documented fact
        return "documented", "strong"
    if rel_type == "POTENTIALLY_SAME_PERSONA" and not direct:
        # ML-inferred similarity = inferred, unverified
        return "inferred", "unverified"

    # Conservative default for unknown types
    return "unresolved", "insufficient"


def validate_origin(value: Optional[str]) -> str:
    """Validate and normalize an origin value.

    Args:
        value: Origin string to validate.

    Returns:
        Normalized origin value.

    Raises:
        ValueError: If the value is not one of the allowed origins.
    """
    valid_origins = ["synthetic", "external", "manual"]
    if value is None:
        return "manual"
    if value not in valid_origins:
        raise ValueError(
            f"Invalid origin: '{value}'. Valid values: {valid_origins}"
        )
    return value


def validate_source_consistency(is_synthetic: bool, origin: str) -> None:
    """Validate that origin and is_synthetic are consistent.

    Args:
        is_synthetic: Whether the source is synthetic.
        origin: The origin string (synthetic, external, manual).

    Raises:
        ValueError: If origin and is_synthetic are contradictory.
    """
    expected_synthetic = origin == "synthetic"
    if is_synthetic != expected_synthetic:
        raise ValueError(
            f"Inconsistent source attributes: is_synthetic={is_synthetic} "
            f"but origin='{origin}'. origin='synthetic' requires is_synthetic=True, "
            f"origin='external' or origin='manual' requires is_synthetic=False."
        )


def create_relationship(
    db: SessionLocal,
    source_type: str,
    source_entity_id: int,
    target_type: str,
    target_entity_id: int,
    rel_type: str,
    evidence: Optional[str] = None,
    score: float = 0.0,
    relationship_classification: Optional[str] = None,
    confidence_level: Optional[str] = None,
    source_confidence: Optional[str] = None,
    direct: bool = False,
    commit: bool = True,
) -> Relationship:
    """Create and persist a validated polymorphic relationship.

    This is the single creation entry point for all relationship records.
    Every caller (graph API, source adapters, investigation tools) must use
    this function so that validation rules are consistently applied.

    Args:
        db: SQLAlchemy database session.
        source_type: Entity type of the source (actor, campaign, malware, tool, technique, tactic, indicator).
        source_entity_id: ID of the source entity.
        target_type: Entity type of the target.
        target_entity_id: ID of the target entity.
        rel_type: Relationship type from VALID_RELATIONSHIP_TYPES.
        evidence: Optional evidence text describing the relationship basis.
        score: Numeric similarity/association score (0.0 to 1.0).
        relationship_classification: One of documented/inferred/unresolved.
        confidence_level: One of strong/limited/insufficient/conflicting/unverified.
        source_confidence: Source-provided confidence value, preserved independently.
        direct: Whether this is a direct identifier match (vs inferred).
        commit: Whether to commit the transaction immediately. When False,
            the record is added and flushed but not committed, allowing the
            caller to batch multiple creations in a single transaction.

    Returns:
        The persisted Relationship object.

    Raises:
        RelationshipValidationError: If validation fails.
        ValueError: If database persistence fails.

    Transaction ownership:
        - commit=True (default): The function commits after adding the record.
          The caller does not need to call db.commit().
        - commit=False: The function calls db.add() and db.flush() but does
          NOT commit. The caller is responsible for calling db.commit() to
          persist all batched changes, or db.rollback() to discard them.
    """
    # Run all validation checks first (uses the same db session)
    validate_relationship(
        db=db,
        source_type=source_type,
        source_entity_id=source_entity_id,
        target_type=target_type,
        target_entity_id=target_entity_id,
        rel_type=rel_type,
        relationship_classification=relationship_classification,
        confidence_level=confidence_level,
    )

    # Map legacy actor fields for backward compatibility
    source_actor_id = source_entity_id if source_type == "actor" else None
    target_actor_id = target_entity_id if target_type == "actor" else None

    rel = Relationship(
        source_actor_id=source_actor_id,
        target_actor_id=target_actor_id,
        source_type=source_type,
        source_entity_id=source_entity_id,
        target_type=target_type,
        target_entity_id=target_entity_id,
        rel_type=rel_type,
        evidence=evidence,
        score=score,
        relationship_classification=relationship_classification,
        confidence_level=confidence_level,
        source_confidence=source_confidence,
        direct=direct,
    )

    db.add(rel)
    if commit:
        db.commit()
        db.refresh(rel)
    else:
        db.flush()
    return rel
