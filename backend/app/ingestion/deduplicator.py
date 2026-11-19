"""Deduplication module for STIX 2.1 intelligence ingestion.

Provides entity deduplication based on external_id and relationship
deduplication based on source_type, source_entity_id, target_type,
target_entity_id, and rel_type.

Supports idempotent re-imports without creating duplicate records.
"""

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.entities import (
    Actor,
    Campaign,
    IntelligenceSource,
    Malware,
    Relationship,
    Technique,
    Tactic,
    Tool,
)

# Entity type -> model class mapping for dedup lookups
ENTITY_MODEL_MAP: Dict[str, Any] = {
    "actor": Actor,
    "campaign": Campaign,
    "malware": Malware,
    "tool": Tool,
    "technique": Technique,
    "tactic": Tactic,
}


class DuplicateError(Exception):
    """Raised when a duplicate record is detected and cannot be merged."""
    pass


class Deduplicator:
    """Handles deduplication of entities and relationships during ingestion.

    Uses external_id as the primary identity key for entities and
    (source_type, source_entity_id, target_type, target_entity_id, rel_type)
    for relationships.

    Supports upsert semantics: existing records are updated with new data
    when they already exist, preserving the original internal_id.
    """

    def __init__(self, db: Session):
        """Initialize the deduplicator with a database session.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db
        self._entity_cache: Dict[str, Dict[str, Any]] = {}
        self._relationship_cache: Dict[str, Any] = {}
        self._created_count = 0
        self._updated_count = 0
        self._skipped_count = 0

    # ------------------------------------------------------------------
    # Entity deduplication
    # ------------------------------------------------------------------

    def find_or_create_entity(
        self,
        model_class: Any,
        external_id: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find an existing entity by external_id or create a new one.

        Args:
            model_class: The SQLAlchemy model class.
            external_id: The external identifier (STIX ID).
            defaults: Default field values for creation if not found.

        Returns:
            Tuple of (entity_instance, created_bool).
            created_bool is True if a new record was created, False if existing.
        """
        # Query by external_id
        existing = (
            self.db.query(model_class)
            .filter(model_class.external_id == external_id)
            .first()
        )

        if existing is not None:
            # Update existing record with new defaults, but don't overwrite
            # manually set fields that might be more recent
            updated = False
            for field, value in defaults.items():
                if value is not None and getattr(existing, field, None) in (None, ""):
                    setattr(existing, field, value)
                    updated = True

            if updated:
                self._updated_count += 1
            else:
                self._skipped_count += 1

            return existing, False

        # Create new entity
        entity = model_class(external_id=external_id, **defaults)
        self.db.add(entity)
        self.db.flush()
        self._created_count += 1
        return entity, True

    def find_entity(
        self,
        model_class: Any,
        external_id: str,
    ) -> Optional[Any]:
        """Find an existing entity by external_id without creating.

        Args:
            model_class: The SQLAlchemy model class.
            external_id: The external identifier.

        Returns:
            The existing entity or None if not found.
        """
        return (
            self.db.query(model_class)
            .filter(model_class.external_id == external_id)
            .first()
        )

    def find_or_create_actor(
        self,
        external_id: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find or create an Actor entity."""
        return self.find_or_create_entity(Actor, external_id, defaults)

    def find_or_create_campaign(
        self,
        external_id: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find or create a Campaign entity."""
        return self.find_or_create_entity(Campaign, external_id, defaults)

    def find_or_create_malware(
        self,
        external_id: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find or create a Malware entity."""
        return self.find_or_create_entity(Malware, external_id, defaults)

    def find_or_create_tool(
        self,
        external_id: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find or create a Tool entity."""
        return self.find_or_create_entity(Tool, external_id, defaults)

    def find_or_create_tactic(
        self,
        external_id: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find or create a Tactic entity.

        Tactic.external_id has a unique constraint, so upsert behavior
        is handled by the find_or_create_entity method.
        """
        return self.find_or_create_entity(Tactic, external_id, defaults)

    def find_or_create_technique(
        self,
        external_id: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find or create a Technique entity.

        Technique.external_id has a unique constraint, so upsert behavior
        is handled by the find_or_create_entity method.
        """
        return self.find_or_create_entity(Technique, external_id, defaults)

    # ------------------------------------------------------------------
    # Relationship deduplication
    # ------------------------------------------------------------------

    def find_or_create_relationship(
        self,
        source_type: str,
        source_entity_id: int,
        target_type: str,
        target_entity_id: int,
        rel_type: str,
        defaults: Dict[str, Any],
    ) -> Tuple[Any, bool]:
        """Find an existing relationship or create a new one.

        Deduplication is based on:
            source_type, source_entity_id, target_type, target_entity_id, rel_type

        Args:
            source_type: Source entity type.
            source_entity_id: Source entity database ID.
            target_type: Target entity type.
            target_entity_id: Target entity database ID.
            rel_type: Relationship type string.
            defaults: Default field values for creation.

        Returns:
            Tuple of (relationship_instance, created_bool).
        """
        existing = (
            self.db.query(Relationship)
            .filter(
                Relationship.source_type == source_type,
                Relationship.source_entity_id == source_entity_id,
                Relationship.target_type == target_type,
                Relationship.target_entity_id == target_entity_id,
                Relationship.rel_type == rel_type,
            )
            .first()
        )

        if existing is not None:
            # Update existing relationship with new values
            updated = False
            for field, value in defaults.items():
                if value is not None:
                    current = getattr(existing, field, None)
                    if current in (None, "") and value not in (None, ""):
                        setattr(existing, field, value)
                        updated = True

            if updated:
                self._updated_count += 1
            else:
                self._skipped_count += 1

            return existing, False

        # Create new relationship
        rel = Relationship(
            source_type=source_type,
            source_entity_id=source_entity_id,
            target_type=target_type,
            target_entity_id=target_entity_id,
            rel_type=rel_type,
            **defaults,
        )
        self.db.add(rel)
        self.db.flush()
        self._created_count += 1
        return rel, True

    def find_relationship(
        self,
        source_type: str,
        source_entity_id: int,
        target_type: str,
        target_entity_id: int,
        rel_type: str,
    ) -> Optional[Any]:
        """Find an existing relationship without creating.

        Args:
            source_type: Source entity type.
            source_entity_id: Source entity database ID.
            target_type: Target entity type.
            target_entity_id: Target entity database ID.
            rel_type: Relationship type string.

        Returns:
            The existing Relationship or None.
        """
        return (
            self.db.query(Relationship)
            .filter(
                Relationship.source_type == source_type,
                Relationship.source_entity_id == source_entity_id,
                Relationship.target_type == target_type,
                Relationship.target_entity_id == target_entity_id,
                Relationship.rel_type == rel_type,
            )
            .first()
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """Return deduplication statistics.

        Returns:
            Dict with keys: created_count, updated_count, skipped_count,
            total_processed.
        """
        return {
            "created_count": self._created_count,
            "updated_count": self._updated_count,
            "skipped_count": self._skipped_count,
            "total_processed": self._created_count
            + self._updated_count
            + self._skipped_count,
        }
