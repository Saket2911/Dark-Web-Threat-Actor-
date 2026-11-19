"""MITRE ATT&CK STIX 2.1 ingestion adapter.

Imports MITRE ATT&CK Enterprise STIX data into the CTI platform.

Extends BaseIngestionAdapter to fetch, validate, normalize, and persist
MITRE ATT&CK objects (intrusion-sets, campaigns, malware, tools, tactics,
techniques, and relationships) into the relational database.

Official source:
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/
enterprise-attack/enterprise-attack.json
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from stix2 import parse

from app.ingestion.base import (
    BaseIngestionAdapter,
    FetchError,
    IngestionAdapterError,
    ParseError,
    ValidationError,
)
from app.ingestion.deduplicator import Deduplicator
from app.ingestion.normalizer import (
    extract_technique_tactic_mapping,
    normalize_stix_bundle,
    normalize_stix_object,
    STIX_TYPE_MAP,
)
from app.ingestion.validator import validate_stix_object
from app.services.evidence_validator import create_evidence
from app.services.relationship_validator import (
    VALID_RELATIONSHIP_TYPES,
    create_relationship,
)
from app.models.entities import (
    Actor,
    Campaign,
    Malware,
    Tool,
    Tactic,
    Technique,
)

# Mapping from STIX relationship_type to internal rel_type
STIX_RELATIONSHIP_MAP: Dict[str, str] = {
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

# Default MITRE ATT&CK Enterprise STIX URL
MITRE_ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Relationship classification for MITRE-curated data
MITRE_CLASSIFICATION = "documented"
MITRE_CONFIDENCE_LEVEL = "strong"


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 datetime string to Python datetime object.

    Args:
        value: ISO 8601 datetime string (e.g., "2020-01-01T00:00:00Z").

    Returns:
        A datetime object, or None if the value is None or empty.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        # Handle Z suffix (UTC)
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


class MitreAttackAdapter(BaseIngestionAdapter):
    """MITRE ATT&CK Enterprise STIX 2.1 ingestion adapter.

    Fetches the Enterprise ATT&CK STIX bundle from the official MITRE
    repository, validates, normalizes, and persists all objects into the
    CTI platform.

    The adapter processes entities before relationships so that relationship
    targets can be resolved. Revoked and deprecated objects are imported
    with their status preserved in raw_payload.

    Attributes:
        source_name: "mitre-attack-enterprise"
        source_type: "stix_bundle"
        reliability: 0.9 (MITRE is authoritative)
        is_synthetic: False
        origin: "external"
        stix_url: The URL to fetch the STIX bundle from.
        batch_size: Number of objects to process per batch commit.
        bundle_version: The MITRE ATT&CK version detected from the bundle.
    """

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
    ):
        """Initialize the MITRE ATT&CK adapter.

        Args:
            db: SQLAlchemy database session.
            stix_url: URL to the Enterprise ATT&CK STIX JSON.
            batch_size: Number of objects per batch commit.
            source_name: Optional override for source name.
        """
        super().__init__(db=db, source_name=source_name)
        self.stix_url = stix_url
        self.batch_size = batch_size
        self.bundle_version: Optional[str] = None
        self._entity_id_map: Dict[str, int] = {}  # stix_id -> db_id
        self.deduplicator = Deduplicator(db)

    def fetch(self) -> List[Dict[str, Any]]:
        """Download the MITRE ATT&CK Enterprise STIX bundle.

        Returns:
            A list containing a single element: the parsed bundle dict.

        Raises:
            FetchError: If the download fails.
        """
        self.logger.info("Fetching MITRE ATT&CK bundle from %s", self.stix_url)
        try:
            response = requests.get(self.stix_url, timeout=60)
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            raise FetchError(
                f"Failed to fetch MITRE ATT&CK bundle: {exc}"
            ) from exc

        try:
            bundle = response.json()
        except ValueError as exc:
            raise ParseError(
                f"Failed to parse MITRE ATT&CK bundle as JSON: {exc}"
            ) from exc

        # Extract bundle metadata
        self.bundle_version = bundle.get("spec_version", "")

        # STIX bundles wrap objects in an "objects" list
        objects = bundle.get("objects", []) or []
        self.logger.info(
            "Fetched MITRE ATT&CK bundle with %d objects", len(objects)
        )

        # Return as a list with one element (the bundle dict) to match
        # the base adapter's fetch() contract
        return [bundle]

    def parse(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse STIX bundle objects using stix2.

        Args:
            raw_data: List containing the bundle dict.

        Returns:
            List of parsed STIX objects as dicts.

        Raises:
            ParseError: If parsing fails.
        """
        if not raw_data:
            raise ParseError("No raw data to parse")

        bundle = raw_data[0]
        objects = bundle.get("objects", []) or []

        parsed_objects = []
        for obj in objects:
            try:
                parsed = parse(obj, version="2.1")
                if hasattr(parsed, "to_dict"):
                    parsed_dict = parsed.to_dict()
                else:
                    parsed_dict = dict(obj)
                parsed_objects.append(parsed_dict)
            except Exception as exc:
                self.logger.warning(
                    "Failed to parse STIX object %s: %s",
                    obj.get("id", "unknown"),
                    exc,
                )
                parsed_objects.append(obj)

        self.logger.info("Parsed %d STIX objects", len(parsed_objects))
        return parsed_objects

    def validate(self, record: Dict[str, Any]) -> bool:
        """Validate a normalized STIX object record.

        The base adapter passes normalized dictionaries to this method, while
        the raw bundle uses ``type``/``id``. Both shapes are accepted.

        Args:
            record: A normalized or raw STIX record dict.

        Returns:
            True if valid, False otherwise.
        """
        candidate = record
        if "type" not in candidate and candidate.get("stix_type"):
            candidate = {
                "type": candidate.get("stix_type"),
                "id": candidate.get("stix_id") or candidate.get("external_id"),
                "name": candidate.get("name"),
                "description": candidate.get("description"),
                "external_references": candidate.get("external_references") or [],
                "kill_chain_phases": candidate.get("kill_chain_phases") or [],
                "relationship_type": (candidate.get("raw_payload") or {}).get("relationship_type"),
                "source_ref": (candidate.get("raw_payload") or {}).get("source_ref"),
                "target_ref": (candidate.get("raw_payload") or {}).get("target_ref"),
            }
        try:
            validate_stix_object(candidate)
            return True
        except ValidationError as exc:
            self.logger.debug("Validation failed: %s", exc)
            return False

    def normalize(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a validated STIX object record.

        Args:
            record: A validated record dict.

        Returns:
            A normalized record dict ready for persistence.
        """
        return normalize_stix_object(record)

    def _persist_record(self, normalized_record: Dict[str, Any]) -> None:
        """Persist a normalized STIX object to the database.

        Creates or updates the entity record and creates an Evidence record
        linking it to the MITRE ATT&CK IntelligenceSource.

        Args:
            normalized_record: A normalized record from normalize().
        """
        model_type = normalized_record.get("model_type", "unknown")
        external_id = normalized_record.get("external_id", "")

        # Build defaults for entity creation/update
        # Map model-specific name field: Actor uses primary_handle, others use name
        # Map model-specific description field: Actor uses notes, others use description
        name_field = "primary_handle" if model_type == "Actor" else "name"
        desc_field = "notes" if model_type == "Actor" else "description"

        # Extract source_url from external_references in raw_payload
        raw_payload = normalized_record.get("raw_payload", {}) or {}
        external_refs = raw_payload.get("external_references", []) or []
        source_url = external_refs[0].get("url", "") if external_refs else ""

        # Parse timestamp strings to datetime objects
        created_str = normalized_record.get("created")
        modified_str = normalized_record.get("modified")
        created_dt = _parse_iso_datetime(created_str) if created_str else None
        modified_dt = _parse_iso_datetime(modified_str) if modified_str else None

        defaults = {
            name_field: normalized_record.get("name", ""),
            desc_field: normalized_record.get("description", ""),
            "source_url": source_url,
            "origin": self.origin,
        }

        # Add timestamp fields only for models that actually define them.
        # (Tactic has no first_seen/last_seen columns.)
        if model_type == "Actor":
            defaults["last_observed"] = modified_dt
            # Actor.internal_id is required - derive it from the STIX id
            defaults["internal_id"] = external_id
        elif model_type in ("Campaign", "Malware", "Tool", "Technique"):
            defaults["first_seen"] = created_dt
            defaults["last_seen"] = modified_dt

        # Create or update the entity using the deduplicator
        entity, created = self.deduplicator.find_or_create_entity(
            model_class=self._get_model_class(model_type),
            external_id=external_id,
            defaults=defaults,
        )

        # Create Evidence record linking the source to this entity
        raw_payload = normalized_record.get("raw_payload", {}) or {}
        external_refs = raw_payload.get("external_references", []) or []
        source_url = external_refs[0].get("url", "") if external_refs else ""

        created_str = normalized_record.get("created")
        created_dt = _parse_iso_datetime(created_str) if created_str else None

        create_evidence(
            db=self.db,
            source_id=self.source_id,
            entity_type=model_type.lower(),
            entity_id=entity.id,
            evidence_type="stix_import",
            content=normalized_record.get("description", ""),
            reference=source_url,
            external_record_id=external_id,
            source_url=self.stix_url,
            source_published_at=created_dt,
            source_description=normalized_record.get("description", ""),
            source_confidence=None,
            reliability=self.reliability,
            raw_payload=raw_payload,
            commit=False,
        )

        # Track the entity ID mapping for relationship resolution
        self._entity_id_map[external_id] = entity.id

    def _get_model_class(self, model_type: str) -> Any:
        """Get the SQLAlchemy model class for a normalized model type.

        Args:
            model_type: The model type string (Actor, Campaign, etc.).

        Returns:
            The SQLAlchemy model class.

        Raises:
            ValueError: If the model type is not supported.
        """
        model_map = {
            "Actor": Actor,
            "Campaign": Campaign,
            "Malware": Malware,
            "Tool": Tool,
            "Tactic": Tactic,
            "Technique": Technique,
        }
        model_class = model_map.get(model_type)
        if model_class is None:
            raise ValueError(f"Unsupported model type: {model_type}")
        return model_class

    def run(self) -> Dict[str, Any]:
        """Execute the full MITRE ATT&CK ingestion pipeline.

        Overrides BaseIngestionAdapter.run() to handle relationship
        processing after all entities have been persisted.

        Returns:
            Import statistics dictionary.
        """
        self.logger.info("Starting MITRE ATT&CK ingestion from %s", self.stix_url)

        # Step 0: Create/resolve IntelligenceSource and CollectionJob
        self.source_id = self._create_or_get_source()
        self.collection_job_id = self._create_collection_job()

        # Step 1: Fetch
        try:
            raw_data = self.fetch()
        except Exception as exc:
            self.logger.exception("Failed to fetch from %s: %s", self.stix_url, exc)
            self._errors.append(str(exc))
            self._update_collection_job(
                status="failed",
                records_imported=0,
            )
            return {
                "source_name": self.source_name,
                "source_type": self.source_type,
                "records_fetched": 0,
                "records_parsed": 0,
                "records_validated": 0,
                "records_normalized": 0,
                "records_imported": 0,
                "errors": self._errors,
                "relationships_created": 0,
                "relationships_skipped": 0,
                "bundle_version": self.bundle_version,
            }
        self.logger.info("Fetched %d raw records from %s", len(raw_data), self.source_name)

        # Step 2: Parse
        parsed = self.parse(raw_data)
        self.logger.info("Parsed %d STIX objects", len(parsed))

        # Step 3: Build bundle for normalization from valid objects
        bundle_data = {"objects": parsed, "type": "bundle", "id": self.stix_url}

        # Step 4: Normalize valid objects
        normalized = normalize_stix_bundle(bundle_data)

        # Step 5: Process entities first (actors, campaigns, malware, tools,
        # tactics, techniques)
        entity_types = [
            "actors", "campaigns", "malware", "tools", "tactics", "techniques"
        ]
        for entity_type in entity_types:
            entities = normalized.get(entity_type, [])
            self.logger.info(
                "Processing %d %s entities", len(entities), entity_type
            )
            for norm_obj in entities:
                # Persist (already validated and normalized)
                self._persist_record(norm_obj)
                self._records_imported += 1

        # Commit entities before processing relationships
        self.db.commit()
        self.logger.info("Committed %d entities", self._records_imported)

        # Step 6: Process relationships
        relationships = normalized.get("relationships", [])
        self.logger.info("Processing %d relationships", len(relationships))

        # Build the set of all known STIX IDs for relationship validation
        all_stix_ids = set()
        for entity_type in entity_types:
            for obj in normalized.get(entity_type, []):
                all_stix_ids.add(obj.get("stix_id", ""))
        # Also include relationship IDs themselves
        for rel in relationships:
            all_stix_ids.add(rel.get("stix_id", ""))

        relationships_created = 0
        relationships_skipped = 0

        for norm_rel in relationships:
            source_ref = norm_rel.get("raw_payload", {}).get("source_ref", "")
            target_ref = norm_rel.get("raw_payload", {}).get("target_ref", "")
            rel_type_stix = norm_rel.get("raw_payload", {}).get("relationship_type", "")

            # Validate source and target exist in our entity map
            source_actor_id = self._entity_id_map.get(source_ref)
            target_actor_id = self._entity_id_map.get(target_ref)

            if source_actor_id is None:
                self._errors.append(
                    f"Relationship {norm_rel.get('stix_id', 'unknown')}: "
                    f"source_actor_id '{source_ref}' not found in imported entities"
                )
                relationships_skipped += 1
                continue
            if target_actor_id is None:
                self._errors.append(
                    f"Relationship {norm_rel.get('stix_id', 'unknown')}: "
                    f"target_actor_id '{target_ref}' not found in imported entities"
                )
                relationships_skipped += 1
                continue

            # Map STIX relationship type to internal rel_type
            internal_rel_type = STIX_RELATIONSHIP_MAP.get(
                rel_type_stix, "RELATED_TO"
            )

            # Build evidence text explaining the original STIX relationship
            evidence_text = (
                f"MITRE ATT&CK STIX relationship '{rel_type_stix}' "
                f"({source_ref} -> {target_ref}), imported from {self.source_name}."
            )

            # Create or update relationship
            rel, created = self.deduplicator.find_or_create_relationship(
                source_type=self._get_source_type_from_id(source_ref),
                source_entity_id=source_actor_id,
                target_type=self._get_source_type_from_id(target_ref),
                target_entity_id=target_actor_id,
                rel_type=internal_rel_type,
                defaults={
                    "evidence": evidence_text,
                    "score": 0.8,
                    "relationship_classification": MITRE_CLASSIFICATION,
                    "confidence_level": MITRE_CONFIDENCE_LEVEL,
                    "direct": True,
                },
            )

            if created:
                relationships_created += 1
            else:
                relationships_skipped += 1

        # Commit relationships
        self.db.commit()

        # Update collection job (entity count; relationship counts are reported
        # separately so the same unit is never counted twice)
        self._update_collection_job(
            status="completed",
            records_imported=self._records_imported,
        )

        self.logger.info(
            "MITRE ATT&CK import complete: %d entities, %d relationships created, "
            "%d skipped",
            self._records_imported, relationships_created, relationships_skipped,
        )

        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "records_fetched": len(raw_data),
            "records_parsed": len(parsed),
            "records_validated": len(parsed),
            "records_normalized": len(normalized.get("actors", []))
            + len(normalized.get("campaigns", []))
            + len(normalized.get("malware", []))
            + len(normalized.get("tools", []))
            + len(normalized.get("tactics", []))
            + len(normalized.get("techniques", [])),
            "records_imported": self._records_imported,
            "errors": self._errors,
            "relationships_created": relationships_created,
            "relationships_skipped": relationships_skipped,
            "bundle_version": self.bundle_version,
        }

    def _get_source_type_from_id(self, stix_id: str) -> str:
        """Determine the entity type from a STIX ID prefix.

        Args:
            stix_id: STIX identifier string.

        Returns:
            The entity type string (actor, campaign, malware, tool, technique, tactic).
        """
        if stix_id.startswith("intrusion-set--"):
            return "actor"
        elif stix_id.startswith("campaign--"):
            return "campaign"
        elif stix_id.startswith("malware--"):
            return "malware"
        elif stix_id.startswith("tool--"):
            return "tool"
        elif stix_id.startswith("x-mitre-tactic--"):
            return "tactic"
        elif stix_id.startswith("attack-pattern--"):
            return "technique"
        elif stix_id.startswith("relationship--"):
            return "relationship"
        return "actor"
