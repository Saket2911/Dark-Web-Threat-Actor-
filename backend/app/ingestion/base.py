"""Abstract base class for intelligence data ingestion adapters.

Provides a reusable foundation for external threat-intelligence integrations
such as MITRE ATT&CK, APTnotes, ThreatFox, and URLhaus.

All adapters inherit from BaseIngestionAdapter and implement the abstract
methods: fetch, parse, validate, normalize.

Transaction ownership: The caller (orchestration layer) owns the SQLAlchemy
session and is responsible for calling db.commit() or db.rollback(). The
adapter methods use commit=False when calling create_evidence() and
create_relationship(), allowing batch processing within a single transaction.
"""

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.entities import CollectionJob, IntelligenceSource
from app.services.evidence_validator import create_evidence
from app.services.relationship_validator import (
    create_relationship,
    validate_origin,
    validate_source_consistency,
)


class IngestionAdapterError(Exception):
    """Base exception for all ingestion adapter errors."""
    pass


class FetchError(IngestionAdapterError):
    """Raised when data retrieval from the external source fails."""
    pass


class ParseError(IngestionAdapterError):
    """Raised when parsing the fetched data fails."""
    pass


class ValidationError(IngestionAdapterError):
    """Raised when a record fails validation."""
    pass


class BaseIngestionAdapter(ABC):
    """Abstract base class for intelligence data ingestion adapters.

    Subclasses must implement:
        fetch()       - Retrieve raw data from the external source.
        parse()       - Convert raw data into normalized record dicts.
        validate()    - Check that a normalized record is valid.
        normalize()   - Transform a validated record into a canonical form.
        _persist_record() - Persist a normalized record to the database.

    The adapter uses a caller-provided SQLAlchemy session and does NOT
    commit transactions itself (commit=False is used for all persistence
    calls). The orchestration layer is responsible for committing or
    rolling back the transaction.

    Attributes:
        db: SQLAlchemy database session.
        source_name: Human-readable name of the intelligence source.
        source_type: Type of source (e.g., "stix_feed", "csv_import", "api_feed").
        reliability: Source reliability score (0.0 to 1.0).
        is_synthetic: Whether the source contains synthetic demonstration data.
        origin: Source origin category ("synthetic", "external", "manual").
        collection_job_id: ID of the CollectionJob tracking this import run.
        source_id: ID of the IntelligenceSource record, once created/resolved.
        _records_imported: Count of records successfully imported in this run.
        _errors: List of error messages encountered during import.
        logger: Logger instance for the adapter.
    """

    # Subclasses must override these class attributes
    source_name: str = ""
    source_type: str = ""
    reliability: float = 0.5
    is_synthetic: bool = False
    origin: str = "external"

    def __init__(self, db: Session, source_name: Optional[str] = None):
        """Initialize the adapter with a database session.

        Args:
            db: SQLAlchemy database session (caller-owned transaction).
            source_name: Optional override for the source name.
        """
        self.db = db
        self.source_name = source_name or self.source_name
        self.source_id: Optional[int] = None
        self.collection_job_id: Optional[int] = None
        self._records_imported = 0
        self._errors: List[str] = []
        self.logger = logging.getLogger(self.__class__.__name__)

        # Validate origin on initialization
        if self.source_name:
            validate_source_consistency(self.is_synthetic, self.origin)

    # ------------------------------------------------------------------
    # Abstract methods - subclasses must implement these
    # ------------------------------------------------------------------

    @abstractmethod
    def fetch(self) -> List[Dict[str, Any]]:
        """Retrieve raw data from the external intelligence source.

        Returns:
            A list of raw data records as dictionaries.

        Raises:
            FetchError: If the data cannot be retrieved.
        """
        raise NotImplementedError

    @abstractmethod
    def parse(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert raw fetched data into normalized record dictionaries.

        Args:
            raw_data: The raw data returned by fetch().

        Returns:
            A list of parsed record dictionaries.

        Raises:
            ParseError: If the data cannot be parsed.
        """
        raise NotImplementedError

    @abstractmethod
    def validate(self, record: Dict[str, Any]) -> bool:
        """Validate a single normalized record.

        Args:
            record: A normalized record dictionary.

        Returns:
            True if the record is valid, False otherwise.

        Raises:
            ValidationError: If the record is structurally invalid.
        """
        raise NotImplementedError

    @abstractmethod
    def normalize(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Transform a validated record into the canonical form.

        Args:
            record: A validated record dictionary.

        Returns:
            A normalized record dictionary ready for persistence.

        Raises:
            ValidationError: If the record cannot be normalized.
        """
        raise NotImplementedError

    @abstractmethod
    def _persist_record(self, normalized_record: Dict[str, Any]) -> None:
        """Persist a single normalized record to the database.

        Uses create_evidence() and/or create_relationship() with commit=False
        so the caller controls transaction boundaries.

        Args:
            normalized_record: A normalized record from normalize().
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete methods - shared behavior for all adapters
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        """Execute the full ingestion pipeline.

        Orchestrates: fetch -> parse -> validate -> normalize -> persist.
        Uses batch transaction semantics (commit=False) for all persistence
        calls; the caller is responsible for committing the transaction.

        Returns:
            A dictionary with import statistics:
                {
                    "source_name": str,
                    "source_type": str,
                    "records_fetched": int,
                    "records_parsed": int,
                    "records_validated": int,
                    "records_normalized": int,
                    "records_imported": int,
                    "errors": List[str],
                }
        """
        self.logger.info("Starting ingestion for source: %s", self.source_name)

        # Create or resolve the IntelligenceSource record
        self.source_id = self._create_or_get_source()

        # Create a collection job to track this import run
        self.collection_job_id = self._create_collection_job()

        try:
            # Step 1: Fetch
            raw_data = self.fetch()
            self.logger.info("Fetched %d raw records from %s", len(raw_data), self.source_name)

            # Step 2: Parse
            parsed = self.parse(raw_data)
            self.logger.info("Parsed %d records from %d raw", len(parsed), len(raw_data))

            # Step 3: Validate + Normalize + Persist (batch)
            validated_count = 0
            normalized_count = 0

            for record in parsed:
                if not self.validate(record):
                    self._errors.append(f"Validation failed for record: {record.get('external_record_id', 'unknown')}")
                    continue
                validated_count += 1

                try:
                    normalized = self.normalize(record)
                    normalized_count += 1
                except ValidationError as exc:
                    self._errors.append(f"Normalization failed: {exc}")
                    continue

                # Persist the normalized record (subclass implements _persist_record)
                self._persist_record(normalized)
                self._records_imported += 1

            # Step 4: Update collection job
            self._update_collection_job(
                status="completed",
                records_imported=self._records_imported,
            )

            self.logger.info(
                "Import complete for %s: %d/%d records imported",
                self.source_name, self._records_imported, len(raw_data),
            )

            return {
                "source_name": self.source_name,
                "source_type": self.source_type,
                "records_fetched": len(raw_data),
                "records_parsed": len(parsed),
                "records_validated": validated_count,
                "records_normalized": normalized_count,
                "records_imported": self._records_imported,
                "errors": self._errors,
            }

        except Exception as exc:
            self.logger.exception("Ingestion failed for %s: %s", self.source_name, exc)
            self._errors.append(str(exc))
            self._update_collection_job(
                status="failed",
                records_imported=self._records_imported,
            )
            return {
                "source_name": self.source_name,
                "source_type": self.source_type,
                "records_fetched": 0,
                "records_parsed": 0,
                "records_validated": 0,
                "records_normalized": 0,
                "records_imported": self._records_imported,
                "errors": self._errors,
            }

    # ------------------------------------------------------------------
    # Source and job management
    # ------------------------------------------------------------------

    def _create_or_get_source(self) -> int:
        """Create or resolve the IntelligenceSource record for this adapter.

        Returns:
            The IntelligenceSource database ID.
        """
        src = (
            self.db.query(IntelligenceSource)
            .filter(IntelligenceSource.name == self.source_name)
            .first()
        )
        if src is None:
            src = IntelligenceSource(
                name=self.source_name,
                source_type=self.source_type,
                reliability=self.reliability,
                is_synthetic=self.is_synthetic,
                origin=self.origin,
                url=getattr(self, "stix_url", None),
            )
            # Enforce origin/is_synthetic consistency
            validate_source_consistency(self.is_synthetic, self.origin)
            self.db.add(src)
            self.db.flush()
            self.logger.info("Created intelligence source: %s (id=%d)", self.source_name, src.id)
        return src.id

    def _create_collection_job(self) -> int:
        """Create a CollectionJob record to track this import run.

        Returns:
            The CollectionJob database ID.
        """
        job = CollectionJob(
            source_name=self.source_name,
            source_key=getattr(self, "source_key", None),
            source_url=getattr(self, "stix_url", None),
            status="running",
            records_imported=0,
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(job)
        self.db.flush()
        self.logger.info("Created collection job: %s (id=%d)", self.source_name, job.id)
        return job.id

    def _update_collection_job(self, status: str, records_imported: int) -> None:
        """Update the CollectionJob record with import results.

        Args:
            status: Job status ("running", "completed", "failed").
            records_imported: Number of records successfully imported.
        """
        if self.collection_job_id is None:
            return
        job = (
            self.db.query(CollectionJob)
            .filter(CollectionJob.id == self.collection_job_id)
            .first()
        )
        if job is not None:
            job.status = status
            job.records_imported = records_imported
            job.finished_at = datetime.now(timezone.utc)
            self.db.flush()

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def log_error(self, message: str, record: Optional[Dict[str, Any]] = None) -> None:
        """Log an error and record it for the import summary.

        Args:
            message: Human-readable error message.
            record: Optional record dictionary that caused the error.
        """
        record_id = record.get("external_record_id", "unknown") if record else "unknown"
        full_message = f"{message} (record: {record_id})"
        self._errors.append(full_message)
        self.logger.error(full_message)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return current import statistics.

        Returns:
            A dictionary with import counts and errors.
        """
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "records_imported": self._records_imported,
            "errors": list(self._errors),
            "source_id": self.source_id,
            "collection_job_id": self.collection_job_id,
        }
