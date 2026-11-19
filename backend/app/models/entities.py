from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.core.time import utcnow
from app.database.session import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")
    created_at = Column(DateTime, default=utcnow)


class Actor(Base):
    __tablename__ = "actors"
    id = Column(Integer, primary_key=True)
    internal_id = Column(String(64), unique=True, nullable=False)
    primary_handle = Column(String(255), index=True)
    threat_category = Column(String(100))
    investigation_status = Column(String(50), default="open")
    last_observed = Column(DateTime)
    notes = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    external_id = Column(String(255), index=True)  # MITRE STIX ID or external source ID
    source_url = Column(String(500))  # Original source URL
    origin = Column(String(50), default="manual", index=True)  # synthetic, external, manual
    handles = relationship("Handle", back_populates="actor", cascade="all, delete-orphan")
    identifiers = relationship("Identifier", back_populates="actor", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="actor", cascade="all, delete-orphan")


class Handle(Base):
    __tablename__ = "handles"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), index=True)
    handle = Column(String(255), nullable=False, index=True)
    marketplace = Column(String(255))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    actor = relationship("Actor", back_populates="handles")


class Identifier(Base):
    __tablename__ = "identifiers"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), index=True)
    id_type = Column(String(50), index=True)  # pgp, wallet, domain, ip, email, username...
    value = Column(String(500), nullable=False, index=True)
    source = Column(String(255))
    external_id = Column(String(255))  # External source record ID
    origin = Column(String(50), default="manual")  # synthetic, external, manual
    reliability = Column(Float, default=0.5)
    actor = relationship("Actor", back_populates="identifiers")


class Marketplace(Base):
    __tablename__ = "marketplaces"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True)
    url = Column(String(500))


class InfrastructureIndicator(Base):
    __tablename__ = "infrastructure_indicators"
    id = Column(Integer, primary_key=True)
    indicator_type = Column(String(50), index=True)
    value = Column(String(500), index=True)
    metadata_json = Column(JSON)
    source = Column(String(255))
    external_id = Column(String(255))
    origin = Column(String(50), default="manual")
    reliability = Column(Float, default=0.5)
    last_observed = Column(DateTime)


class IntelligenceSource(Base):
    __tablename__ = "intelligence_sources"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), index=True)
    source_type = Column(String(100))
    reliability = Column(Float, default=0.5)
    url = Column(String(500))
    is_synthetic = Column(Boolean, default=False)
    origin = Column(String(50), default="manual")
    collected_at = Column(DateTime, default=utcnow)


class Campaign(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    external_id = Column(String(255), index=True)
    source_url = Column(String(500))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    origin = Column(String(50), default="manual")
    created_at = Column(DateTime, default=utcnow)


class Malware(Base):
    __tablename__ = "malware"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    malware_type = Column(String(100))  # ransomware, trojan, worm, etc.
    external_id = Column(String(255), index=True)
    source_url = Column(String(500))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    origin = Column(String(50), default="manual")
    created_at = Column(DateTime, default=utcnow)


class Tool(Base):
    __tablename__ = "tools"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    tool_type = Column(String(100))
    external_id = Column(String(255), index=True)
    source_url = Column(String(500))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    origin = Column(String(50), default="manual")
    created_at = Column(DateTime, default=utcnow)


class Tactic(Base):
    __tablename__ = "tactics"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    external_id = Column(String(100), unique=True)  # e.g. TA0001
    source_url = Column(String(500))
    origin = Column(String(50), default="manual")
    created_at = Column(DateTime, default=utcnow)


class Technique(Base):
    __tablename__ = "techniques"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    external_id = Column(String(100), unique=True)  # e.g. T1234
    tactic_id = Column(Integer, ForeignKey("tactics.id"), nullable=True)
    source_url = Column(String(500))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    origin = Column(String(50), default="manual")
    created_at = Column(DateTime, default=utcnow)
    tactic = relationship("Tactic")


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), nullable=True, index=True)
    source_id = Column(Integer, ForeignKey("intelligence_sources.id"), index=True)
    entity_type = Column(String(50), index=True)  # actor, campaign, ... indicator
    entity_id = Column(Integer, index=True)
    evidence_type = Column(String(100), index=True)
    content = Column(Text)
    reference = Column(String(500))
    external_record_id = Column(String(255))
    source_url = Column(String(500))
    source_published_at = Column(DateTime)
    source_description = Column(Text)
    source_confidence = Column(String(50))
    reliability = Column(Float, default=0.5)
    raw_payload = Column(JSON)
    collected_at = Column(DateTime, default=utcnow)
    created_at = Column(DateTime, default=utcnow)  # kept for backward compatibility
    __table_args__ = (Index("ix_evidence_entity", "entity_type", "entity_id"),)


class Relationship(Base):
    __tablename__ = "relationships"
    id = Column(Integer, primary_key=True)
    source_actor_id = Column(Integer, ForeignKey("actors.id"), nullable=True, index=True)
    target_actor_id = Column(Integer, ForeignKey("actors.id"), nullable=True, index=True)
    source_type = Column(String(50))
    source_entity_id = Column(Integer, index=True)
    target_type = Column(String(50))
    target_entity_id = Column(Integer, index=True)
    rel_type = Column(String(100), index=True)
    evidence = Column(Text)
    score = Column(Float, default=0.0)
    relationship_classification = Column(String(50))  # documented, inferred, unresolved
    confidence_level = Column(String(50))  # strong, limited, insufficient, conflicting, unverified
    source_confidence = Column(String(100))
    direct = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
    __table_args__ = (
        Index("ix_relationship_legacy_pair", "source_actor_id", "target_actor_id"),
        Index("ix_relationship_poly_pair", "source_type", "source_entity_id", "target_type", "target_entity_id"),
    )


class Investigation(Base):
    __tablename__ = "investigations"
    id = Column(Integer, primary_key=True)
    title = Column(String(255))
    status = Column(String(50), default="open")
    created_at = Column(DateTime, default=utcnow)
    notes = Column(Text)


class InvestigationEntity(Base):
    __tablename__ = "investigation_entities"
    id = Column(Integer, primary_key=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), index=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), index=True)
    added_at = Column(DateTime, default=utcnow)


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id = Column(Integer, primary_key=True)
    actor_a_id = Column(Integer, ForeignKey("actors.id"), index=True)
    actor_b_id = Column(Integer, ForeignKey("actors.id"), index=True)
    analysis_type = Column(String(100), index=True)
    score = Column(Float)
    details = Column(JSON)
    created_at = Column(DateTime, default=utcnow)


class AnalystReview(Base):
    __tablename__ = "analyst_reviews"
    id = Column(Integer, primary_key=True)
    relationship_id = Column(Integer, ForeignKey("relationships.id"), nullable=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=True, index=True)
    analyst = Column(String(100))
    decision = Column(String(50), index=True)
    notes = Column(Text)
    reviewed_at = Column(DateTime, default=utcnow)


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("actors.id"), index=True)
    event_type = Column(String(100), index=True)
    description = Column(Text)
    event_date = Column(DateTime, index=True)
    source = Column(String(255))
    actor = relationship("Actor", back_populates="timeline_events")


class CollectionJob(Base):
    __tablename__ = "collection_jobs"
    id = Column(Integer, primary_key=True)
    source_name = Column(String(255), index=True)
    status = Column(String(50), default="pending")
    records_imported = Column(Integer, default=0)
    started_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user = Column(String(100), index=True)
    action = Column(String(255), index=True)
    details = Column(Text)
    created_at = Column(DateTime, default=utcnow)
