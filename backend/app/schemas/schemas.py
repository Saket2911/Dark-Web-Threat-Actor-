from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class LoginIn(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=200)
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def _valid_role(cls, value: str) -> str:
        if value not in ("admin", "analyst"):
            raise ValueError("role must be 'admin' or 'analyst'")
        return value

    @field_validator("username")
    @classmethod
    def _clean_username(cls, value: str) -> str:
        username = value.strip()
        if not username.replace("_", "").replace("-", "").replace(".", "").isalnum():
            raise ValueError("username may only contain letters, digits, '.', '-' and '_'")
        return username


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Actors and identifiers
# ---------------------------------------------------------------------------
class ActorCreate(BaseModel):
    primary_handle: Optional[str] = None
    threat_category: Optional[str] = None
    notes: Optional[str] = None
    investigation_status: Optional[str] = "open"


class ActorUpdate(BaseModel):
    primary_handle: Optional[str] = None
    threat_category: Optional[str] = None
    notes: Optional[str] = None
    investigation_status: Optional[str] = None


class ActorOut(BaseModel):
    id: int
    internal_id: str
    primary_handle: Optional[str]
    threat_category: Optional[str]
    investigation_status: str
    last_observed: Optional[datetime]
    notes: Optional[str]

    class Config:
        from_attributes = True


class IdentifierIn(BaseModel):
    id_type: str
    value: str
    source: Optional[str] = None
    reliability: float = Field(default=0.5, ge=0.0, le=1.0)


class IdentifierOut(BaseModel):
    id: int
    actor_id: int
    id_type: str
    value: str
    source: Optional[str] = None
    reliability: float = 0.5
    origin: Optional[str] = "manual"


class HandleIn(BaseModel):
    handle: str
    marketplace: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class EvidenceIn(BaseModel):
    evidence_type: str = "osint_report"
    content: Optional[str] = None
    reference: Optional[str] = None
    source: Optional[str] = None
    source_url: Optional[str] = None
    reliability: float = Field(default=0.5, ge=0.0, le=1.0)


class TimelineEventIn(BaseModel):
    event_type: str = "activity"
    description: str
    event_date: Optional[datetime] = None
    source: Optional[str] = None


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
class IngestRecord(BaseModel):
    handle: str
    marketplace: Optional[str] = None
    pgp: Optional[str] = None
    wallet: Optional[str] = None
    domain: Optional[str] = None
    infra: Optional[str] = None
    email: Optional[str] = None
    ip: Optional[str] = None
    username: Optional[str] = None
    text_sample: Optional[str] = None
    threat_category: Optional[str] = None
    source: str
    source_reliability: float = Field(default=0.5, ge=0.0, le=1.0)
    is_synthetic: bool = False
    activity_dates: Optional[List[str]] = None
    evidence_reference: Optional[str] = None


class FeedRequest(BaseModel):
    url: Optional[str] = None
    limit: int = Field(default=200, ge=1, le=2000)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
class StylometricRequest(BaseModel):
    text_a: str
    text_b: str


class BehaviouralRequest(BaseModel):
    actor_a_id: int
    actor_b_id: int


class ScoreRequest(BaseModel):
    actor_a_id: int
    actor_b_id: int
    weights: Optional[Dict[str, float]] = None


class ClusterRequest(BaseModel):
    method: str = "kmeans"  # kmeans | dbscan
    k: Optional[int] = None
    eps: float = 0.5
    min_samples: int = 2


class InferenceRequest(BaseModel):
    text: str


class BatchInferenceRequest(BaseModel):
    texts: List[str]

    @field_validator("texts")
    @classmethod
    def _non_empty(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("texts must contain at least one entry")
        if len(value) > 500:
            raise ValueError("batch size limit is 500")
        return value


# ---------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------
class InvestigationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    status: str = "open"
    notes: Optional[str] = None
    actor_ids: List[int] = []

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        if value not in ("open", "review", "closed"):
            raise ValueError("status must be open, review or closed")
        return value


class InvestigationUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=255)
    status: Optional[str] = None
    notes: Optional[str] = None


class InvestigationEntityIn(BaseModel):
    actor_id: int


class ReviewIn(BaseModel):
    relationship_id: Optional[int] = None
    decision: str
    notes: Optional[str] = None

    @field_validator("decision")
    @classmethod
    def _valid_decision(cls, value: str) -> str:
        if value not in ("pending", "approved", "rejected"):
            raise ValueError("decision must be pending, approved or rejected")
        return value


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------
class RelationshipIn(BaseModel):
    source_actor_id: int
    target_actor_id: int
    rel_type: str
    evidence: Optional[str] = None
    score: float = 0.0
    relationship_classification: Optional[str] = "unresolved"
    confidence_level: Optional[str] = "unverified"
