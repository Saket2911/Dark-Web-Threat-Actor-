"""Settings and system status API.

Only genuinely implemented configuration is exposed. Secrets (JWT key, feed
Auth-Key) are never returned: only whether they are configured.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, require_admin
from app.database.session import get_db
from app.ingestion.feeds import get_feed_status
from app.ml.inference import model_status
from app.models.entities import (
    Actor,
    Identifier,
    IntelligenceSource,
    Relationship,
    TimelineEvent,
)
from app.services.relationship_engine import relationship_statistics

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/sources")
def sources(db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = db.query(IntelligenceSource).order_by(IntelligenceSource.id).all()
    usage = {
        row[0]: row[1]
        for row in db.query(IntelligenceSource.id, func.count(IntelligenceSource.id)).group_by(IntelligenceSource.id).all()
    }
    return [
        {
            "id": source.id,
            "name": source.name,
            "type": source.source_type,
            "reliability": source.reliability,
            "is_synthetic": source.is_synthetic,
            "origin": source.origin,
            "url": source.url,
            "collected_at": source.collected_at,
            "last_success_at": source.last_success_at,
            "last_error": source.last_error,
            "last_error_at": source.last_error_at,
            "last_object_count": source.last_object_count,
        }
        for source in rows
    ]


@router.get("/weights/default")
def default_weights(user=Depends(get_current_user)):
    settings = get_settings()
    return settings.default_weights


@router.get("/thresholds")
def thresholds(user=Depends(get_current_user)):
    settings = get_settings()
    return {
        "strong": 0.75,
        "moderate": 0.5,
        "weak": 0.25,
        "minimum_coverage": 0.4,
        "inference_threshold": settings.inference_threshold,
        "min_style_words": settings.min_style_words,
        "min_behaviour_events": settings.min_behaviour_events,
        "upload_limit_bytes": settings.max_upload_bytes,
    }


@router.get("/models")
def models(user=Depends(get_current_user)):
    settings = get_settings()
    return {
        "deterministic": [
            {
                "name": "TF-IDF stylometry",
                "type": "nlp",
                "detail": "Word 1-2 gram TF-IDF cosine + lexical/punctuation closeness.",
                "available": True,
            },
            {
                "name": "Hourly behavioural cosine",
                "type": "behavioural",
                "detail": "Normalised 24-bin activity distributions compared with cosine similarity.",
                "available": True,
            },
            {
                "name": "Weighted attribution model",
                "type": "scoring",
                "detail": "Explainable weighted evidence with coverage and contribution reporting.",
                "available": True,
                "weights": settings.default_weights,
            },
            {
                "name": "K-Means clustering",
                "type": "clustering",
                "detail": "Structural features (identifiers, handles, marketplaces, events, category).",
                "available": True,
            },
            {
                "name": "DBSCAN clustering",
                "type": "clustering",
                "detail": "Density clustering over hourly activity vectors, cosine metric.",
                "available": True,
            },
        ],
        "persisted": model_status(),
        "note": "No external model service is used. All models run locally and deterministically.",
    }


@router.get("/feeds")
def feeds(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return get_feed_status(db)


@router.get("/feeds/status")
def feeds_status(db: Session = Depends(get_db), user=Depends(get_current_user)):
    return get_feed_status(db)


@router.get("/system")
def system(db: Session = Depends(get_db), user=Depends(get_current_user)):
    settings = get_settings()
    db_path = settings.database_path
    return {
        "app_name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "database": {
            "driver": "sqlite" if settings.sqlalchemy_url.startswith("sqlite") else "other",
            "path": str(db_path) if db_path else settings.sqlalchemy_url.split("@")[-1],
            "exists": bool(db_path and db_path.exists()),
            "writable": bool(db_path and db_path.exists() and db_path.stat().st_mode),
            "actors": db.query(Actor).count(),
            "identifiers": db.query(Identifier).count(),
            "relationships": db.query(Relationship).count(),
            "timeline_events": db.query(TimelineEvent).count(),
        },
        "relationships": relationship_statistics(db),
        "uploads": {"max_bytes": settings.max_upload_bytes},
        "auth": {
            "scheme": "JWT bearer (HS256)",
            "password_hashing": "PBKDF2-SHA256",
            "token_ttl_minutes": settings.access_token_expire_minutes,
            "secret_key_configured": bool(settings.secret_key and settings.secret_key != "change-me"),
        },
    }


@router.get("/health")
def health(db: Session = Depends(get_db)):
    settings = get_settings()
    try:
        db.query(Actor.id).first()
        db_ok = True
        db_error = None
    except Exception as exc:  # pragma: no cover
        db_ok = False
        db_error = str(exc)
    return {
        "status": "ok" if db_ok else "degraded",
        "db": "sqlite" if settings.sqlalchemy_url.startswith("sqlite") else "other",
        "db_ok": db_ok,
        "db_error": db_error,
        "graph": "networkx",
        "ml": "available",
        "version": settings.app_version,
    }
