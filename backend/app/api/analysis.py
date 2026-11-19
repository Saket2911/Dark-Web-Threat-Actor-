"""Analysis API: stylometry, behaviour, attribution, clustering and ML inference."""

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user, require_admin
from app.database.session import get_db
from app.ml.behavioural import behavioural_similarity
from app.ml.clustering import cluster_actors, cluster_behavioural
from app.ml.inference import (
    InferenceError,
    InvalidInferenceInputError,
    ModelNotTrainedError,
    infer,
    infer_batch,
    model_status,
    persist_inference,
    train_model,
)
from app.ml.scoring import DEFAULT_WEIGHTS, final_score
from app.ml.stylometry import stylometric_similarity
from app.models.entities import Actor, AnalysisResult, Evidence, Identifier, TimelineEvent
from app.schemas.schemas import (
    BatchInferenceRequest,
    BehaviouralRequest,
    ClusterRequest,
    InferenceRequest,
    ScoreRequest,
    StylometricRequest,
)
from app.services.audit import audit

router = APIRouter(prefix="/analysis", tags=["analysis"])

STRONG_IDENTIFIER_TYPES = {"pgp", "wallet", "email"}
INFRA_IDENTIFIER_TYPES = {"domain", "ip", "cert", "url", "infra"}


def _actor_or_404(db: Session, actor_id: int) -> Actor:
    actor = db.query(Actor).filter(Actor.id == actor_id).first()
    if not actor:
        raise HTTPException(404, f"Actor {actor_id} not found")
    return actor


def _actor_texts(db: Session, actor_id: int) -> List[str]:
    rows = (
        db.query(Evidence.content)
        .filter(
            Evidence.evidence_type == "text_sample",
            (Evidence.actor_id == actor_id)
            | ((Evidence.entity_type == "actor") & (Evidence.entity_id == actor_id)),
        )
        .all()
    )
    return [content for (content,) in rows if content]


def _actor_identifiers(db: Session, actor_id: int) -> Dict[str, set]:
    grouped: Dict[str, set] = {}
    for ident in db.query(Identifier).filter(Identifier.actor_id == actor_id).all():
        grouped.setdefault(ident.id_type, set()).add(str(ident.value))
    return grouped


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


@router.post("/stylometry")
def stylometry(body: StylometricRequest, user=Depends(get_current_user)):
    score, details = stylometric_similarity(body.text_a, body.text_b)
    return {
        "score": score,
        "details": details,
        "features_a": details.get("features_a"),
        "features_b": details.get("features_b"),
        "sufficient": details.get("sufficient", False),
        "warnings": details.get("warnings", []),
        "explanation": details.get("explanation"),
        "disclaimer": "Writing-style similarity supports analysis; it does not prove identity.",
    }


@router.post("/behavioural")
def behavioural(body: BehaviouralRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    a = _actor_or_404(db, body.actor_a_id)
    b = _actor_or_404(db, body.actor_b_id)
    if a.id == b.id:
        raise HTTPException(422, "Select two different actors")
    score, details = behavioural_similarity(a.id, b.id, db)
    return {
        "actor_a": {"id": a.id, "handle": a.primary_handle, "internal_id": a.internal_id},
        "actor_b": {"id": b.id, "handle": b.primary_handle, "internal_id": b.internal_id},
        "score": score,
        "details": details,
        "disclaimer": "Hourly activity similarity is analytical support, not proof of identity.",
    }


@router.post("/score")
def score(body: ScoreRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    actor_a = _actor_or_404(db, body.actor_a_id)
    actor_b = _actor_or_404(db, body.actor_b_id)
    if actor_a.id == actor_b.id:
        raise HTTPException(422, "Select two different actors")

    ids_a = _actor_identifiers(db, actor_a.id)
    ids_b = _actor_identifiers(db, actor_b.id)

    strong_a = {f"{t}:{v}" for t, values in ids_a.items() if t in STRONG_IDENTIFIER_TYPES for v in values}
    strong_b = {f"{t}:{v}" for t, values in ids_b.items() if t in STRONG_IDENTIFIER_TYPES for v in values}
    infra_a = {f"{t}:{v}" for t, values in ids_a.items() if t in INFRA_IDENTIFIER_TYPES for v in values}
    infra_b = {f"{t}:{v}" for t, values in ids_b.items() if t in INFRA_IDENTIFIER_TYPES for v in values}

    shared_strong = sorted(strong_a & strong_b)
    identifier_similarity = _jaccard(strong_a, strong_b)
    infrastructure_similarity = _jaccard(infra_a, infra_b)

    texts_a = _actor_texts(db, actor_a.id)
    texts_b = _actor_texts(db, actor_b.id)
    if texts_a and texts_b:
        styl_score, styl_details = stylometric_similarity(" ".join(texts_a), " ".join(texts_b))
        styl_available = bool(styl_details.get("sufficient"))
    else:
        styl_score, styl_details, styl_available = 0.0, {"reason": "missing text sample"}, False

    beh_score, beh_details = behavioural_similarity(actor_a.id, actor_b.id, db)
    beh_available = bool(beh_details.get("sufficient"))

    dates_a = {
        event.event_date.date().isoformat()
        for event in db.query(TimelineEvent).filter(TimelineEvent.actor_id == actor_a.id).all()
        if event.event_date
    }
    dates_b = {
        event.event_date.date().isoformat()
        for event in db.query(TimelineEvent).filter(TimelineEvent.actor_id == actor_b.id).all()
        if event.event_date
    }
    temporal_similarity = _jaccard(dates_a, dates_b)
    temporal_available = bool(dates_a) and bool(dates_b)

    availability = {
        "identifier": bool(strong_a) or bool(strong_b),
        "stylometric": styl_available,
        "behavioural": beh_available,
        "temporal": temporal_available,
        "infrastructure": bool(infra_a) or bool(infra_b),
    }

    weights = body.weights or get_settings().default_weights
    result = final_score(
        identifier_similarity,
        styl_score,
        beh_score,
        temporal_similarity,
        infrastructure_similarity,
        weights=weights,
        availability=availability,
        identifiers=shared_strong,
        details={
            "identifier": {
                "shared": shared_strong,
                "count_a": len(strong_a),
                "count_b": len(strong_b),
            },
            "stylometric": {
                "tfidf_cosine": styl_details.get("tfidf_cosine"),
                "samples_a": len(texts_a),
                "samples_b": len(texts_b),
                "warnings": styl_details.get("warnings", []),
            },
            "behavioural": {
                "cosine": beh_details.get("cosine"),
                "events_a": beh_details.get("activity_count_a"),
                "events_b": beh_details.get("activity_count_b"),
            },
            "temporal": {
                "shared_days": len(dates_a & dates_b),
                "days_a": len(dates_a),
                "days_b": len(dates_b),
            },
            "infrastructure": {
                "shared": sorted(infra_a & infra_b),
                "count_a": len(infra_a),
                "count_b": len(infra_b),
            },
        },
    )

    result["actor_a"] = {
        "id": actor_a.id,
        "handle": actor_a.primary_handle,
        "internal_id": actor_a.internal_id,
    }
    result["actor_b"] = {
        "id": actor_b.id,
        "handle": actor_b.primary_handle,
        "internal_id": actor_b.internal_id,
    }

    record = AnalysisResult(
        actor_a_id=actor_a.id,
        actor_b_id=actor_b.id,
        analysis_type="attribution",
        score=result["final"],
        details=result,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    result["analysis_id"] = record.id
    audit(db, user.username, "attribution_score", f"actors {actor_a.id}/{actor_b.id} score {result['final']}")
    return result


@router.post("/cluster")
def cluster(
    body: Optional[ClusterRequest] = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    request = body or ClusterRequest()
    if request.method not in ("kmeans", "dbscan"):
        raise HTTPException(422, "method must be 'kmeans' or 'dbscan'")
    if request.method == "dbscan":
        return cluster_behavioural(db, eps=request.eps, min_samples=request.min_samples)
    return cluster_actors(db, k=request.k)


@router.post("/cluster/behavioural")
def cluster_behav(
    eps: float = Query(0.5, gt=0.0, le=2.0),
    min_samples: int = Query(2, ge=1, le=50),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return cluster_behavioural(db, eps=eps, min_samples=min_samples)


@router.post("/cluster/kmeans")
def cluster_kmeans(
    k: Optional[int] = Query(None, ge=2, le=20),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return cluster_actors(db, k=k)


@router.get("/history")
def history(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), user=Depends(get_current_user)):
    rows = (
        db.query(AnalysisResult)
        .order_by(AnalysisResult.created_at.desc(), AnalysisResult.id.desc())
        .limit(limit)
        .all()
    )
    output = []
    for row in rows:
        actor_a = db.query(Actor).filter(Actor.id == row.actor_a_id).first()
        actor_b = db.query(Actor).filter(Actor.id == row.actor_b_id).first()
        output.append(
            {
                "id": row.id,
                "actor_a": row.actor_a_id,
                "actor_b": row.actor_b_id,
                "actor_a_handle": actor_a.primary_handle if actor_a else None,
                "actor_b_handle": actor_b.primary_handle if actor_b else None,
                "type": row.analysis_type,
                "score": row.score,
                "created": row.created_at,
                "category": (row.details or {}).get("category") if isinstance(row.details, dict) else None,
            }
        )
    return output


# ---------------------------------------------------------------------------
# Model registry / inference adapter
# ---------------------------------------------------------------------------
@router.get("/models")
def list_models(user=Depends(get_current_user)):
    settings = get_settings()
    return {
        "models": [
            {
                "name": "stylometric",
                "status": "available",
                "description": "TF-IDF (word 1-2 grams) cosine plus lexical feature closeness.",
                "deterministic": True,
            },
            {
                "name": "behavioural",
                "status": "available",
                "description": "Cosine similarity of normalised 24-hour activity distributions.",
                "deterministic": True,
            },
            {
                "name": "attribution",
                "status": "available",
                "description": "Explainable weighted evidence model with coverage reporting.",
                "weights": settings.default_weights,
            },
            {
                "name": "clustering",
                "status": "available",
                "description": "K-Means (structural features) and DBSCAN (hourly activity).",
            },
            {
                "name": "style-inference",
                "status": "trained" if model_status().get("trained") else "not_trained",
                "description": "Persistent TF-IDF centroid model for single and batch inference.",
            },
        ]
    }


@router.get("/models/status")
def get_model_status(user=Depends(get_current_user)):
    return model_status()


@router.post("/models/train")
def train(user=Depends(require_admin), db: Session = Depends(get_db)):
    try:
        manifest = train_model(db)
    except InferenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(db, user.username, "train_model", manifest.get("name", "style-inference"))
    return {"status": "trained", **manifest}


@router.post("/models/infer")
def model_infer(body: InferenceRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        result = infer(body.text, db)
    except ModelNotTrainedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except InvalidInferenceInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result["analysis_id"] = persist_inference(db, body.text, result)
    return result


@router.post("/models/batch")
def model_batch(body: BatchInferenceRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        result = infer_batch(body.texts, db)
    except ModelNotTrainedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except InvalidInferenceInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result


@router.get("/model/info")
def model_info(user=Depends(get_current_user)):
    settings = get_settings()
    return {
        "stylometric": ["tfidf_word_1_2gram", "lexical_features", "punctuation_profile"],
        "behavioural": ["hourly_activity_cosine"],
        "scoring": "weighted_evidence_with_coverage",
        "clustering": ["kmeans", "dbscan"],
        "inference": model_status(),
        "weights": settings.default_weights,
        "thresholds": {
            "strong": 0.75,
            "moderate": 0.5,
            "weak": 0.25,
            "minimum_coverage": 0.4,
            "inference_threshold": settings.inference_threshold,
        },
    }
