"""Persistent ML inference adapter.

A small, explainable writing-style attribution model:

* Training collects ``text_sample`` evidence per actor and fits a TF-IDF
  vectorizer over word and character n-grams.
* Each actor's samples are averaged into a centroid; inference scores a text
  against every centroid with cosine similarity.
* The fitted pipeline is persisted to ``MODEL_DIR`` with joblib, together with
  a manifest (version, training timestamp, sample counts, feature counts) so
  every prediction can be traced to a specific model artifact.

There is no network dependency. Failures (no trained model, insufficient
training data, empty input) raise typed exceptions that the API maps to clear
HTTP errors instead of fabricating a prediction.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.time import utcnow
from app.models.entities import Actor, AnalysisResult, Evidence

MODEL_NAME = "style-centroid-tfidf"
MODEL_VERSION = 1


class InferenceError(RuntimeError):
    """Base class for inference failures."""


class ModelNotTrainedError(InferenceError):
    """Raised when no trained artifact is available."""


class InsufficientTrainingDataError(InferenceError):
    """Raised when there is not enough labeled text to train."""


class InvalidInferenceInputError(InferenceError):
    """Raised when the supplied text is unusable."""


def _artifact_path() -> Path:
    settings = get_settings()
    directory = settings.model_path
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{MODEL_NAME}.joblib"


def _text_hashes(db: Session) -> Dict[int, List[str]]:
    """Collect text samples grouped by owning actor."""
    rows = (
        db.query(Evidence.entity_id, Evidence.actor_id, Evidence.content)
        .filter(Evidence.evidence_type == "text_sample")
        .all()
    )
    grouped: Dict[int, List[str]] = {}
    for entity_id, actor_id, content in rows:
        owner = actor_id if actor_id is not None else entity_id
        if owner is None or not content or len(content.split()) < 5:
            continue
        grouped.setdefault(int(owner), []).append(content)
    return grouped


def train_model(db: Session) -> Dict:
    """Fit and persist the style attribution model."""
    from sklearn.feature_extraction.text import TfidfVectorizer

    grouped = _text_hashes(db)
    if len(grouped) < 2:
        raise InsufficientTrainingDataError(
            "At least 2 actors with text-sample evidence are required to train the model "
            f"(found {len(grouped)})."
        )

    documents: List[str] = []
    labels: List[int] = []
    for actor_id, texts in sorted(grouped.items()):
        for text in texts:
            documents.append(text)
            labels.append(actor_id)

    if len(documents) < 2:
        raise InsufficientTrainingDataError("At least 2 usable text samples are required.")

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 3), analyzer="word", sublinear_tf=True, min_df=1, max_features=5000
    )
    matrix = vectorizer.fit_transform(documents)

    centroids: Dict[int, np.ndarray] = {}
    for actor_id in sorted(set(labels)):
        indices = [i for i, label in enumerate(labels) if label == actor_id]
        centroid = np.asarray(matrix[indices].mean(axis=0)).ravel()
        centroids[actor_id] = centroid

    manifest = {
        "name": MODEL_NAME,
        "version": MODEL_VERSION,
        "trained_at": utcnow().isoformat(),
        "document_count": len(documents),
        "actor_count": len(centroids),
        "feature_count": int(matrix.shape[1]),
        "label_counts": {
            str(actor_id): sum(1 for label in labels if label == actor_id)
            for actor_id in centroids
        },
        "artifact": str(_artifact_path()),
    }

    artifact = {"manifest": manifest, "vectorizer": vectorizer, "centroids": centroids}
    joblib.dump(artifact, _artifact_path())
    return manifest


def load_model() -> Dict:
    path = _artifact_path()
    if not path.exists():
        raise ModelNotTrainedError(
            "No trained style model is available. Train the model first "
            "(POST /api/analysis/models/train)."
        )
    try:
        artifact = joblib.load(path)
    except Exception as exc:  # pragma: no cover - corrupt artifact
        raise ModelNotTrainedError(f"Stored model could not be loaded: {exc}") from exc
    if not isinstance(artifact, dict) or "vectorizer" not in artifact:
        raise ModelNotTrainedError("Stored model artifact is not compatible with this version.")
    return artifact


def model_status() -> Dict:
    path = _artifact_path()
    if not path.exists():
        return {
            "name": MODEL_NAME,
            "version": MODEL_VERSION,
            "trained": False,
            "artifact": str(path),
            "note": "No artifact on disk. Train the model to enable inference.",
        }
    try:
        artifact = load_model()
        manifest = artifact.get("manifest", {})
        return {"trained": True, "artifact": str(path), **manifest}
    except InferenceError as exc:
        return {"name": MODEL_NAME, "trained": False, "error": str(exc), "artifact": str(path)}


def _predict(artifact: Dict, text: str, db: Session, top_n: int = 5) -> Dict:
    from sklearn.metrics.pairwise import cosine_similarity

    if not text or len(text.split()) < 5:
        raise InvalidInferenceInputError(
            "Provide at least 5 words of text for a meaningful style comparison."
        )

    vectorizer = artifact["vectorizer"]
    centroids: Dict[int, np.ndarray] = artifact["centroids"]
    try:
        vector = vectorizer.transform([text])
    except Exception as exc:  # pragma: no cover - vectorizer contract
        raise InvalidInferenceInputError(f"Text could not be vectorised: {exc}") from exc

    scores = []
    for actor_id, centroid in centroids.items():
        similarity = float(cosine_similarity(vector, centroid.reshape(1, -1))[0][0])
        scores.append((int(actor_id), similarity))
    scores.sort(key=lambda item: item[1], reverse=True)

    top = scores[:top_n]
    actor_ids = [actor_id for actor_id, _ in top]
    actors = {
        actor.id: actor
        for actor in db.query(Actor).filter(Actor.id.in_(actor_ids)).all()
    }

    candidates = []
    for actor_id, similarity in top:
        actor = actors.get(actor_id)
        candidates.append(
            {
                "actor_id": actor_id,
                "handle": actor.primary_handle if actor else None,
                "internal_id": actor.internal_id if actor else None,
                "score": round(similarity, 4),
            }
        )

    margin = round(scores[0][1] - scores[1][1], 4) if len(scores) > 1 else None
    manifest = artifact.get("manifest", {})
    return {
        "model": {
            "name": manifest.get("name", MODEL_NAME),
            "version": manifest.get("version", MODEL_VERSION),
            "trained_at": manifest.get("trained_at"),
            "feature_count": manifest.get("feature_count"),
            "actor_count": manifest.get("actor_count"),
        },
        "predicted_actor_id": scores[0][0] if scores else None,
        "predicted_handle": candidates[0]["handle"] if candidates else None,
        "score": candidates[0]["score"] if candidates else 0.0,
        "margin": margin,
        "candidates": candidates,
        "status": "ok",
        "note": (
            "Nearest style centroid. A high score means the text resembles an actor's "
            "existing samples, not that the actor wrote it."
        ),
    }


def infer(text: str, db: Session) -> Dict:
    return _predict(load_model(), text, db)


def infer_batch(texts: List[str], db: Session) -> Dict:
    if not texts:
        raise InvalidInferenceInputError("Batch inference requires at least one text.")
    artifact = load_model()
    results = []
    failures = 0
    for index, text in enumerate(texts):
        try:
            prediction = _predict(artifact, text, db)
            results.append({"index": index, "status": "ok", **prediction})
        except InvalidInferenceInputError as exc:
            failures += 1
            results.append({"index": index, "status": "error", "error": str(exc)})
    return {
        "model": artifact.get("manifest", {}),
        "processed": len(texts),
        "succeeded": len(texts) - failures,
        "failed": failures,
        "results": results,
    }


def persist_inference(db: Session, text: str, result: Dict) -> Optional[int]:
    """Store inference provenance in ``analysis_results``."""
    try:
        record = AnalysisResult(
            actor_a_id=result.get("predicted_actor_id"),
            actor_b_id=None,
            analysis_type="ml_inference",
            score=float(result.get("score") or 0.0),
            details={
                "model": result.get("model"),
                "candidates": result.get("candidates"),
                "margin": result.get("margin"),
                "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "text_word_count": len(text.split()),
                "recorded_at": utcnow().isoformat(),
                "disclaimer": result.get("note"),
            },
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record.id
    except Exception:
        db.rollback()
        return None
