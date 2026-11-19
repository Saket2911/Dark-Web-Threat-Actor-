"""Stylometry, behaviour, attribution scoring, clustering and model inference."""

from uuid import uuid4

SAMPLE_A = (
    "The operation proceeded according to plan. Coordination was established via the usual "
    "channel. All parties confirmed receipt of the package. Further instructions will follow "
    "at the scheduled time. Keep transfers split and confirm each leg settles cleanly."
)
SAMPLE_B = (
    "Short sentences. Different rhythm. Nothing here resembles the other sample in wording, "
    "structure or punctuation, and the vocabulary is deliberately unrelated to the topic."
)


def test_stylometry_identical_and_different(client, admin_headers):
    identical = client.post(
        "/api/analysis/stylometry",
        json={"text_a": SAMPLE_A, "text_b": SAMPLE_A},
        headers=admin_headers,
    )
    assert identical.status_code == 200
    identical_body = identical.json()
    assert identical_body["score"] >= 0.95
    assert identical_body["details"]["identical_text"] is True
    assert any("copied" in warning.lower() or "template" in warning.lower()
               for warning in identical_body["details"]["warnings"])
    assert identical_body["details"]["shared_terms"]

    different = client.post(
        "/api/analysis/stylometry",
        json={"text_a": SAMPLE_A, "text_b": SAMPLE_B},
        headers=admin_headers,
    )
    body = different.json()
    assert 0.0 <= body["score"] < identical_body["score"]
    assert body["explanation"]
    assert body["details"]["feature_comparison"]

    short = client.post(
        "/api/analysis/stylometry",
        json={"text_a": "Too short.", "text_b": "Also short."},
        headers=admin_headers,
    )
    assert short.status_code == 200
    assert short.json()["sufficient"] is False
    assert short.json()["warnings"]

    empty = client.post(
        "/api/analysis/stylometry",
        json={"text_a": "", "text_b": SAMPLE_A},
        headers=admin_headers,
    )
    assert empty.status_code == 200
    assert empty.json()["score"] == 0.0
    assert empty.json()["details"]["reason"] == "missing text"


def test_behavioural_similarity(client, admin_headers, make_actor):
    suffix = uuid4().hex[:6]
    a = make_actor(f"beh_a_{suffix}")
    b = make_actor(f"beh_b_{suffix}")
    for actor in (a, b):
        for hour in (2, 2, 3, 2):
            created = client.post(
                f"/api/actors/{actor['id']}/timeline",
                json={
                    "event_type": "post",
                    "description": f"activity at {hour}",
                    "event_date": f"2024-02-0{hour}T0{hour}:15:00",
                },
                headers=admin_headers,
            )
            assert created.status_code == 201

    response = client.post(
        "/api/analysis/behavioural",
        json={"actor_a_id": a["id"], "actor_b_id": b["id"]},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["score"] > 0.9
    assert body["details"]["sufficient"] is True
    assert body["details"]["overlapping_hours"]
    assert body["disclaimer"]

    idle = make_actor(f"beh_idle_{suffix}")
    empty = client.post(
        "/api/analysis/behavioural",
        json={"actor_a_id": a["id"], "actor_b_id": idle["id"]},
        headers=admin_headers,
    )
    assert empty.status_code == 200
    assert empty.json()["score"] == 0.0
    assert empty.json()["details"]["sufficient"] is False

    same = client.post(
        "/api/analysis/behavioural",
        json={"actor_a_id": a["id"], "actor_b_id": a["id"]},
        headers=admin_headers,
    )
    assert same.status_code == 422


def test_attribution_scoring_is_explainable(client, admin_headers, make_pair):
    a, b, fingerprint = make_pair
    for actor in (a, b):
        client.post(
            f"/api/actors/{actor['id']}/evidence",
            json={
                "evidence_type": "text_sample",
                "content": SAMPLE_A,
                "source": "Explainability Source",
                "reliability": 0.8,
            },
            headers=admin_headers,
        )

    response = client.post(
        "/api/analysis/score",
        json={"actor_a_id": a["id"], "actor_b_id": b["id"]},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["category"] in (
        "Strong evidence",
        "Moderate evidence",
        "Weak evidence",
        "Insufficient evidence",
    )
    assert body["final"] > 0
    assert body["components"]["identifier"] > 0
    assert body["contributions"]
    assert body["weights"]
    assert 0 < body["coverage"] <= 1
    assert body["limitations"]
    assert "hypothesis" in body["hypothesis"].lower()
    assert body["explanation"]
    assert body["analysis_id"]
    assert body["actor_a"]["id"] == a["id"]

    history = client.get("/api/analysis/history", headers=admin_headers).json()
    assert any(item["id"] == body["analysis_id"] for item in history)

    custom = client.post(
        "/api/analysis/score",
        json={
            "actor_a_id": a["id"],
            "actor_b_id": b["id"],
            "weights": {"identifier": 1.0, "stylometric": 0, "behavioural": 0, "temporal": 0, "infrastructure": 0},
        },
        headers=admin_headers,
    )
    assert custom.status_code == 200
    assert custom.json()["weights"]["identifier"] == 1.0
    assert custom.json()["components"]["identifier"] > 0

    same = client.post(
        "/api/analysis/score",
        json={"actor_a_id": a["id"], "actor_b_id": a["id"]},
        headers=admin_headers,
    )
    assert same.status_code == 422

    missing = client.post(
        "/api/analysis/score",
        json={"actor_a_id": a["id"], "actor_b_id": 999999},
        headers=admin_headers,
    )
    assert missing.status_code == 404


def test_infrastructure_similarity_component(client, admin_headers, make_actor):
    suffix = uuid4().hex[:6]
    a = make_actor(f"infra_a_{suffix}")
    b = make_actor(f"infra_b_{suffix}")
    for actor in (a, b):
        client.post(
            f"/api/actors/{actor['id']}/identifiers",
            json={"id_type": "domain", "value": f"shared-{suffix}.example.com"},
            headers=admin_headers,
        )
    response = client.post(
        "/api/analysis/score",
        json={"actor_a_id": a["id"], "actor_b_id": b["id"]},
        headers=admin_headers,
    )
    body = response.json()
    assert body["components"]["infrastructure"] > 0
    assert body["available"]["infrastructure"] is True
    infra = next(c for c in body["contributions"] if c["feature"] == "infrastructure")
    assert infra["detail"]["shared"]


def test_clustering_endpoints(client, admin_headers):
    kmeans = client.post("/api/analysis/cluster", json={"method": "kmeans"}, headers=admin_headers)
    assert kmeans.status_code == 200, kmeans.text
    body = kmeans.json()
    if body["status"] == "ok":
        assert body["clusters"] >= 2
        assert body["summaries"]
        assert body["feature_note"]
        assert body["limitations"]
        for assignment in body["assignments"]:
            assert isinstance(assignment["cluster"], int)

    behavioural = client.post(
        "/api/analysis/cluster/behavioural?eps=0.6&min_samples=2", headers=admin_headers
    )
    assert behavioural.status_code == 200
    dbscan = behavioural.json()
    assert "noise_count" in dbscan
    assert dbscan["method"] == "dbscan"
    for assignment in dbscan["assignments"]:
        if assignment["cluster"] == -1:
            assert dbscan["noise_count"] >= 1

    invalid = client.post("/api/analysis/cluster", json={"method": "magic"}, headers=admin_headers)
    assert invalid.status_code == 422


def test_model_training_requires_data(client, admin_headers, monkeypatch):
    from app.ml import inference

    status = client.get("/api/analysis/models/status", headers=admin_headers)
    assert status.status_code == 200

    # Simulate an empty corpus so the insufficient-data path is deterministic
    # regardless of the order in which the suite runs.
    monkeypatch.setattr(inference, "_text_hashes", lambda db: {})
    response = client.post("/api/analysis/models/train", headers=admin_headers)
    assert response.status_code == 422
    assert "text" in response.json()["detail"].lower()


def test_model_train_infer_and_batch(client, admin_headers, analyst_headers, make_actor):
    suffix = uuid4().hex[:6]
    samples = {
        f"style_a_{suffix}": [
            "Nightly transfers settle through the same clearing channel before the window closes. "
            "Confirmation arrives once the ledger reconciles and both counterparties acknowledge.",
            "Every settlement uses the same clearing channel. Confirmation follows once the ledger "
            "reconciles and all counterparties acknowledge the transfer window.",
        ],
        f"style_b_{suffix}": [
            "Ransom notes are short. Deadlines are absolute. Payment routes rotate weekly and "
            "negotiation happens only on the private channel.",
            "Short ransom notes with absolute deadlines. Payment routes rotate weekly and all "
            "negotiation stays on the private channel.",
        ],
    }

    for handle, texts in samples.items():
        actor = make_actor(handle)
        for text in texts:
            created = client.post(
                f"/api/actors/{actor['id']}/evidence",
                json={
                    "evidence_type": "text_sample",
                    "content": text,
                    "source": "Style Training Source",
                    "reliability": 0.8,
                },
                headers=admin_headers,
            )
            assert created.status_code == 201

    forbidden = client.post("/api/analysis/models/train", headers=analyst_headers)
    assert forbidden.status_code == 403

    trained = client.post("/api/analysis/models/train", headers=admin_headers)
    assert trained.status_code == 200, trained.text
    manifest = trained.json()
    assert manifest["status"] == "trained"
    assert manifest["actor_count"] >= 2
    assert manifest["document_count"] >= 4

    inference = client.post(
        "/api/analysis/models/infer",
        json={
            "text": "Settlement confirmation follows once the ledger reconciles and every "
            "counterparty acknowledges the nightly transfer window."
        },
        headers=admin_headers,
    )
    assert inference.status_code == 200, inference.text
    result = inference.json()
    assert result["predicted_actor_id"]
    assert result["candidates"]
    assert result["model"]["name"] == "style-centroid-tfidf"
    assert result["analysis_id"]

    too_short = client.post(
        "/api/analysis/models/infer", json={"text": "too short"}, headers=admin_headers
    )
    assert too_short.status_code == 422

    batch = client.post(
        "/api/analysis/models/batch",
        json={
            "texts": [
                "Settlement confirmation follows once the ledger reconciles and every "
                "counterparty acknowledges the nightly transfer window.",
                "short",
            ]
        },
        headers=admin_headers,
    )
    assert batch.status_code == 200
    batch_body = batch.json()
    assert batch_body["processed"] == 2
    assert batch_body["succeeded"] == 1
    assert batch_body["failed"] == 1
    assert batch_body["results"][1]["status"] == "error"

    empty_batch = client.post(
        "/api/analysis/models/batch", json={"texts": []}, headers=admin_headers
    )
    assert empty_batch.status_code == 422


def test_model_info_endpoint(client, admin_headers):
    response = client.get("/api/analysis/model/info", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["scoring"] == "weighted_evidence_with_coverage"
    assert body["thresholds"]["minimum_coverage"] == 0.4
    assert "inference" in body
