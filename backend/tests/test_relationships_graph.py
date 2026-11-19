"""Relationship engine and graph API."""

from uuid import uuid4


def _actor_nodes(graph):
    return [node for node in graph["nodes"] if node["data"]["type"] == "actor"]


def test_build_creates_direct_relationships_and_is_idempotent(client, admin_headers, make_pair):
    a, b, fingerprint = make_pair
    first = client.post("/api/graph/build", headers=admin_headers)
    assert first.status_code == 200
    assert first.json()["direct_created"] >= 1

    second = client.post("/api/graph/build", headers=admin_headers)
    assert second.status_code == 200
    assert second.json()["direct_created"] == 0

    pair_edges = [
        edge
        for edge in client.get("/api/graph/data", headers=admin_headers).json()["edges"]
        if edge["data"]["label"] == "SHARED_IDENTIFIER"
        and {edge["data"]["source"], edge["data"]["target"]}
        == {f"actor_{a['id']}", f"actor_{b['id']}"}
    ]
    assert len(pair_edges) == 1
    edge = pair_edges[0]["data"]
    assert edge["direct"] is True
    assert edge["relationship_classification"] == "documented"
    assert fingerprint in edge["evidence"]


def test_graph_data_structure_and_filters(client, admin_headers, make_pair):
    a, b, _ = make_pair
    client.post("/api/graph/build", headers=admin_headers)

    graph = client.get("/api/graph/data", headers=admin_headers).json()
    assert {"nodes", "edges", "stats"} <= set(graph)
    assert graph["stats"]["actor_nodes"] >= 2
    assert any(edge["data"]["label"] == "HAS_IDENTIFIER" for edge in graph["edges"])
    node_ids = {node["data"]["id"] for node in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["data"]["source"] in node_ids
        assert edge["data"]["target"] in node_ids

    focused = client.get(
        f"/api/graph/data?actor_id={a['id']}&depth=1", headers=admin_headers
    ).json()
    assert f"actor_{a['id']}" in {node["data"]["id"] for node in focused["nodes"]}

    search = client.get(f"/api/graph/data?q={a['primary_handle']}", headers=admin_headers).json()
    assert any(
        node["data"]["label"] == a["primary_handle"] for node in search["nodes"]
    )

    high_score = client.get(
        "/api/graph/data?min_score=0.95", headers=admin_headers
    ).json()
    assert all((edge["data"].get("score") or 0) >= 0.95 for edge in high_score["edges"])

    only_inferred = client.get(
        "/api/graph/data?rel_types=POTENTIALLY_SAME_PERSONA", headers=admin_headers
    ).json()
    assert all(
        edge["data"]["label"] == "POTENTIALLY_SAME_PERSONA"
        for edge in only_inferred["edges"]
    )


def test_relationship_detail(client, admin_headers, make_pair):
    a, b, _ = make_pair
    client.post("/api/graph/build", headers=admin_headers)
    edges = [
        edge["data"]
        for edge in client.get("/api/graph/data", headers=admin_headers).json()["edges"]
        if edge["data"]["label"] == "SHARED_IDENTIFIER"
    ]
    assert edges
    relationship_id = edges[0]["relationship_id"]
    detail = client.get(f"/api/graph/relationships/{relationship_id}", headers=admin_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["interpretation"]
    assert body["source"]["type"] in ("actor", "indicator", "campaign", "malware", "tool", "technique")
    assert client.get("/api/graph/relationships/999999", headers=admin_headers).status_code == 404


def test_manual_relationship_validation(client, admin_headers, make_actor):
    a = make_actor(f"rel_a_{uuid4().hex[:6]}")
    b = make_actor(f"rel_b_{uuid4().hex[:6]}")

    self_link = client.post(
        "/api/graph/relationships",
        json={
            "source_actor_id": a["id"],
            "target_actor_id": a["id"],
            "rel_type": "RELATED_TO",
        },
        headers=admin_headers,
    )
    assert self_link.status_code == 422

    invalid_type = client.post(
        "/api/graph/relationships",
        json={
            "source_actor_id": a["id"],
            "target_actor_id": b["id"],
            "rel_type": "BEST_FRIENDS",
        },
        headers=admin_headers,
    )
    assert invalid_type.status_code == 422

    created = client.post(
        "/api/graph/relationships",
        json={
            "source_actor_id": a["id"],
            "target_actor_id": b["id"],
            "rel_type": "RELATED_TO",
            "evidence": "Analyst observed a shared marketplace.",
            "score": 0.4,
            "relationship_classification": "unresolved",
            "confidence_level": "limited",
        },
        headers=admin_headers,
    )
    assert created.status_code == 200

    duplicate = client.post(
        "/api/graph/relationships",
        json={
            "source_actor_id": a["id"],
            "target_actor_id": b["id"],
            "rel_type": "RELATED_TO",
        },
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    missing_actor = client.post(
        "/api/graph/relationships",
        json={
            "source_actor_id": 999999,
            "target_actor_id": b["id"],
            "rel_type": "RELATED_TO",
        },
        headers=admin_headers,
    )
    assert missing_actor.status_code == 422


def test_inferred_relationships_from_analysis(client, admin_headers, make_actor):
    suffix = uuid4().hex[:6]
    a = make_actor(f"infer_a_{suffix}")
    b = make_actor(f"infer_b_{suffix}")
    text = (
        "The shipment will move through the usual channel tonight. Confirm receipt "
        "before the next window opens and keep the ledger updated for both parties."
    )
    for actor in (a, b):
        client.post(
            f"/api/actors/{actor['id']}/evidence",
            json={
                "evidence_type": "text_sample",
                "content": text,
                "source": "Inference Test Source",
                "reliability": 0.8,
            },
            headers=admin_headers,
        )
    scored = client.post(
        "/api/analysis/score",
        json={"actor_a_id": a["id"], "actor_b_id": b["id"]},
        headers=admin_headers,
    )
    assert scored.status_code == 200
    assert scored.json()["final"] >= 0.6

    inference = client.post("/api/graph/infer", headers=admin_headers)
    assert inference.status_code == 200
    assert inference.json()["inferred"] >= 1

    again = client.post("/api/graph/infer", headers=admin_headers)
    assert again.json()["inferred"] == 0

    graph = client.get("/api/graph/data?rel_types=POTENTIALLY_SAME_PERSONA", headers=admin_headers).json()
    target = {
        f"actor_{a['id']}",
        f"actor_{b['id']}",
    }
    matches = [
        edge
        for edge in graph["edges"]
        if {edge["data"]["source"], edge["data"]["target"]} == target
    ]
    assert matches
    assert matches[0]["data"]["direct"] is False


def test_components_and_clusters(client, admin_headers):
    components = client.get("/api/graph/components", headers=admin_headers)
    assert components.status_code == 200
    assert components.json()["component_count"] >= 1

    clusters = client.get("/api/graph/clusters", headers=admin_headers)
    assert clusters.status_code == 200
    assert "cluster_count" in clusters.json()

    stats = client.get("/api/graph/stats", headers=admin_headers)
    assert stats.status_code == 200
    assert stats.json()["total"] >= 1
