"""End-to-end integration workflow across backend, database and exports."""

from uuid import uuid4


def test_complete_analyst_workflow(client, admin_headers):
    suffix = uuid4().hex[:6]
    fingerprint = "WORKFLOW" + suffix.upper()

    # 1. Create actors
    actor_a = client.post(
        "/api/actors",
        json={"primary_handle": f"wf_a_{suffix}", "threat_category": "APT"},
        headers=admin_headers,
    ).json()
    actor_b = client.post(
        "/api/actors",
        json={"primary_handle": f"wf_b_{suffix}", "threat_category": "APT"},
        headers=admin_headers,
    ).json()

    # 2. Add identifiers
    for actor in (actor_a, actor_b):
        added = client.post(
            f"/api/actors/{actor['id']}/identifiers",
            json={"id_type": "pgp", "value": fingerprint, "source": "Workflow test"},
            headers=admin_headers,
        )
        assert added.status_code == 201

    # 3. Evidence linked to an investigated actor (used by the case file)
    attached = client.post(
        f"/api/actors/{actor_a['id']}/evidence",
        json={
            "evidence_type": "osint_report",
            "content": "Analyst-collected forum profile referencing the shared key.",
            "reference": "https://example.org/workflow",
            "source": "Workflow OSINT",
            "reliability": 0.7,
        },
        headers=admin_headers,
    )
    assert attached.status_code == 201

    # 3b. Ingest evidence (single record with text + activity)
    ingest = client.post(
        "/api/ingestion/record",
        json={
            "handle": f"wf_ingest_{suffix}",
            "source": "Workflow Demo Feed",
            "is_synthetic": True,
            "text_sample": (
                "Coordination was established via the usual channel and every party "
                "confirmed receipt before the next window opened."
            ),
            "activity_dates": ["2024-04-01T04:00:00", "2024-04-02T04:30:00"],
            "threat_category": "APT",
        },
        headers=admin_headers,
    )
    assert ingest.status_code == 200, ingest.text

    # 4. Build relationships
    built = client.post("/api/graph/build", headers=admin_headers).json()
    assert built["direct_created"] >= 0

    # 5. Retrieve graph
    graph = client.get("/api/graph/data", headers=admin_headers).json()
    assert graph["nodes"] and graph["edges"]
    pair_edges = [
        edge["data"]
        for edge in graph["edges"]
        if edge["data"]["label"] == "SHARED_IDENTIFIER"
        and {edge["data"]["source"], edge["data"]["target"]}
        == {f"actor_{actor_a['id']}", f"actor_{actor_b['id']}"}
    ]
    assert pair_edges, "shared fingerprint should generate a direct relationship"
    relationship_id = pair_edges[0]["relationship_id"]

    # 6. Analyses
    style = client.post(
        "/api/analysis/stylometry",
        json={"text_a": "Alpha text with words. Beta text with other words.", "text_b": "Alpha text with words."},
        headers=admin_headers,
    )
    assert style.status_code == 200

    behavioural = client.post(
        "/api/analysis/behavioural",
        json={"actor_a_id": actor_a["id"], "actor_b_id": actor_b["id"]},
        headers=admin_headers,
    )
    assert behavioural.status_code == 200

    attribution = client.post(
        "/api/analysis/score",
        json={"actor_a_id": actor_a["id"], "actor_b_id": actor_b["id"]},
        headers=admin_headers,
    )
    assert attribution.status_code == 200
    assert attribution.json()["category"]

    clusters = client.post("/api/analysis/cluster", json={"method": "kmeans"}, headers=admin_headers)
    assert clusters.status_code == 200

    # 7. Investigation
    investigation = client.post(
        "/api/investigations",
        json={
            "title": f"Workflow case {suffix}",
            "status": "open",
            "notes": "Integration test case",
            "actor_ids": [actor_a["id"]],
        },
        headers=admin_headers,
    )
    assert investigation.status_code == 201, investigation.text
    investigation_id = investigation.json()["id"]

    added = client.post(
        f"/api/investigations/{investigation_id}/entities",
        json={"actor_id": actor_b["id"]},
        headers=admin_headers,
    )
    assert added.status_code == 201
    duplicate = client.post(
        f"/api/investigations/{investigation_id}/entities",
        json={"actor_id": actor_b["id"]},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    # 8. Analyst decision
    review = client.post(
        f"/api/investigations/{investigation_id}/review",
        json={
            "relationship_id": relationship_id,
            "decision": "approved",
            "notes": "Shared fingerprint corroborated by analyst.",
        },
        headers=admin_headers,
    )
    assert review.status_code == 201, review.text
    assert review.json()["analyst"] == "admin"

    invalid_decision = client.post(
        f"/api/investigations/{investigation_id}/review",
        json={"relationship_id": relationship_id, "decision": "maybe"},
        headers=admin_headers,
    )
    assert invalid_decision.status_code == 422

    missing_relationship = client.post(
        f"/api/investigations/{investigation_id}/review",
        json={"relationship_id": 999999, "decision": "pending"},
        headers=admin_headers,
    )
    assert missing_relationship.status_code == 422

    detail = client.get(
        f"/api/investigations/{investigation_id}", headers=admin_headers
    ).json()
    assert len(detail["entities"]) == 2
    assert detail["review_counts"]["approved"] == 1
    assert detail["relationships"]
    assert detail["evidence_count"] >= 1

    # 9. Reports
    csv_export = client.get("/api/reports/export/csv?kind=actors", headers=admin_headers)
    assert csv_export.status_code == 200
    assert "text/csv" in csv_export.headers["content-type"]
    assert actor_a["primary_handle"] in csv_export.text

    json_export = client.get("/api/reports/export/json?kind=relationships", headers=admin_headers)
    assert json_export.status_code == 200
    payload = json_export.json()
    assert payload["record_count"] == len(payload["records"])
    assert payload["provenance_note"]

    pdf = client.get(f"/api/reports/pdf/{actor_a['id']}", headers=admin_headers)
    assert pdf.status_code == 200
    assert pdf.content[:4] == b"%PDF"

    investigation_pdf = client.get(
        f"/api/reports/pdf/investigation/{investigation_id}", headers=admin_headers
    )
    assert investigation_pdf.status_code == 200
    assert investigation_pdf.content[:4] == b"%PDF"

    unsupported = client.get("/api/reports/export/csv?kind=secrets", headers=admin_headers)
    assert unsupported.status_code == 422


def test_csv_export_neutralises_formula_injection(client, admin_headers):
    actor = client.post(
        "/api/actors",
        json={"primary_handle": "=HYPERLINK(\"http://evil\")", "threat_category": "Test"},
        headers=admin_headers,
    )
    assert actor.status_code == 201
    export = client.get("/api/reports/export/csv?kind=actors", headers=admin_headers).text
    assert "'=HYPERLINK" in export


def test_dashboard_and_timeline_and_infrastructure(client, admin_headers, make_actor):
    stats = client.get("/api/dashboard/stats", headers=admin_headers)
    assert stats.status_code == 200
    body = stats.json()
    for key in (
        "actors",
        "identifiers",
        "relationships",
        "infra",
        "sources",
        "timeline_events",
        "direct_relationships",
        "inferred_relationships",
    ):
        assert key in body
    assert body["actors"] >= 2

    for path in (
        "/api/dashboard/charts/category",
        "/api/dashboard/charts/activity",
        "/api/dashboard/charts/sources",
        "/api/dashboard/charts/identifiers",
        "/api/dashboard/charts/relationships",
        "/api/dashboard/charts/origin",
        "/api/dashboard/recent",
        "/api/dashboard/activity-log",
    ):
        response = client.get(path, headers=admin_headers)
        assert response.status_code == 200, path
        assert isinstance(response.json(), list)

    actor = make_actor(f"timeline_wf_{uuid4().hex[:6]}")
    for day in ("2024-06-01", "2024-06-02"):
        client.post(
            f"/api/actors/{actor['id']}/timeline",
            json={
                "event_type": "post",
                "description": f"event on {day}",
                "event_date": f"{day}T12:00:00",
            },
            headers=admin_headers,
        )

    timeline = client.get(
        f"/api/timeline?actor_id={actor['id']}&start=2024-06-01&end=2024-06-02&order=desc",
        headers=admin_headers,
    )
    assert timeline.status_code == 200
    events = timeline.json()
    assert len(events) == 2
    assert events[0]["event_date"].startswith("2024-06-02")
    assert events[0]["actor_handle"] == actor["primary_handle"]

    bad_date = client.get("/api/timeline?start=not-a-date", headers=admin_headers)
    assert bad_date.status_code == 422

    summary = client.get(
        f"/api/timeline/summary?actor_id={actor['id']}", headers=admin_headers
    ).json()
    assert summary["total"] == 2
    assert summary["by_day"]

    indicator = client.post(
        "/api/infrastructure",
        json={
            "indicator_type": "domain",
            "value": f"wf-{uuid4().hex[:6]}.example.com",
            "source": "Workflow test",
            "reliability": 0.6,
        },
        headers=admin_headers,
    )
    assert indicator.status_code == 201, indicator.text
    indicator_id = indicator.json()["id"]

    duplicate = client.post(
        "/api/infrastructure",
        json={"indicator_type": "domain", "value": indicator.json()["value"]},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    invalid = client.post(
        "/api/infrastructure",
        json={"indicator_type": "domain", "value": "not a domain"},
        headers=admin_headers,
    )
    assert invalid.status_code == 422

    detail = client.get(f"/api/infrastructure/{indicator_id}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["indicator"]["value"] == indicator.json()["value"]

    listing = client.get("/api/infrastructure?type=domain&page_size=5", headers=admin_headers)
    assert listing.status_code == 200
    assert listing.json()["types"]


def test_settings_surface_real_configuration(client, admin_headers):
    system = client.get("/api/settings/system", headers=admin_headers)
    assert system.status_code == 200
    body = system.json()
    assert body["database"]["actors"] >= 1
    assert body["auth"]["password_hashing"] == "PBKDF2-SHA256"
    assert "secret_key" not in body["auth"]

    weights = client.get("/api/settings/weights/default", headers=admin_headers).json()
    assert abs(sum(weights.values()) - 1.0) < 1e-6

    thresholds = client.get("/api/settings/thresholds", headers=admin_headers).json()
    assert thresholds["minimum_coverage"] == 0.4

    models = client.get("/api/settings/models", headers=admin_headers).json()
    assert models["deterministic"]
    assert models["persisted"]["name"]

    feeds = client.get("/api/settings/feeds", headers=admin_headers).json()
    assert any(feed["key"] == "threatfox" for feed in feeds)

    sources = client.get("/api/settings/sources", headers=admin_headers).json()
    assert isinstance(sources, list)
    assert all("url" in source for source in sources)

    health = client.get("/api/settings/health")
    assert health.status_code == 200
    assert health.json()["db_ok"] is True


def test_analyst_role_cannot_perform_admin_actions(client, analyst_headers, make_actor):
    actor = make_actor(f"rbac_{uuid4().hex[:6]}")
    assert (
        client.delete(f"/api/actors/{actor['id']}", headers=analyst_headers).status_code
        == 403
    )
    assert (
        client.post("/api/graph/infer", headers=analyst_headers).status_code
        == 200
    )
    investigation = client.post(
        "/api/investigations",
        json={"title": "Analyst-created case", "actor_ids": [actor["id"]]},
        headers=analyst_headers,
    )
    assert investigation.status_code == 201
    assert (
        client.delete(
            f"/api/investigations/{investigation.json()['id']}", headers=analyst_headers
        ).status_code
        == 403
    )


def test_unknown_routes_return_404(client):
    assert client.get("/api/does-not-exist", headers={}).status_code == 404
