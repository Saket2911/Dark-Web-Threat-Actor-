"""Actor CRUD, identifier normalisation, evidence and timeline management."""


def test_actor_crud_and_pagination(client, admin_headers, make_actor):
    actor = make_actor("crud_actor", "APT", notes="initial notes")
    actor_id = actor["id"]
    assert actor["internal_id"].startswith("TA")
    assert actor["origin"] == "manual"

    listing = client.get("/api/actors", headers=admin_headers).json()
    assert listing["total"] >= 1
    assert listing["page"] == 1
    assert any(item["id"] == actor_id for item in listing["items"])

    search = client.get("/api/actors?q=crud_actor", headers=admin_headers).json()
    assert search["total"] == 1

    page = client.get("/api/actors?page=1&page_size=1", headers=admin_headers).json()
    assert len(page["items"]) == 1
    assert page["pages"] >= 1

    filtered = client.get("/api/actors?category=APT", headers=admin_headers).json()
    assert all(item["threat_category"] == "APT" for item in filtered["items"])

    bad_origin = client.get("/api/actors?origin=unknown", headers=admin_headers)
    assert bad_origin.status_code == 400

    updated = client.patch(
        f"/api/actors/{actor_id}",
        json={"investigation_status": "review", "threat_category": "FinCrime"},
        headers=admin_headers,
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["investigation_status"] == "review"
    assert body["threat_category"] == "FinCrime"
    # Partial update must not erase untouched fields
    assert body["notes"] == "initial notes"

    missing = client.get("/api/actors/999999", headers=admin_headers)
    assert missing.status_code == 404


def test_identifier_normalisation_and_validation(client, admin_headers, make_actor):
    actor = make_actor("identifier_actor")

    email = client.post(
        f"/api/actors/{actor['id']}/identifiers",
        json={"id_type": "email", "value": "Ops.Team@Example.COM"},
        headers=admin_headers,
    )
    assert email.status_code == 201
    assert email.json()["value"] == "ops.team@example.com"

    domain = client.post(
        f"/api/actors/{actor['id']}/identifiers",
        json={"id_type": "hostname", "value": "HTTPS://Example-Market.COM/path"},
        headers=admin_headers,
    )
    assert domain.status_code == 201
    assert domain.json()["id_type"] == "domain"
    assert domain.json()["value"] == "example-market.com"

    ip = client.post(
        f"/api/actors/{actor['id']}/identifiers",
        json={"id_type": "ip", "value": "203.0.113.7"},
        headers=admin_headers,
    )
    assert ip.status_code == 201
    assert ip.json()["value"] == "203.0.113.7"

    pgp = client.post(
        f"/api/actors/{actor['id']}/identifiers",
        json={
            "id_type": "pgp",
            "value": "abcd 1234 efgh 5678 ijkl 9012 mnop 3456 qrst 7890",
        },
        headers=admin_headers,
    )
    assert pgp.status_code == 201
    assert pgp.json()["value"] == "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"

    duplicate = client.post(
        f"/api/actors/{actor['id']}/identifiers",
        json={"id_type": "pgp", "value": "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    invalid_email = client.post(
        f"/api/actors/{actor['id']}/identifiers",
        json={"id_type": "email", "value": "not-an-email"},
        headers=admin_headers,
    )
    assert invalid_email.status_code == 422

    invalid_type = client.post(
        f"/api/actors/{actor['id']}/identifiers",
        json={"id_type": "shoe_size", "value": "42"},
        headers=admin_headers,
    )
    assert invalid_type.status_code == 422

    identifiers = client.get(
        f"/api/actors/{actor['id']}/identifiers", headers=admin_headers
    ).json()
    assert len(identifiers) == 4

    removed = client.delete(
        f"/api/actors/{actor['id']}/identifiers/{identifiers[0]['id']}",
        headers=admin_headers,
    )
    assert removed.status_code == 200
    assert len(
        client.get(f"/api/actors/{actor['id']}/identifiers", headers=admin_headers).json()
    ) == 3


def test_handles_evidence_and_timeline(client, admin_headers, make_actor):
    actor = make_actor("enrichment_actor")
    actor_id = actor["id"]

    handle = client.post(
        f"/api/actors/{actor_id}/handles",
        json={"handle": "enrichment_actor", "marketplace": "ForumZ"},
        headers=admin_headers,
    )
    assert handle.status_code == 201

    duplicate = client.post(
        f"/api/actors/{actor_id}/handles",
        json={"handle": "enrichment_actor", "marketplace": "ForumZ"},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    evidence = client.post(
        f"/api/actors/{actor_id}/evidence",
        json={
            "evidence_type": "osint_report",
            "content": "Forum profile links the handle to a wallet address.",
            "reference": "https://example.org/report",
            "source": "Open Source Review",
            "reliability": 0.7,
        },
        headers=admin_headers,
    )
    assert evidence.status_code == 201
    assert evidence.json()["is_synthetic"] is False

    listed = client.get(f"/api/actors/{actor_id}/evidence", headers=admin_headers).json()
    assert len(listed) == 1
    assert listed[0]["source"] == "Open Source Review"

    event = client.post(
        f"/api/actors/{actor_id}/timeline",
        json={
            "event_type": "post",
            "description": "Observed posting activity",
            "event_date": "2024-03-01T10:30:00",
            "source": "ForumZ",
        },
        headers=admin_headers,
    )
    assert event.status_code == 201
    assert event.json()["event_date"].startswith("2024-03-01")

    profile = client.get(f"/api/actors/{actor_id}/profile", headers=admin_headers).json()
    assert len(profile["handles"]) == 1
    assert len(profile["evidence"]) == 1
    assert len(profile["timeline"]) == 1


def test_actor_profile_includes_relationships(client, admin_headers, make_pair):
    a, b, fingerprint = make_pair
    client.post("/api/graph/build", headers=admin_headers)

    profile = client.get(f"/api/actors/{a['id']}/profile", headers=admin_headers).json()
    assert profile["related"], "expected at least one relationship"
    rel = profile["related"][0]
    assert rel["other_handle"] in (b["primary_handle"], None)
    assert rel["relationship_classification"] in (
        "documented",
        "inferred",
        "unresolved",
    )


def test_delete_actor_requires_admin(client, admin_headers, analyst_headers, make_actor):
    actor = make_actor("delete_actor")
    forbidden = client.delete(
        f"/api/actors/{actor['id']}", headers=analyst_headers
    )
    assert forbidden.status_code == 403

    deleted = client.delete(f"/api/actors/{actor['id']}", headers=admin_headers)
    assert deleted.status_code == 200
    assert client.get(f"/api/actors/{actor['id']}", headers=admin_headers).status_code == 404
