"""CSV, JSON, single-record and STIX ingestion flows."""

import io
import json
from uuid import uuid4

from app.database.session import SessionLocal
from app.models.entities import Actor, CollectionJob, Identifier, IntelligenceSource


def _upload(client, headers, path, filename, content: bytes, content_type="text/csv"):
    return client.post(
        path,
        files={"file": (filename, content, content_type)},
        headers=headers,
    )


def test_single_record_import_is_idempotent(client, admin_headers):
    suffix = uuid4().hex[:6]
    record = {
        "handle": f"ingest_{suffix}",
        "pgp": "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890",
        "wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "domain": "ingest-example.com",
        "email": "ingest@example.com",
        "ip": "203.0.113.55",
        "threat_category": "Test",
        "source": f"Test Source {suffix}",
        "source_reliability": 0.8,
        "is_synthetic": True,
        "text_sample": "This is a synthetic sample used to test ingestion behaviour.",
        "activity_dates": ["2024-05-01T10:00:00", "not-a-date"],
    }

    first = client.post("/api/ingestion/record", json=record, headers=admin_headers)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["imported"] == 1
    assert body["duplicates"] == 0
    assert body["identifiers_added"] >= 5
    assert body["evidence_added"] == 1
    assert body["events_added"] == 1
    assert any("not-a-date" in warning for warning in body["errors"])

    second = client.post("/api/ingestion/record", json=record, headers=admin_headers)
    assert second.status_code == 200, second.text
    duplicate = second.json()
    assert duplicate["imported"] == 0
    assert duplicate["duplicates"] == 1
    assert duplicate["identifiers_added"] == 0

    db = SessionLocal()
    try:
        actor = (
            db.query(Actor)
            .filter(Actor.primary_handle == f"ingest_{suffix}")
            .one()
        )
        # Re-import must not duplicate identifiers or handles
        values = [
            row.value for row in db.query(Identifier).filter(Identifier.actor_id == actor.id)
        ]
        assert len(values) == len(set(values))
    finally:
        db.close()


def test_invalid_identifier_rejects_record(client, admin_headers):
    response = client.post(
        "/api/ingestion/record",
        json={
            "handle": f"bad_{uuid4().hex[:6]}",
            "wallet": "short",
            "source": "Bad Source",
            "is_synthetic": True,
        },
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert "wallet" in response.json()["detail"].lower()


def test_source_provenance_conflict_rejected(client, admin_headers):
    suffix = uuid4().hex[:6]
    source_name = f"Mixed Source {suffix}"
    ok = client.post(
        "/api/ingestion/record",
        json={
            "handle": f"prov_{suffix}",
            "source": source_name,
            "is_synthetic": True,
        },
        headers=admin_headers,
    )
    assert ok.status_code == 200

    conflict = client.post(
        "/api/ingestion/record",
        json={
            "handle": f"prov2_{suffix}",
            "source": source_name,
            "is_synthetic": False,
        },
        headers=admin_headers,
    )
    assert conflict.status_code == 422
    assert "is_synthetic" in conflict.json()["detail"]


def test_csv_import_reports_partial_failures(client, admin_headers):
    suffix = uuid4().hex[:6]
    csv_content = (
        "handle,pgp,email,threat_category,source,is_synthetic\n"
        f"csv_ok_{suffix},,csv_ok_{suffix}@example.com,Test,CSV Demo,true\n"
        f"csv_bad_{suffix},,not-an-email,Test,CSV Demo,true\n"
        f",,,Test,CSV Demo,true\n"
    ).encode()

    response = _upload(
        client, admin_headers, "/api/ingestion/csv", "demo.csv", csv_content
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 3
    assert body["imported"] == 1
    assert body["rejected"] == 2
    assert len(body["errors"]) == 2

    # Duplicate re-upload is reported, not silently dropped
    again = _upload(client, admin_headers, "/api/ingestion/csv", "demo.csv", csv_content)
    assert again.json()["duplicates"] == 1

    jobs = client.get("/api/ingestion/jobs", headers=admin_headers).json()
    assert any(job["source"] == "demo.csv" for job in jobs)


def test_csv_requires_handle_column(client, admin_headers):
    response = _upload(
        client, admin_headers, "/api/ingestion/csv", "bad.csv", b"name,value\nx,1\n"
    )
    assert response.status_code == 400


def test_json_import_list_and_wrapper(client, admin_headers):
    suffix = uuid4().hex[:6]
    records = [
        {
            "handle": f"json_a_{suffix}",
            "source": "JSON Demo",
            "is_synthetic": True,
            "pgp": "FINGERPRINT" + suffix.upper(),
        },
        {
            "handle": f"json_b_{suffix}",
            "source": "JSON Demo",
            "is_synthetic": True,
            "ip": "198.51.100.9",
        },
    ]
    list_response = _upload(
        client,
        admin_headers,
        "/api/ingestion/json",
        "records.json",
        json.dumps(records).encode(),
        "application/json",
    )
    assert list_response.status_code == 200, list_response.text
    assert list_response.json()["imported"] == 2

    wrapped = _upload(
        client,
        admin_headers,
        "/api/ingestion/json",
        "wrapped.json",
        json.dumps({"records": records}).encode(),
        "application/json",
    )
    assert wrapped.status_code == 200
    assert wrapped.json()["duplicates"] == 2

    malformed = _upload(
        client, admin_headers, "/api/ingestion/json", "bad.json", b"{not json", "application/json"
    )
    assert malformed.status_code == 400


def test_stix_bundle_import_and_dedup(client, admin_headers):
    suffix = uuid4().hex[:8]
    group_id = f"intrusion-set--{suffix}"
    technique_id = f"attack-pattern--{suffix}"
    bundle = {
        "type": "bundle",
        "id": f"bundle--{suffix}",
        "objects": [
            {
                "type": "intrusion-set",
                "id": group_id,
                "name": f"STIX Group {suffix}",
                "description": "STIX test group",
                "external_references": [
                    {"source_name": "mitre-attack", "url": "https://attack.mitre.org/groups/G9999"}
                ],
                "created": "2023-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
            },
            {
                "type": "attack-pattern",
                "id": technique_id,
                "name": f"STIX Technique {suffix}",
                "description": "STIX test technique",
                "external_references": [],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "relationship",
                "id": f"relationship--{suffix}",
                "relationship_type": "uses",
                "source_ref": group_id,
                "target_ref": technique_id,
            },
            {
                "type": "marking-definition",
                "id": f"marking-definition--{suffix}",
                "name": "TLP:WHITE",
            },
        ],
    }

    response = _upload(
        client,
        admin_headers,
        "/api/ingestion/stix?source_name=stix_test_feed",
        "bundle.json",
        json.dumps(bundle).encode(),
        "application/json",
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["records_imported"] == 2
    assert body["relationships_created"] == 1
    assert body["unsupported_objects"] == 1

    repeat = _upload(
        client,
        admin_headers,
        "/api/ingestion/stix?source_name=stix_test_feed",
        "bundle.json",
        json.dumps(bundle).encode(),
        "application/json",
    )
    assert repeat.status_code == 200
    assert repeat.json()["records_imported"] == 0
    assert repeat.json()["relationships_created"] == 0

    db = SessionLocal()
    try:
        source = (
            db.query(IntelligenceSource)
            .filter(IntelligenceSource.name == "stix_test_feed")
            .one()
        )
        assert source.origin == "external"
        assert source.is_synthetic is False
        assert (
            db.query(Actor).filter(Actor.external_id == group_id).count() == 1
        )
    finally:
        db.close()


def test_stix_bundle_without_supported_objects_is_rejected(client, admin_headers):
    response = _upload(
        client,
        admin_headers,
        "/api/ingestion/stix",
        "empty.json",
        json.dumps({"type": "bundle", "objects": []}).encode(),
        "application/json",
    )
    assert response.status_code == 422


def test_feed_status_reports_real_configuration(client, admin_headers):
    response = client.get("/api/ingestion/feeds", headers=admin_headers)
    assert response.status_code == 200
    feeds = {feed["key"]: feed for feed in response.json()}
    assert feeds["aptnotes"]["configured"] is True
    assert feeds["urlhaus"]["configured"] is True
    assert feeds["mitre_attack"]["configured"] is True
    # ThreatFox needs a key that is intentionally absent in the test environment
    assert feeds["threatfox"]["configured"] is False
    assert feeds["threatfox"]["status"] == "blocked_missing_credentials"


def test_threatfox_without_key_returns_503(client, admin_headers):
    response = client.post("/api/ingestion/feeds/threatfox", json={}, headers=admin_headers)
    assert response.status_code == 503
    assert "ABUSE_CH_AUTH_KEY" in response.json()["detail"]


def test_unknown_feed_404(client, admin_headers):
    response = client.post("/api/ingestion/feeds/not-a-feed", json={}, headers=admin_headers)
    assert response.status_code == 404


def test_feed_ingestion_requires_admin(client, analyst_headers):
    response = client.post("/api/ingestion/feeds/aptnotes", json={}, headers=analyst_headers)
    assert response.status_code == 403


def test_collection_jobs_are_recorded(client, admin_headers):
    db = SessionLocal()
    try:
        assert db.query(CollectionJob).count() > 0
    finally:
        db.close()
