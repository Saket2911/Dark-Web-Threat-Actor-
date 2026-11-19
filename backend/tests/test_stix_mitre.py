"""STIX normalization, validation, deduplication and the MITRE ATT&CK adapter."""

from unittest.mock import patch
from uuid import uuid4

import pytest

from app.database.session import SessionLocal
from app.ingestion.deduplicator import Deduplicator
from app.ingestion.mitre_attack import MitreAttackAdapter
from app.ingestion.normalizer import normalize_stix_bundle, normalize_stix_object
from app.ingestion.validator import (
    ValidationError,
    validate_stix_bundle,
    validate_stix_object,
    validate_stix_relationship,
)
from app.models.entities import (
    Actor,
    CollectionJob,
    Evidence,
    IntelligenceSource,
    Tactic,
    Technique,
)


def test_normalize_intrusion_set_to_actor():
    stix_obj = {
        "type": "intrusion-set",
        "id": "intrusion-set--12345678-1234-1234-1234-123456789012",
        "name": "APT28",
        "description": "Russian APT group",
        "aliases": ["Fancy Bear", "Sofacy"],
        "created": "2020-01-01T00:00:00Z",
        "modified": "2021-01-01T00:00:00Z",
        "external_references": [
            {"source_name": "mitre-attack", "url": "https://attack.mitre.org/groups/G0001"}
        ],
        "revoked": False,
        "deprecated": False,
    }
    result = normalize_stix_object(stix_obj)
    assert result["stix_type"] == "intrusion-set"
    assert result["model_type"] == "Actor"
    assert result["external_id"] == stix_obj["id"]
    assert result["name"] == "APT28"
    assert result["aliases"] == ["Fancy Bear", "Sofacy"]
    assert result["raw_payload"] == stix_obj


def test_normalize_attack_pattern_to_technique():
    stix_obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--12345678-1234-1234-1234-123456789012",
        "name": "Phishing",
        "external_references": [],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
        ],
    }
    result = normalize_stix_object(stix_obj)
    assert result["model_type"] == "Technique"
    assert len(result["kill_chain_phases"]) == 1


def test_normalize_preserves_revoked_and_custom_fields():
    stix_obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--12345678-1234-1234-1234-123456789012",
        "name": "Deprecated Technique",
        "revoked": True,
        "deprecated": True,
        "custom_field": "custom_value",
    }
    result = normalize_stix_object(stix_obj)
    assert result["revoked"] is True
    assert result["deprecated"] is True
    assert result["raw_payload"]["custom_field"] == "custom_value"


def test_normalize_stix_bundle_groups_by_type():
    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-1234-1234-123456789012",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--12345678-1234-1234-1234-123456789012",
                "name": "APT28",
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--12345678-1234-1234-1234-123456789012",
                "name": "Phishing",
            },
        ],
    }
    result = normalize_stix_bundle(bundle)
    assert len(result["actors"]) == 1
    assert len(result["techniques"]) == 1
    assert result["bundle_metadata"]["object_count"] == 2


def test_validate_valid_intrusion_set():
    validate_stix_object(
        {
            "type": "intrusion-set",
            "id": "intrusion-set--12345678-1234-1234-1234-123456789012",
            "name": "APT28",
        }
    )


def test_validate_unsupported_type():
    with pytest.raises(ValidationError):
        validate_stix_object(
            {
                "type": "marking-definition",
                "id": "marking-definition--12345678-1234-1234-1234-123456789012",
                "name": "TLP:RED",
            }
        )


def test_validate_missing_required_field():
    with pytest.raises(ValidationError):
        validate_stix_object(
            {
                "type": "intrusion-set",
                "id": "intrusion-set--12345678-1234-1234-1234-123456789012",
            }
        )


def test_validate_invalid_id_prefix():
    with pytest.raises(ValidationError):
        validate_stix_object(
            {
                "type": "intrusion-set",
                "id": "wrong-prefix--12345678-1234-1234-1234-123456789012",
                "name": "Test",
            }
        )


def test_validate_relationship_endpoints():
    rel = {
        "type": "relationship",
        "id": "relationship--12345678-1234-1234-1234-123456789012",
        "name": "APT28 uses Phishing",
        "source_ref": "intrusion-set--12345678-1234-1234-1234-123456789012",
        "target_ref": "attack-pattern--12345678-1234-1234-1234-123456789012",
        "relationship_type": "uses",
    }
    ids = [rel["source_ref"], rel["target_ref"]]
    validate_stix_relationship(rel, ids)

    with pytest.raises(ValidationError):
        validate_stix_relationship({**rel, "target_ref": "intrusion-set--missing"}, ids)


def test_validate_stix_bundle_summary():
    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-1234-1234-123456789012",
        "objects": [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--12345678-1234-1234-1234-123456789012",
                "name": "APT28",
            }
        ],
    }
    result = validate_stix_bundle(bundle)
    assert result["valid"] is True
    assert result["object_count"] == 1
    assert result["supported_object_count"] == 1
    assert result["unsupported_object_count"] == 0
    assert result["errors"] == []


def test_deduplicator_creates_then_reuses_actor():
    db = SessionLocal()
    try:
        dedup = Deduplicator(db)
        external_id = f"intrusion-set--{uuid4().hex}"
        entity, created = dedup.find_or_create_actor(
            external_id=external_id,
            defaults={
                "primary_handle": "Dedup APT",
                "threat_category": "APT",
                "origin": "external",
                "internal_id": external_id,
            },
        )
        assert created is True
        again, created_again = dedup.find_or_create_actor(
            external_id=external_id,
            defaults={
                "primary_handle": "Dedup APT Renamed",
                "threat_category": "APT",
                "origin": "external",
                "internal_id": external_id,
            },
        )
        assert created_again is False
        assert again.id == entity.id
        assert db.query(Actor).filter(Actor.external_id == external_id).count() == 1
        db.delete(entity)
        db.commit()
    finally:
        db.close()


def test_deduplicator_prevents_duplicate_relationships():
    db = SessionLocal()
    try:
        a1 = Actor(
            internal_id=f"TA-{uuid4().hex[:8].upper()}",
            primary_handle="dedup_rel_1",
            origin="external",
        )
        a2 = Actor(
            internal_id=f"TA-{uuid4().hex[:8].upper()}",
            primary_handle="dedup_rel_2",
            origin="external",
        )
        db.add_all([a1, a2])
        db.commit()
        db.refresh(a1)
        db.refresh(a2)

        dedup = Deduplicator(db)
        defaults = {"evidence": "test", "relationship_classification": "documented"}
        rel1, created1 = dedup.find_or_create_relationship(
            "actor", a1.id, "actor", a2.id, "USES", defaults
        )
        rel2, created2 = dedup.find_or_create_relationship(
            "actor", a1.id, "actor", a2.id, "USES", defaults
        )
        assert created1 is True
        assert created2 is False
        assert rel2.id == rel1.id
        db.delete(rel1)
        db.delete(a1)
        db.delete(a2)
        db.commit()
    finally:
        db.close()


def _mitre_bundle():
    suffix = uuid4().hex
    intrusion_id = f"intrusion-set--{suffix}"
    attack_id = f"attack-pattern--{suffix}"
    tactic_id = f"x-mitre-tactic--{suffix}"
    return {
        "type": "bundle",
        "id": f"bundle--{suffix}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "intrusion-set",
                "id": intrusion_id,
                "name": f"Test APT {suffix[:6]}",
                "description": "A test threat group",
                "external_references": [
                    {"source_name": "mitre-attack", "url": "https://attack.mitre.org/groups/G0001"}
                ],
                "created": "2020-01-01T00:00:00Z",
                "modified": "2021-01-01T00:00:00Z",
            },
            {
                "type": "attack-pattern",
                "id": attack_id,
                "name": f"Test Technique {suffix[:6]}",
                "description": "A test technique",
                "external_references": [],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "x-mitre-tactic",
                "id": tactic_id,
                "name": f"Test Tactic {suffix[:6]}",
                "description": "A test tactic",
                "external_references": [],
            },
            {
                "type": "relationship",
                "id": f"relationship--{suffix}",
                "source_ref": intrusion_id,
                "target_ref": attack_id,
                "relationship_type": "uses",
                "external_references": [],
            },
        ],
    }


def test_mitre_adapter_imports_entities_tactics_and_relationships():
    db = SessionLocal()
    try:
        adapter = MitreAttackAdapter(db=db, stix_url="https://example.com/attack.json")
        adapter.fetch = lambda: [_mitre_bundle()]
        result = adapter.run()

        assert result["records_imported"] >= 3, result
        assert result["relationships_created"] >= 1
        assert result["errors"] == []

        source = (
            db.query(IntelligenceSource)
            .filter(IntelligenceSource.name == "mitre-attack-enterprise")
            .first()
        )
        assert source is not None
        assert source.origin == "external"
        assert source.is_synthetic is False

        assert db.query(Tactic).filter(Tactic.name.like("Test Tactic%")).first() is not None
        assert (
            db.query(Technique).filter(Technique.name.like("Test Technique%")).first()
            is not None
        )

        actor = db.query(Actor).filter(Actor.primary_handle.like("Test APT%")).first()
        assert actor is not None
        assert actor.origin == "external"
        evidence = (
            db.query(Evidence)
            .filter(Evidence.entity_type == "actor", Evidence.entity_id == actor.id)
            .first()
        )
        assert evidence is not None
        assert evidence.raw_payload.get("type") == "intrusion-set"
    finally:
        db.close()


def test_mitre_adapter_reimport_is_idempotent():
    db = SessionLocal()
    try:
        bundle = _mitre_bundle()
        first_adapter = MitreAttackAdapter(db=db, stix_url="https://example.com/attack.json")
        first_adapter.fetch = lambda: [bundle]
        first = first_adapter.run()

        second_adapter = MitreAttackAdapter(db=db, stix_url="https://example.com/attack.json")
        second_adapter.fetch = lambda: [bundle]
        second = second_adapter.run()

        assert first["records_imported"] >= 3
        assert second["relationships_created"] == 0
        group_name = [
            obj["name"] for obj in bundle["objects"] if obj["type"] == "intrusion-set"
        ][0]
        assert db.query(Actor).filter(Actor.primary_handle == group_name).count() == 1
    finally:
        db.close()


def test_mitre_adapter_fetch_failure_marks_job_failed():
    from app.ingestion.base import FetchError

    db = SessionLocal()
    try:
        adapter = MitreAttackAdapter(db=db, stix_url="https://unreachable.example/x.json")

        def _boom():
            raise FetchError("simulated network failure")

        adapter.fetch = _boom
        result = adapter.run()
        assert result["records_imported"] == 0
        assert result["errors"]

        job = (
            db.query(CollectionJob)
            .filter(CollectionJob.source_name == "mitre-attack-enterprise")
            .order_by(CollectionJob.id.desc())
            .first()
        )
        assert job is not None
        assert job.status == "failed"
    finally:
        db.close()


def test_mitre_api_endpoint_success(client, admin_headers):
    with patch.object(MitreAttackAdapter, "run") as mock_run:
        mock_run.return_value = {
            "source_name": "mitre-attack-enterprise",
            "records_imported": 3,
            "relationships_created": 1,
            "relationships_skipped": 0,
            "errors": [],
        }
        response = client.post("/api/ingestion/mitre-attack", json={}, headers=admin_headers)
        assert response.status_code == 200, response.text
        assert response.json()["records_imported"] == 3


def test_mitre_api_endpoint_failure(client, admin_headers):
    with patch.object(MitreAttackAdapter, "run") as mock_run:
        mock_run.side_effect = Exception("Network error")
        response = client.post("/api/ingestion/mitre-attack", json={}, headers=admin_headers)
        assert response.status_code == 500
        assert "Network error" in response.json()["detail"]


def test_mitre_api_requires_admin(client, analyst_headers):
    response = client.post("/api/ingestion/mitre-attack", json={}, headers=analyst_headers)
    assert response.status_code == 403
