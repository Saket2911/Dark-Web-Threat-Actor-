"""Genuine-source connectors, provenance and synthetic-data isolation."""

from datetime import datetime
from uuid import uuid4

import pytest

from app.database.session import SessionLocal
from app.core.provenance import hide_synthetic_analyses, hide_synthetic_relationships
from app.ingestion import feeds
from app.ingestion.feeds import FeedAuthRequired, ingest_feed
from app.models.entities import (
    Actor,
    AnalysisResult,
    CollectionJob,
    Evidence,
    InfrastructureIndicator,
    IntelligenceSource,
    Investigation,
    InvestigationEntity,
)


# ---------------------------------------------------------------------------
# APTnotes
# ---------------------------------------------------------------------------
def test_parse_aptnotes_record_uses_published_field_names():
    record = {
        "Filename": "WickedRose_andNCPH",
        "Title": '"Wicked Rose" And The Ncph Hacking Group',
        "Source": "iDefense",
        "Link": "https://example.invalid/report.pdf",
        "SHA-1": "e802d6f06085f22242a66b06c785f8f4b6d9a6f4",
        "Date": "2017-06-01",
        "Year": "2017",
    }
    parsed = feeds.parse_aptnotes_record(record)

    assert parsed["external_id"] == "WickedRose_andNCPH"
    assert parsed["title"].startswith('"Wicked Rose"')
    assert parsed["publisher"] == "iDefense"
    assert parsed["link"] == "https://example.invalid/report.pdf"
    assert parsed["published"].date().isoformat() == "2017-06-01"


def test_parse_aptnotes_record_does_not_invent_missing_fields():
    parsed = feeds.parse_aptnotes_record({"Filename": "only_filename"})

    assert parsed["external_id"] == "only_filename"
    assert parsed["title"] is None
    assert parsed["publisher"] is None
    assert parsed["link"] is None
    assert parsed["published"] is None


def test_aptnotes_ingestion_is_real_and_idempotent(monkeypatch):
    suffix = uuid4().hex[:6]
    records = [
        {
            "Filename": f"report_{suffix}_a",
            "Title": f"Public APT report {suffix} A",
            "Source": "Example CERT",
            "Link": f"https://example.invalid/{suffix}/a.pdf",
            "SHA-1": "a" * 40,
            "Date": "2024-03-04",
            "Year": "2024",
        },
        {
            "Filename": f"report_{suffix}_b",
            "Title": f"Public APT report {suffix} B",
            "Source": "Example CERT",
            "Link": f"https://example.invalid/{suffix}/b.pdf",
            "Date": "2025-01-02",
            "Year": "2025",
        },
    ]
    monkeypatch.setattr(feeds, "_http_json", lambda *a, **k: (records, None))

    db = SessionLocal()
    try:
        first = ingest_feed(db, "aptnotes")
        db.commit()
        assert first["fetched"] == 2
        assert first["imported"] == 2
        assert first["rejected"] == 0

        stored = (
            db.query(Evidence)
            .filter(Evidence.external_record_id == f"report_{suffix}_a")
            .one()
        )
        assert stored.evidence_type == "report"
        assert stored.source_url == f"https://example.invalid/{suffix}/a.pdf"
        assert stored.source_published_at.date().isoformat() == "2024-03-04"
        assert stored.raw_payload["Source"] == "Example CERT"
        assert stored.entity_type is None  # no actor invented from a title

        second = ingest_feed(db, "aptnotes")
        db.commit()
        assert second["imported"] == 0
        assert second["duplicates"] == 2

        source = db.query(IntelligenceSource).filter(IntelligenceSource.name == "APTnotes").one()
        assert source.origin == "external"
        assert source.is_synthetic is False
    finally:
        db.close()


def test_aptnotes_direct_call_creates_tracked_job_and_stamps_evidence(monkeypatch):
    suffix = uuid4().hex[:6]
    records = [
        {
            "Filename": f"tracked_{suffix}",
            "Title": f"Tracked report {suffix}",
            "Source": "Example CERT",
            "Link": f"https://example.invalid/{suffix}/tracked.pdf",
            "Date": "2024-06-01",
        }
    ]
    monkeypatch.setattr(feeds, "_http_json", lambda *a, **k: (records, None))

    db = SessionLocal()
    try:
        result = ingest_feed(db, "aptnotes")
        db.commit()
        job_id = result["job_id"]
        assert job_id is not None

        job = db.query(CollectionJob).filter(CollectionJob.id == job_id).one()
        assert job.source_key == "aptnotes"
        assert job.status == "completed"
        assert job.records_fetched == 1
        assert job.records_imported == 1
        assert job.relationships_created == 0

        evidence = (
            db.query(Evidence)
            .filter(Evidence.external_record_id == f"tracked_{suffix}")
            .one()
        )
        assert evidence.import_job_id == job_id
        source = (
            db.query(IntelligenceSource)
            .filter(IntelligenceSource.id == evidence.source_id)
            .one()
        )
        assert source.name == "APTnotes"
        assert evidence.source_url == f"https://example.invalid/{suffix}/tracked.pdf"
        assert evidence.external_record_id == f"tracked_{suffix}"

        repeat = ingest_feed(db, "aptnotes")
        db.commit()
        repeat_job = db.query(CollectionJob).filter(CollectionJob.id == repeat["job_id"]).one()
        assert repeat["imported"] == 0
        assert repeat_job.status == "completed_no_changes"
        assert repeat_job.records_skipped >= 1
    finally:
        db.close()


def test_aptnotes_links_only_external_actors_named_in_title(monkeypatch):
    suffix = uuid4().hex[:6]
    db = SessionLocal()
    try:
        real = Actor(
            internal_id=f"TA-REAL-{suffix}",
            primary_handle=f"Group{suffix}",
            aliases=[f"Alias{suffix}"],
            origin="external",
            external_id=f"intrusion-set--{suffix}",
        )
        fake = Actor(
            internal_id=f"TA-FAKE-{suffix}",
            primary_handle=f"Fake{suffix}",
            origin="synthetic",
        )
        db.add_all([real, fake])
        db.commit()

        records = [
            {
                "Filename": f"names_real_{suffix}",
                "Title": f"Report on Group{suffix} operations",
                "Source": "Example CERT",
                "Link": "https://example.invalid/real.pdf",
                "Date": "2024-01-01",
            },
            {
                "Filename": f"names_fake_{suffix}",
                "Title": f"Report on Fake{suffix} operations",
                "Source": "Example CERT",
                "Link": "https://example.invalid/fake.pdf",
                "Date": "2024-01-02",
            },
        ]
        monkeypatch.setattr(feeds, "_http_json", lambda *a, **k: (records, None))

        result = ingest_feed(db, "aptnotes")
        db.commit()
        assert result["linked_to_actor"] == 1

        linked = db.query(Evidence).filter(Evidence.external_record_id == f"names_real_{suffix}").one()
        assert linked.entity_type == "actor" and linked.entity_id == real.id

        unlinked = db.query(Evidence).filter(Evidence.external_record_id == f"names_fake_{suffix}").one()
        assert unlinked.entity_type is None  # synthetic actors never receive external evidence
    finally:
        db.close()


# ---------------------------------------------------------------------------
# abuse.ch connectors
# ---------------------------------------------------------------------------
def test_urlhaus_requires_auth_key(monkeypatch):
    monkeypatch.setattr(feeds, "_auth_key", lambda: "")
    db = SessionLocal()
    try:
        with pytest.raises(FeedAuthRequired) as excinfo:
            ingest_feed(db, "urlhaus")
        assert "ABUSE_CH_AUTH_KEY" in str(excinfo.value)
    finally:
        db.close()


def test_threatfox_requires_auth_key(monkeypatch):
    monkeypatch.setattr(feeds, "_auth_key", lambda: "")
    db = SessionLocal()
    try:
        with pytest.raises(FeedAuthRequired) as excinfo:
            ingest_feed(db, "threatfox")
        assert "blocked_missing_credentials" in str(excinfo.value)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Synthetic-data isolation
# ---------------------------------------------------------------------------
def _make_actor(origin: str, prefix: str):
    db = SessionLocal()
    try:
        suffix = uuid4().hex[:8]
        actor = Actor(
            internal_id=f"TA-{suffix.upper()}",
            primary_handle=f"{prefix}_{suffix}",
            origin=origin,
        )
        db.add(actor)
        db.commit()
        db.refresh(actor)
        return actor.id, actor.primary_handle
    finally:
        db.close()


def test_actor_list_hides_synthetic_by_default(client, admin_headers):
    _, real_handle = _make_actor("manual", "isolation_real")
    _, fake_handle = _make_actor("synthetic", "isolation_fake")

    default = client.get("/api/actors?page_size=100", headers=admin_headers)
    handles = [item["primary_handle"] for item in default.json()["items"]]
    assert real_handle in handles
    assert fake_handle not in handles

    included = client.get(
        "/api/actors?page_size=100&include_synthetic=true", headers=admin_headers
    )
    assert fake_handle in [item["primary_handle"] for item in included.json()["items"]]


def test_synthetic_actor_profile_is_hidden(client, admin_headers):
    fake_id, _ = _make_actor("synthetic", "profile_fake")

    assert client.get(f"/api/actors/{fake_id}/profile", headers=admin_headers).status_code == 404
    assert (
        client.get(
            f"/api/actors/{fake_id}/profile?include_synthetic=true", headers=admin_headers
        ).status_code
        == 200
    )


def test_dashboard_counts_exclude_synthetic(client, admin_headers):
    _make_actor("synthetic", "dash_fake")
    _make_actor("manual", "dash_real")

    body = client.get("/api/dashboard/stats", headers=admin_headers).json()
    assert body["synthetic_hidden"] is True

    db = SessionLocal()
    try:
        visible = db.query(Actor).filter(Actor.origin != "synthetic").count()
    finally:
        db.close()
    assert body["actors"] == visible


def test_graph_excludes_synthetic_nodes(client, admin_headers):
    _, fake_handle = _make_actor("synthetic", "graph_fake")
    _, real_handle = _make_actor("manual", "graph_real")

    body = client.get("/api/graph/data", headers=admin_headers).json()
    labels = {node["data"].get("label") for node in body["nodes"]}
    assert real_handle in labels
    assert fake_handle not in labels
    assert "truncated" in body["stats"]


def test_dashboard_hides_synthetic_analyses_and_investigations(client, admin_headers):
    fake_id, fake_handle = _make_actor("synthetic", "dash_case_fake")
    real_id, real_handle = _make_actor("manual", "dash_case_real")

    db = SessionLocal()
    try:
        synthetic_case = Investigation(title="Synthetic case", status="review")
        real_case = Investigation(title="Genuine case", status="open")
        db.add_all([synthetic_case, real_case])
        db.flush()
        db.add_all(
            [
                InvestigationEntity(investigation_id=synthetic_case.id, actor_id=fake_id),
                InvestigationEntity(investigation_id=real_case.id, actor_id=real_id),
            ]
        )
        db.add_all(
            [
                AnalysisResult(
                    actor_a_id=fake_id, actor_b_id=real_id, analysis_type="attribution", score=0.5
                ),
                AnalysisResult(
                    actor_a_id=real_id, actor_b_id=real_id, analysis_type="attribution", score=0.4
                ),
            ]
        )
        db.commit()
        visible_analyses = hide_synthetic_analyses(db.query(AnalysisResult), False).count()
        synthetic_case_id = synthetic_case.id
        real_case_id = real_case.id
    finally:
        db.close()

    stats = client.get("/api/dashboard/stats", headers=admin_headers).json()
    assert stats["analyses"] == visible_analyses

    cases = client.get("/api/investigations", headers=admin_headers).json()
    ids = {case["id"] for case in cases}
    assert real_case_id in ids
    assert synthetic_case_id not in ids
    assert client.get(
        f"/api/investigations/{synthetic_case_id}", headers=admin_headers
    ).status_code == 404
    assert client.get(
        f"/api/investigations/{synthetic_case_id}?include_synthetic=true",
        headers=admin_headers,
    ).status_code == 200

    history = client.get("/api/analysis/history", headers=admin_headers).json()
    assert all(
        row["actor_a"] != fake_id and row["actor_b"] != fake_id for row in history
    )

    exported = client.get(
        "/api/reports/export/json?kind=investigations", headers=admin_headers
    ).json()
    exported_ids = {row["id"] for row in exported["records"]}
    assert synthetic_case_id not in exported_ids
    assert real_case_id in exported_ids


def test_legacy_relationship_without_polymorphic_fields_is_hidden(client, admin_headers):
    """Early rows keep the actor id only in source_actor_id/target_actor_id."""

    from app.models.entities import Relationship

    fake_id, _ = _make_actor("synthetic", "legacy_edge_fake")
    real_id, _ = _make_actor("manual", "legacy_edge_real")

    db = SessionLocal()
    try:
        legacy_demo = Relationship(
            source_actor_id=fake_id,
            target_actor_id=real_id,
            source_type=None,
            source_entity_id=None,
            target_type=None,
            target_entity_id=None,
            rel_type="SHARED_IDENTIFIER",
            direct=True,
        )
        legacy_real = Relationship(
            source_actor_id=real_id,
            target_actor_id=real_id,
            source_type=None,
            source_entity_id=None,
            target_type=None,
            target_entity_id=None,
            rel_type="SHARED_IDENTIFIER",
            direct=True,
        )
        db.add_all([legacy_demo, legacy_real])
        db.commit()
        real_edge_id = legacy_real.id
    finally:
        db.close()

    payload = client.get(
        "/api/reports/export/json?kind=relationships", headers=admin_headers
    ).json()
    ids = {row["id"] for row in payload["records"]}
    assert real_edge_id in ids
    assert all(row["source_actor_id"] != fake_id for row in payload["records"])

    stats = client.get("/api/dashboard/stats", headers=admin_headers).json()
    db = SessionLocal()
    try:
        visible = hide_synthetic_relationships(db.query(Relationship), False).count()
    finally:
        db.close()
    assert stats["relationships"] == visible


def test_reports_keep_genuine_evidence_without_an_entity_link(client, admin_headers):
    """Unlinked reports are genuine records and must not be hidden by NULL filters."""

    from app.models.entities import Evidence

    suffix = uuid4().hex[:6]
    db = SessionLocal()
    try:
        source = IntelligenceSource(
            name=f"Genuine source {suffix}",
            source_type="public_feed",
            reliability=0.7,
            is_synthetic=False,
            origin="external",
        )
        db.add(source)
        db.flush()
        evidence = Evidence(
            source_id=source.id,
            entity_type=None,
            entity_id=None,
            evidence_type="report",
            content=f"Unlinked genuine report {suffix}",
        )
        db.add(evidence)
        db.commit()
        evidence_id = evidence.id
    finally:
        db.close()

    payload = client.get(
        "/api/reports/export/json?kind=evidence", headers=admin_headers
    ).json()
    assert evidence_id in {row["id"] for row in payload["records"]}

    dashboard = client.get("/api/dashboard/stats", headers=admin_headers).json()
    assert dashboard["evidence"] >= 1


def test_infrastructure_detail_hides_demo_indicator(client, admin_headers):
    db = SessionLocal()
    try:
        indicator = InfrastructureIndicator(
            indicator_type="domain",
            value="example-market.com",
            source="Synthetic demo source",
            origin="synthetic",
            reliability=0.1,
        )
        db.add(indicator)
        db.commit()
        indicator_id = indicator.id
    finally:
        db.close()

    assert client.get(
        f"/api/infrastructure/{indicator_id}", headers=admin_headers
    ).status_code == 404
    assert client.get(
        f"/api/infrastructure/{indicator_id}?include_synthetic=true",
        headers=admin_headers,
    ).status_code == 200

    listing = client.get("/api/infrastructure?page_size=200", headers=admin_headers).json()
    assert indicator_id not in {row["id"] for row in listing["items"]}


def test_reports_export_excludes_synthetic(client, admin_headers):
    _, fake_handle = _make_actor("synthetic", "export_fake")
    _, real_handle = _make_actor("manual", "export_real")

    csv_body = client.get("/api/reports/export/csv?kind=actors", headers=admin_headers).text
    assert real_handle in csv_body
    assert fake_handle not in csv_body

    payload = client.get("/api/reports/export/json?kind=actors", headers=admin_headers).json()
    assert payload["synthetic_excluded"] is True
    assert fake_handle not in [row["handle"] for row in payload["records"]]
