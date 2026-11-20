"""Idempotent demonstration data seed.

Six documented scenarios are created (or completed if they already exist):

1. Two accounts sharing a PGP fingerprint           (ghostsec / ciphermoth)
2. Similar writing patterns                          (redpanda / blackpanda)
3. Similar hourly behaviour                          (nightshade / darkshade)
4. Marketplace migration                             (migrator)
5. Superficially similar but unrelated accounts      (alpha1 / beta2)
6. Conflicting evidence                              (conflict_a / conflict_b)

Every record is explicitly marked ``origin='synthetic'`` /
``is_synthetic=True``. The script never deletes data and never creates a second
copy of a record it already created: it looks up each entity before inserting.
"""

import argparse
import datetime as dt
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.core.config import get_settings
from app.core.security import hash_password
from app.core.time import utcnow
from app.database.session import Base, SessionLocal, engine
from app.ml.behavioural import behavioural_similarity
from app.ml.stylometry import stylometric_similarity
from app.models.entities import (
    Actor,
    AnalysisResult,
    AnalystReview,
    Evidence,
    Handle,
    Identifier,
    IntelligenceSource,
    Investigation,
    InvestigationEntity,
    Relationship,
    TimelineEvent,
    User,
)
from app.services.relationship_engine import build_direct_relationships, build_inferred_relationships

Base.metadata.create_all(bind=engine)


def _require_demo_consent() -> None:
    """Synthetic demonstration data is opt-in only.

    The production application must contain genuine intelligence only. This
    script therefore refuses to run unless the operator explicitly asks for the
    demonstration dataset.
    """
    parser = argparse.ArgumentParser(description="Insert the synthetic demonstration dataset.")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="required: confirms that labelled synthetic demonstration data may be inserted",
    )
    args = parser.parse_args()
    if get_settings().environment == "production":
        print(
            "Refusing to seed: ENVIRONMENT=production must contain genuine intelligence\n"
            "only. Demonstration data is limited to development and test databases.\n"
        )
        raise SystemExit(2)
    if args.demo or os.environ.get("ALLOW_SYNTHETIC_SEED", "").strip().lower() in ("1", "true", "yes"):
        return
    print(
        "Refusing to seed: this script inserts SYNTHETIC demonstration records that are not\n"
        "real intelligence. Re-run with --demo (development/demo environments only), or\n"
        "import genuine data with the feed connectors instead.\n"
    )
    raise SystemExit(2)


_require_demo_consent()

db = SessionLocal()
counts = {"created": 0, "reused": 0}


def ensure_user(username: str, password: str, role: str) -> None:
    if not db.query(User).filter(User.username == username).first():
        db.add(User(username=username, hashed_password=hash_password(password), role=role))
        db.commit()
        counts["created"] += 1


def ensure_source(name: str, source_type: str, reliability: float) -> IntelligenceSource:
    source = (
        db.query(IntelligenceSource)
        .filter(IntelligenceSource.name == name, IntelligenceSource.is_synthetic.is_(True))
        .order_by(IntelligenceSource.id)
        .first()
    )
    if source:
        counts["reused"] += 1
        return source
    source = IntelligenceSource(
        name=name,
        source_type=source_type,
        reliability=reliability,
        is_synthetic=True,
        origin="synthetic",
        collected_at=utcnow(),
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    counts["created"] += 1
    return source


def ensure_actor(handle: str, category: str, status: str = "open", notes: str = None) -> Actor:
    actor = (
        db.query(Actor)
        .filter(Actor.primary_handle == handle, Actor.origin == "synthetic")
        .order_by(Actor.id)
        .first()
    )
    if actor:
        counts["reused"] += 1
        return actor
    actor = Actor(
        internal_id=f"TA{uuid.uuid4().hex[:8].upper()}",
        primary_handle=handle,
        threat_category=category,
        investigation_status=status,
        notes=notes,
        last_observed=utcnow(),
        origin="synthetic",
    )
    db.add(actor)
    db.commit()
    db.refresh(actor)
    counts["created"] += 1
    return actor


def ensure_handle(actor: Actor, handle: str, marketplace: str, first, last) -> None:
    exists = (
        db.query(Handle)
        .filter(
            Handle.actor_id == actor.id,
            Handle.handle == handle,
            Handle.marketplace == marketplace,
        )
        .first()
    )
    if exists:
        counts["reused"] += 1
        return
    db.add(
        Handle(
            actor_id=actor.id,
            handle=handle,
            marketplace=marketplace,
            first_seen=first,
            last_seen=last,
        )
    )
    db.commit()
    counts["created"] += 1


def ensure_identifier(actor: Actor, id_type: str, value: str, source: str, reliability: float = 0.8) -> None:
    exists = (
        db.query(Identifier)
        .filter(
            Identifier.actor_id == actor.id,
            Identifier.id_type == id_type,
            Identifier.value == value,
        )
        .first()
    )
    if exists:
        counts["reused"] += 1
        return
    db.add(
        Identifier(
            actor_id=actor.id,
            id_type=id_type,
            value=value,
            source=source,
            reliability=reliability,
            origin="synthetic",
        )
    )
    db.commit()
    counts["created"] += 1


def ensure_evidence(actor: Actor, source: IntelligenceSource, evidence_type: str, content: str, reference: str, reliability: float = 0.7) -> None:
    exists = (
        db.query(Evidence)
        .filter(
            Evidence.source_id == source.id,
            Evidence.evidence_type == evidence_type,
            Evidence.content == content,
            (Evidence.actor_id == actor.id)
            | ((Evidence.entity_type == "actor") & (Evidence.entity_id == actor.id)),
        )
        .first()
    )
    if exists:
        counts["reused"] += 1
        return
    db.add(
        Evidence(
            actor_id=actor.id,
            source_id=source.id,
            entity_type="actor",
            entity_id=actor.id,
            evidence_type=evidence_type,
            content=content,
            reference=reference,
            source_description=f"Synthetic demonstration record from {source.name}",
            reliability=reliability,
            raw_payload={"synthetic": True, "source": source.name},
            collected_at=utcnow(),
        )
    )
    db.commit()
    counts["created"] += 1


def ensure_event(actor: Actor, event_type: str, description: str, event_date, source: str) -> None:
    exists = (
        db.query(TimelineEvent)
        .filter(
            TimelineEvent.actor_id == actor.id,
            TimelineEvent.event_date == event_date,
            TimelineEvent.event_type == event_type,
        )
        .first()
    )
    if exists:
        counts["reused"] += 1
        return
    db.add(
        TimelineEvent(
            actor_id=actor.id,
            event_type=event_type,
            description=description,
            event_date=event_date,
            source=source,
        )
    )
    db.commit()
    counts["created"] += 1


def ensure_analysis(actor_a: Actor, actor_b: Actor, analysis_type: str, score: float, details: dict) -> None:
    exists = (
        db.query(AnalysisResult)
        .filter(
            AnalysisResult.actor_a_id == actor_a.id,
            AnalysisResult.actor_b_id == actor_b.id,
            AnalysisResult.analysis_type == analysis_type,
        )
        .first()
    )
    if exists:
        counts["reused"] += 1
        return
    db.add(
        AnalysisResult(
            actor_a_id=actor_a.id,
            actor_b_id=actor_b.id,
            analysis_type=analysis_type,
            score=score,
            details=details,
        )
    )
    db.commit()
    counts["created"] += 1


# ---------------------------------------------------------------------------
# Accounts and sources
# ---------------------------------------------------------------------------
ensure_user("admin", "admin123", "admin")
ensure_user("analyst", "analyst123", "analyst")

src1 = ensure_source("Synthetic Demo Feed 1", "synthetic", 0.7)
src2 = ensure_source("Synthetic Demo Feed 2", "synthetic", 0.6)

# ---------------------------------------------------------------------------
# Scenario 1: shared PGP fingerprint (direct relationship)
# ---------------------------------------------------------------------------
ghostsec = ensure_actor("ghostsec", "APT", notes="Synthetic demonstration actor (Scenario 1)")
ciphermoth = ensure_actor("ciphermoth", "APT", notes="Synthetic demonstration actor (Scenario 1)")
shared_pgp = "ABCD1234EFGH5678IJKL9012MNOP3456QRST7890"
ensure_handle(ghostsec, "ghostsec", "ForumX", dt.datetime(2023, 1, 1), dt.datetime(2024, 6, 1))
ensure_handle(ciphermoth, "ciphermoth", "ForumX", dt.datetime(2023, 3, 1), dt.datetime(2024, 7, 1))
ensure_identifier(ghostsec, "pgp", shared_pgp, "PGP keyserver (synthetic)")
ensure_identifier(ciphermoth, "pgp", shared_pgp, "PGP keyserver (synthetic)")
ensure_identifier(ghostsec, "email", "ghost.ops@example.invalid", "Synthetic forum profile")
ensure_identifier(ciphermoth, "email", "ghost.ops@example.invalid", "Synthetic forum profile")
ensure_event(ghostsec, "registration", "Registered on ForumX", dt.datetime(2023, 1, 1), "Synthetic market log")
ensure_event(ciphermoth, "registration", "Registered on ForumX", dt.datetime(2023, 3, 1), "Synthetic market log")
ensure_evidence(
    ghostsec,
    src1,
    "text_sample",
    (
        "Key announcement for the shared escrow account. The fingerprint is published below "
        "so buyers can verify signed messages. Use the usual channel for disputes and keep "
        "all confirmations inside the marketplace escrow flow."
    ),
    "Synthetic key announcement A",
    0.7,
)
ensure_evidence(
    ciphermoth,
    src2,
    "text_sample",
    (
        "Key announcement for the shared escrow account. The fingerprint is published below "
        "so buyers can verify signed messages. Disputes go through the usual channel and all "
        "confirmations stay inside the marketplace escrow flow."
    ),
    "Synthetic key announcement B",
    0.6,
)

# ---------------------------------------------------------------------------
# Scenario 2: similar writing patterns
# ---------------------------------------------------------------------------
redpanda = ensure_actor("redpanda", "FinCrime", notes="Synthetic demonstration actor (Scenario 2)")
blackpanda = ensure_actor("blackpanda", "FinCrime", notes="Synthetic demonstration actor (Scenario 2)")
ensure_handle(redpanda, "redpanda", "MarketY", dt.datetime(2023, 2, 1), dt.datetime(2024, 1, 1))
ensure_handle(blackpanda, "blackpanda", "MarketY", dt.datetime(2023, 5, 1), dt.datetime(2024, 2, 1))
sample_2 = (
    "The operation proceeded according to plan. Coordination was established via the usual "
    "channel. All parties confirmed receipt of the package. Further instructions will follow "
    "at the scheduled time. Keep the transfer split across the usual wallets and confirm when "
    "each leg settles."
)
ensure_evidence(redpanda, src1, "text_sample", sample_2, "Synthetic forum post A", 0.7)
ensure_evidence(blackpanda, src2, "text_sample", sample_2, "Synthetic forum post B", 0.6)

# ---------------------------------------------------------------------------
# Scenario 3: similar hourly behaviour
# ---------------------------------------------------------------------------
nightshade = ensure_actor("nightshade", "DataTheft", notes="Synthetic demonstration actor (Scenario 3)")
darkshade = ensure_actor("darkshade", "DataTheft", notes="Synthetic demonstration actor (Scenario 3)")
for stamp in [
    "2024-01-10T02:00:00",
    "2024-01-10T02:30:00",
    "2024-01-11T03:00:00",
    "2024-01-12T02:15:00",
]:
    for actor in (nightshade, darkshade):
        ensure_event(
            actor,
            "post",
            "Night-time forum activity",
            dt.datetime.fromisoformat(stamp),
            "Synthetic market log",
        )

# ---------------------------------------------------------------------------
# Scenario 4: marketplace migration
# ---------------------------------------------------------------------------
migrator = ensure_actor("migrator", "Hacktivist", notes="Synthetic demonstration actor (Scenario 4)")
ensure_handle(migrator, "migrator_old", "OldMarket", dt.datetime(2023, 1, 1), dt.datetime(2023, 12, 1))
ensure_handle(migrator, "migrator_new", "NewMarket", dt.datetime(2024, 1, 15), dt.datetime(2024, 6, 1))
ensure_event(
    migrator,
    "migration",
    "Moved from OldMarket to NewMarket",
    dt.datetime(2024, 1, 15),
    "Synthetic market log",
)

# ---------------------------------------------------------------------------
# Scenario 5: superficially similar, unrelated writing
# ---------------------------------------------------------------------------
alpha1 = ensure_actor("alpha1", "Other", notes="Synthetic demonstration actor (Scenario 5)")
beta2 = ensure_actor("beta2", "Other", notes="Synthetic demonstration actor (Scenario 5)")
sample_5 = (
    "Hello everyone. I am new here. I like to read posts and learn. Thank you for the welcome. "
    "I hope to contribute soon."
)
ensure_evidence(alpha1, src1, "text_sample", sample_5, "Synthetic intro post A", 0.5)
ensure_evidence(beta2, src2, "text_sample", sample_5, "Synthetic intro post B", 0.5)

# ---------------------------------------------------------------------------
# Scenario 6: conflicting evidence (shared wallet, different writing)
# ---------------------------------------------------------------------------
conflict_a = ensure_actor("conflict_a", "Fraud", notes="Synthetic demonstration actor (Scenario 6)")
conflict_b = ensure_actor("conflict_b", "Fraud", notes="Synthetic demonstration actor (Scenario 6)")
shared_wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
ensure_identifier(conflict_a, "wallet", shared_wallet, "Blockchain explorer (synthetic)")
ensure_identifier(conflict_b, "wallet", shared_wallet, "Blockchain explorer (synthetic)")
ensure_evidence(
    conflict_a,
    src1,
    "text_sample",
    "Completely different writing style here. Short sentences. No flourish.",
    "Synthetic post A",
    0.4,
)
ensure_evidence(
    conflict_b,
    src2,
    "text_sample",
    "The operation proceeded according to plan. Coordination was established via the usual channel.",
    "Synthetic post B",
    0.4,
)

# ---------------------------------------------------------------------------
# Analysis results (derived from the seeded samples, not hardcoded)
# ---------------------------------------------------------------------------
db.commit()

texts_red = " ".join(
    e.content or ""
    for e in db.query(Evidence).filter(Evidence.actor_id == redpanda.id, Evidence.evidence_type == "text_sample").all()
)
texts_black = " ".join(
    e.content or ""
    for e in db.query(Evidence).filter(Evidence.actor_id == blackpanda.id, Evidence.evidence_type == "text_sample").all()
)
if texts_red and texts_black:
    style_score, style_details = stylometric_similarity(texts_red, texts_black)
    ensure_analysis(
        redpanda,
        blackpanda,
        "stylometric",
        style_score,
        {
            "tfidf_cosine": style_details.get("tfidf_cosine"),
            "feature_similarity": style_details.get("feature_similarity"),
            "note": "Seed-generated demonstration analysis; synthetic text samples.",
            "synthetic": True,
        },
    )

beh_score, beh_details = behavioural_similarity(nightshade.id, darkshade.id, db)
if beh_details.get("cosine") is not None:
    ensure_analysis(
        nightshade,
        darkshade,
        "behavioural",
        beh_score,
        {
            "cosine": beh_details.get("cosine"),
            "activity_count_a": beh_details.get("activity_count_a"),
            "activity_count_b": beh_details.get("activity_count_b"),
            "note": "Seed-generated demonstration analysis; synthetic timeline events.",
            "synthetic": True,
        },
    )

# ---------------------------------------------------------------------------
# Relationship generation from the seeded evidence
# ---------------------------------------------------------------------------
direct = build_direct_relationships(db)
inferred = build_inferred_relationships(db)

# ---------------------------------------------------------------------------
# Demonstration investigation with a pending analyst decision
# ---------------------------------------------------------------------------
investigation = db.query(Investigation).filter(Investigation.title == "Operation Shared Fingerprint").first()
if investigation is None:
    investigation = Investigation(
        title="Operation Shared Fingerprint",
        status="review",
        notes="Synthetic demonstration case: assess the significance of a shared PGP fingerprint.",
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    counts["created"] += 1
else:
    counts["reused"] += 1

for actor in (ghostsec, ciphermoth):
    exists = (
        db.query(InvestigationEntity)
        .filter(
            InvestigationEntity.investigation_id == investigation.id,
            InvestigationEntity.actor_id == actor.id,
        )
        .first()
    )
    if not exists:
        db.add(InvestigationEntity(investigation_id=investigation.id, actor_id=actor.id))
        db.commit()
        counts["created"] += 1

shared_rel = (
    db.query(Relationship)
    .filter(
        Relationship.rel_type == "SHARED_IDENTIFIER",
        Relationship.source_actor_id.in_([ghostsec.id, ciphermoth.id]),
        Relationship.target_actor_id.in_([ghostsec.id, ciphermoth.id]),
    )
    .first()
)
if shared_rel and not db.query(AnalystReview).filter(
    AnalystReview.investigation_id == investigation.id,
    AnalystReview.relationship_id == shared_rel.id,
).first():
    db.add(
        AnalystReview(
            relationship_id=shared_rel.id,
            investigation_id=investigation.id,
            analyst="admin",
            decision="pending",
            notes="Synthetic demo: confirm whether the shared fingerprint is corroborated.",
        )
    )
    db.commit()
    counts["created"] += 1

print("Seed complete.")
print(f"  actors={db.query(Actor).count()} identifiers={db.query(Identifier).count()} "
      f"evidence={db.query(Evidence).count()} relationships={db.query(Relationship).count()}")
print(f"  direct relationships created/verified: {direct}")
print(f"  inferred relationships created: {inferred}")
print(f"  records created={counts['created']} reused={counts['reused']}")
print("  demo accounts: admin/admin123 (admin), analyst/analyst123 (analyst)")
db.close()
