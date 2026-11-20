"""Audit and (only with explicit approval) remove demonstration data.

Production intelligence must contain only records with traceable provenance.
This utility inventories every demonstration record, its dependents, and the
analyst artefacts that reference it, then optionally removes the records that
are provably safe to delete.

Safety rules
------------
* **Dry run by default.** Nothing is written unless ``--apply --yes`` is given.
* Demonstration records are:
  - actors with ``origin='synthetic'``, and
  - legacy demo actors from early seed runs that were stored as
    ``origin='manual'`` for one of the documented scenario handles, have no
    external identifier and no evidence from a real external source.
* A record is *blocked* (never deleted) when it is part of an investigation,
  has an analyst review or decision attached, or is compared against a real
  actor in an analysis result. Blocked records are listed for analyst review.
* Real records (``origin='external'`` or analyst-entered records with
  provenance) are never touched.
* Duplicate synthetic handles are still reported so an operator can see the
  duplicated seed history.

Usage
-----
    python scripts/dedupe_synthetic.py                 # report only
    python scripts/dedupe_synthetic.py --json          # machine-readable report
    python scripts/dedupe_synthetic.py --apply --yes   # remove safe demo rows
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, or_  # noqa: E402

from app.database.session import SessionLocal  # noqa: E402
from app.models.entities import (  # noqa: E402
    Actor,
    AnalysisResult,
    AnalystReview,
    Evidence,
    Handle,
    Identifier,
    IntelligenceSource,
    InvestigationEntity,
    Relationship,
    TimelineEvent,
)

from app.core.provenance import (  # noqa: E402  (shared definitions)
    LEGACY_DEMO_HANDLES,
    LEGACY_DEMO_INDICATOR_VALUES,
)
from app.models.entities import InfrastructureIndicator  # noqa: E402

DEMO_SOURCE_PREFIXES = ("Synthetic Demo Feed",)


def _external_evidence_count(db, actor_id: int) -> int:
    return (
        db.query(Evidence.id)
        .join(IntelligenceSource, Evidence.source_id == IntelligenceSource.id)
        .filter(
            or_(
                Evidence.actor_id == actor_id,
                (Evidence.entity_type == "actor") & (Evidence.entity_id == actor_id),
            ),
            IntelligenceSource.is_synthetic.is_(False),
        )
        .count()
    )


def classify_actors(db) -> Dict[str, List[Actor]]:
    """Split actors into synthetic, legacy demo, and everything else."""

    groups: Dict[str, List[Actor]] = {"synthetic": [], "legacy_demo": [], "real": []}
    for actor in db.query(Actor).order_by(Actor.id).all():
        if actor.origin == "synthetic":
            groups["synthetic"].append(actor)
        elif (
            actor.origin in (None, "manual")
            and (actor.primary_handle or "").strip().lower() in LEGACY_DEMO_HANDLES
            and not actor.external_id
            and _external_evidence_count(db, actor.id) == 0
        ):
            groups["legacy_demo"].append(actor)
        else:
            groups["real"].append(actor)
    return groups


def dependency_counts(db, actor_id: int) -> Dict[str, int]:
    return {
        "identifiers": db.query(Identifier).filter(Identifier.actor_id == actor_id).count(),
        "handles": db.query(Handle).filter(Handle.actor_id == actor_id).count(),
        "evidence": db.query(Evidence)
        .filter(
            or_(
                Evidence.actor_id == actor_id,
                (Evidence.entity_type == "actor") & (Evidence.entity_id == actor_id),
            )
        )
        .count(),
        "timeline": db.query(TimelineEvent).filter(TimelineEvent.actor_id == actor_id).count(),
        "relationships": db.query(Relationship)
        .filter(
            or_(
                Relationship.source_actor_id == actor_id,
                Relationship.target_actor_id == actor_id,
                (Relationship.source_type == "actor") & (Relationship.source_entity_id == actor_id),
                (Relationship.target_type == "actor") & (Relationship.target_entity_id == actor_id),
            )
        )
        .count(),
        "analyses": db.query(AnalysisResult)
        .filter(or_(AnalysisResult.actor_a_id == actor_id, AnalysisResult.actor_b_id == actor_id))
        .count(),
        "investigations": db.query(InvestigationEntity)
        .filter(InvestigationEntity.actor_id == actor_id)
        .count(),
    }


def blockers(db, actor_id: int) -> Dict[str, int]:
    """Analyst artefacts that must stop automatic deletion."""

    investigation_links = (
        db.query(InvestigationEntity).filter(InvestigationEntity.actor_id == actor_id).count()
    )
    relationship_ids = [
        row[0]
        for row in db.query(Relationship.id)
        .filter(
            or_(
                Relationship.source_actor_id == actor_id,
                Relationship.target_actor_id == actor_id,
                (Relationship.source_type == "actor") & (Relationship.source_entity_id == actor_id),
                (Relationship.target_type == "actor") & (Relationship.target_entity_id == actor_id),
            )
        )
        .all()
    ]
    reviews = 0
    if relationship_ids:
        reviews = (
            db.query(AnalystReview)
            .filter(AnalystReview.relationship_id.in_(relationship_ids))
            .count()
        )
    real_counterpart_analyses = 0
    for analysis in (
        db.query(AnalysisResult)
        .filter(or_(AnalysisResult.actor_a_id == actor_id, AnalysisResult.actor_b_id == actor_id))
        .all()
    ):
        other = analysis.actor_b_id if analysis.actor_a_id == actor_id else analysis.actor_a_id
        other_actor = db.query(Actor).filter(Actor.id == other).first() if other else None
        if other_actor and other_actor.origin not in ("synthetic", None, "manual"):
            real_counterpart_analyses += 1
    return {
        "investigation_links": investigation_links,
        "analyst_reviews": reviews,
        "analyses_with_real_counterpart": real_counterpart_analyses,
    }


def build_report(db) -> Dict:
    groups = classify_actors(db)
    demo_actors = groups["synthetic"] + groups["legacy_demo"]
    demo_ids = {actor.id for actor in demo_actors}
    real_ids = {actor.id for actor in groups["real"]}

    actor_rows = []
    for actor in demo_actors:
        dependents = dependency_counts(db, actor.id)
        blocking = blockers(db, actor.id)
        actor_rows.append(
            {
                "id": actor.id,
                "handle": actor.primary_handle,
                "origin": actor.origin,
                "label": "synthetic" if actor.origin == "synthetic" else "legacy_demo",
                "dependents": dependents,
                "blockers": blocking,
                "safe_to_remove": not any(blocking.values()),
            }
        )

    demo_sources = [
        source
        for source in db.query(IntelligenceSource).order_by(IntelligenceSource.id).all()
        if source.is_synthetic
        or (source.name or "").startswith(DEMO_SOURCE_PREFIXES)
    ]

    demo_indicators = (
        db.query(InfrastructureIndicator)
        .filter(
            or_(
                InfrastructureIndicator.origin == "synthetic",
                InfrastructureIndicator.value.in_(LEGACY_DEMO_INDICATOR_VALUES),
            )
        )
        .order_by(InfrastructureIndicator.id)
        .all()
    )

    handle_counts = Counter(
        (actor.primary_handle or "").strip().lower() for actor in demo_actors if actor.primary_handle
    )

    return {
        "database": str(db.bind.url) if db.bind is not None else None,
        "real_actors": len(groups["real"]),
        "synthetic_actors": len(groups["synthetic"]),
        "legacy_demo_actors": len(groups["legacy_demo"]),
        "demo_actors": actor_rows,
        "duplicate_demo_handles": {
            handle: count for handle, count in handle_counts.items() if count > 1
        },
        "demo_indicators": [
            {"id": row.id, "type": row.indicator_type, "value": row.value, "origin": row.origin}
            for row in demo_indicators
        ],
        "demo_sources": [
            {
                "id": source.id,
                "name": source.name,
                "origin": source.origin,
                "is_synthetic": bool(source.is_synthetic),
                "evidence_rows": db.query(Evidence).filter(Evidence.source_id == source.id).count(),
            }
            for source in demo_sources
        ],
        "real_records_touching_demo_actors": {
            "relationships": db.query(Relationship)
            .filter(
                or_(
                    (Relationship.source_type == "actor") & Relationship.source_entity_id.in_(demo_ids),
                    (Relationship.target_type == "actor") & Relationship.target_entity_id.in_(demo_ids),
                ),
                or_(
                    (Relationship.source_type != "actor")
                    | ~Relationship.source_entity_id.in_(demo_ids)
                ),
            )
            .count()
            if demo_ids
            else 0,
            "analyses": db.query(AnalysisResult)
            .filter(
                or_(
                    AnalysisResult.actor_a_id.in_(demo_ids),
                    AnalysisResult.actor_b_id.in_(demo_ids),
                )
            )
            .count()
            if demo_ids
            else 0,
            "known_real_actor_ids": sorted(real_ids)[:5],
        },
    }


def purge(db, report: Dict, keep_blocked: bool = True) -> Dict[str, int]:
    """Delete only demo records that have no analyst blockers."""

    removed = Counter()
    skipped = []

    for row in report["demo_actors"]:
        actor_id = row["id"]
        if row["blockers"] and keep_blocked:
            skipped.append({"id": actor_id, "handle": row["handle"], "blockers": row["blockers"]})
            continue
        relationship_ids = [
            rel.id
            for rel in db.query(Relationship)
            .filter(
                or_(
                    Relationship.source_actor_id == actor_id,
                    Relationship.target_actor_id == actor_id,
                    (Relationship.source_type == "actor") & (Relationship.source_entity_id == actor_id),
                    (Relationship.target_type == "actor") & (Relationship.target_entity_id == actor_id),
                )
            )
            .all()
        ]
        if relationship_ids:
            db.query(AnalystReview).filter(
                AnalystReview.relationship_id.in_(relationship_ids)
            ).delete(synchronize_session=False)
            removed["relationships"] += (
                db.query(Relationship)
                .filter(Relationship.id.in_(relationship_ids))
                .delete(synchronize_session=False)
            )
        db.query(AnalysisResult).filter(
            or_(AnalysisResult.actor_a_id == actor_id, AnalysisResult.actor_b_id == actor_id)
        ).delete(synchronize_session=False)
        db.query(Evidence).filter(
            or_(
                Evidence.actor_id == actor_id,
                (Evidence.entity_type == "actor") & (Evidence.entity_id == actor_id),
            )
        ).delete(synchronize_session=False)
        db.query(Handle).filter(Handle.actor_id == actor_id).delete(synchronize_session=False)
        db.query(Identifier).filter(Identifier.actor_id == actor_id).delete(synchronize_session=False)
        db.query(TimelineEvent).filter(TimelineEvent.actor_id == actor_id).delete(synchronize_session=False)
        db.query(InvestigationEntity).filter(
            InvestigationEntity.actor_id == actor_id
        ).delete(synchronize_session=False)
        db.query(Actor).filter(Actor.id == actor_id).delete(synchronize_session=False)
        removed["actors"] += 1

    for source in report["demo_sources"]:
        remaining = db.query(Evidence).filter(Evidence.source_id == source["id"]).count()
        if remaining:
            skipped.append(
                {"source_id": source["id"], "name": source["name"], "evidence_rows": remaining}
            )
            continue
        db.query(IntelligenceSource).filter(IntelligenceSource.id == source["id"]).delete(
            synchronize_session=False
        )
        removed["sources"] += 1

    db.commit()
    return {"removed": dict(removed), "skipped": skipped}


def print_report(report: Dict) -> None:
    print(f"Database: {report['database']}")
    print(
        f"Actors: {report['real_actors']} real, "
        f"{report['synthetic_actors']} synthetic, "
        f"{report['legacy_demo_actors']} legacy demo (stored as manual)"
    )
    print("\nDemonstration actors:")
    for row in report["demo_actors"]:
        deps = ", ".join(f"{name}={value}" for name, value in row["dependents"].items() if value)
        blocking = ", ".join(f"{name}={value}" for name, value in row["blockers"].items() if value)
        state = "SAFE TO REMOVE" if row["safe_to_remove"] else f"REQUIRES REVIEW ({blocking})"
        print(f"  {row['id']:>4}  {row['handle']:<14} {row['label']:<11} {state}")
        if deps:
            print(f"        dependents: {deps}")
    if report["duplicate_demo_handles"]:
        print("\nDuplicate demonstration handles:")
        for handle, count in sorted(report["duplicate_demo_handles"].items()):
            print(f"  {handle}: {count}")
    print("\nDemonstration sources:")
    for source in report["demo_sources"]:
        print(
            f"  {source['id']:>4}  {source['name']} "
            f"(origin={source['origin']}, synthetic={source['is_synthetic']}, "
            f"evidence={source['evidence_rows']})"
        )
        print("\nDemonstration indicators:")
    for indicator in report.get("demo_indicators", []):
        print(f"  {indicator['id']:>4}  {indicator['type']:<6} {indicator['value']} (origin={indicator['origin']})")
    print("\nAnalyses referencing demo actors: "
        f"{report['real_records_touching_demo_actors']['analyses']}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="delete records that pass the safety checks")
    parser.add_argument("--yes", action="store_true", help="required confirmation when --apply is used")
    parser.add_argument("--json", action="store_true", help="print the inventory as JSON")
    args = parser.parse_args()

    if args.apply and not args.yes:
        print("Refusing to delete: re-run with --apply --yes after reviewing the report.")
        return 2

    db = SessionLocal()
    try:
        report = build_report(db)
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print_report(report)

        if args.apply:
            result = purge(db, report)
            print("\nPurge summary:", json.dumps(result, indent=2, default=str))
        else:
            print("\nDry run only. Re-run with --apply --yes to remove the records marked SAFE TO REMOVE.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
