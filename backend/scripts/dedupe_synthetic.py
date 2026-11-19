"""Detect (and optionally remove) duplicated synthetic demonstration actors.

The seed script is idempotent, but an older run created eight copies of each
demo handle. This utility reports those groups so an operator can review them.

Safety rules
------------
* Dry-run by default: nothing is written unless ``--apply --yes`` is supplied.
* Only actors with ``origin = 'synthetic'`` and duplicate ``primary_handle``
  values are considered. The lowest id in each group is kept.
* A duplicate is removed only when it has no identifiers, handles, evidence,
  timeline events, relationships, analyses or investigation links. Anything
  else is reported as skipped and must be resolved manually.

Usage
-----
    python scripts/dedupe_synthetic.py                # report only
    python scripts/dedupe_synthetic.py --apply --yes  # remove safe duplicates
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, or_  # noqa: E402

from app.database.session import SessionLocal  # noqa: E402
from app.models.entities import (  # noqa: E402
    Actor,
    AnalysisResult,
    Evidence,
    Handle,
    Identifier,
    InvestigationEntity,
    Relationship,
    TimelineEvent,
)


def dependency_counts(db, actor_id: int) -> dict:
    return {
        "identifiers": db.query(Identifier).filter(Identifier.actor_id == actor_id).count(),
        "handles": db.query(Handle).filter(Handle.actor_id == actor_id).count(),
        "evidence": db.query(Evidence)
        .filter(or_(Evidence.actor_id == actor_id, (Evidence.entity_type == "actor") & (Evidence.entity_id == actor_id)))
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="delete duplicates that pass the safety checks")
    parser.add_argument("--yes", action="store_true", help="required confirmation when --apply is used")
    args = parser.parse_args()

    if args.apply and not args.yes:
        print("Refusing to delete: re-run with --apply --yes after reviewing the report.")
        return 2

    db = SessionLocal()
    try:
        rows = (
            db.query(Actor.primary_handle, func.count(Actor.id))
            .filter(Actor.origin == "synthetic")
            .filter(Actor.primary_handle.isnot(None))
            .group_by(Actor.primary_handle)
            .having(func.count(Actor.id) > 1)
            .all()
        )
        if not rows:
            print("No duplicated synthetic handles found.")
            return 0

        removed = skipped = 0
        for handle, _count in rows:
            group = (
                db.query(Actor)
                .filter(Actor.origin == "synthetic", Actor.primary_handle == handle)
                .order_by(Actor.id)
                .all()
            )
            keep, duplicates = group[0], group[1:]
            print(f"\n{handle}: keeping actor {keep.id}, {len(duplicates)} duplicate(s)")
            for duplicate in duplicates:
                deps = dependency_counts(db, duplicate.id)
                blocking = {name: value for name, value in deps.items() if value}
                if blocking:
                    skipped += 1
                    print(f"  actor {duplicate.id}: skipped (has {blocking})")
                    continue
                print(f"  actor {duplicate.id}: safe to remove (no dependent records)")
                if args.apply:
                    db.delete(duplicate)
                    removed += 1
            if args.apply:
                db.commit()

        print(f"\nSummary: {removed} removed, {skipped} skipped.")
        if not args.apply:
            print("Dry run only. Re-run with --apply --yes to remove safe duplicates.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
