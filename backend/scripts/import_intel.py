"""Import genuine intelligence from the supported public sources.

Every run creates a CollectionJob and prints the real statistics: what the
source returned, what was validated, what was written, what was skipped and any
errors. Nothing is fabricated; a feed that cannot authenticate reports
``blocked_missing_credentials`` and imports nothing.

Usage
-----
    python scripts/import_intel.py --source all
    python scripts/import_intel.py --source mitre --force
    python scripts/import_intel.py --source aptnotes --limit 500

Sources
-------
* ``mitre``      MITRE ATT&CK Enterprise STIX 2.1 bundle (public)
* ``aptnotes``   APTnotes public report index (public GitHub JSON)
* ``urlhaus``    abuse.ch URLhaus API (free ABUSE_CH_AUTH_KEY required)
* ``threatfox``  abuse.ch ThreatFox API (free ABUSE_CH_AUTH_KEY required)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database.session import SessionLocal  # noqa: E402
from app.ingestion.feeds import (  # noqa: E402
    FeedAuthRequired,
    FeedUnavailableError,
    ingest_feed,
)
from app.ingestion.jobs import create_job, fail_job, finish_job, serialize_job  # noqa: E402
from app.ingestion.mitre_attack import MitreAttackAdapter  # noqa: E402


def run_mitre(db, force: bool) -> dict:
    return MitreAttackAdapter(db=db, force=force).run()


def run_feed(db, key: str, limit: int) -> dict:
    job = create_job(db, f"feed:{key}", source_key=key)
    try:
        result = ingest_feed(db, key, limit=limit, job_id=job.id)
        db.commit()
    except FeedAuthRequired as exc:
        db.rollback()
        fail_job(db, job, str(exc))
        return {"feed": key, "status": "blocked_missing_credentials", "error": str(exc)}
    except FeedUnavailableError as exc:
        db.rollback()
        fail_job(db, job, str(exc))
        return {"feed": key, "status": "failed", "error": str(exc)}
    except Exception as exc:  # unexpected connector failure
        db.rollback()
        fail_job(db, job, f"unexpected error: {exc}")
        return {"feed": key, "status": "failed", "error": str(exc)}

    finish_job(
        db,
        job,
        status="completed",
        stats={
            "records_fetched": result.get("fetched", 0),
            "records_validated": result.get("processed", 0),
            "records_imported": result.get("imported", 0),
            "records_skipped": result.get("duplicates", 0),
            "records_rejected": result.get("rejected", 0),
            "relationships_created": result.get("relationships_created", 0),
        },
        errors=result.get("errors", []),
        details={"source_url": result.get("source_url")},
    )
    return {**result, "job": serialize_job(job)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        choices=["all", "mitre", "aptnotes", "urlhaus", "threatfox"],
        default="all",
    )
    parser.add_argument("--limit", type=int, default=500, help="maximum records per feed")
    parser.add_argument("--force", action="store_true", help="ignore the stored ETag for MITRE")
    args = parser.parse_args()

    sources = (
        ["mitre", "aptnotes", "urlhaus", "threatfox"]
        if args.source == "all"
        else [args.source]
    )

    db = SessionLocal()
    try:
        for source in sources:
            print(f"\n=== {source} ===")
            if source == "mitre":
                result = run_mitre(db, args.force)
            else:
                result = run_feed(db, source, args.limit)
            print(json.dumps(result, indent=2, default=str))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
