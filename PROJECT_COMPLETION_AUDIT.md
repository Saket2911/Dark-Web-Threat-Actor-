# Project Completion Audit — CN_project

Audit record for the genuine-intelligence implementation on branch `version-2`,
last updated 2026-11-19 after the provenance and job-accounting pass. Statements
below were verified against the code, the canonical SQLite database
(`backend/data/app.db`, Alembic head `d3e4f5a6b7c8`) and the running API.

## 1. Scope of this pass

The previous phase replaced synthetic-only demonstration storage with genuine public
intelligence and added provenance/job tracking. This pass closed the remaining gaps:

1. every genuine ingestion path stamps `evidence.import_job_id`, plus
   `source_modified_at` where the provider publishes a modified timestamp;
2. collection jobs persist `relationships_created`, and status reflects what was
   actually written;
3. APTnotes imports always create a tracked job, including direct connector calls;
4. demonstration records are excluded consistently from dashboard aggregates,
   analyses, investigations, infrastructure, graph, timeline and every export;
5. documentation and the environment template describe the real behaviour.

## 2. Defects found and fixed in this pass

| # | Defect | Root cause | Resolution |
| --- | --- | --- | --- |
| 1 | Evidence never carried a collection-job id | `create_evidence()` had no parameter; connectors were not passed the job | Added `import_job_id`/`source_modified_at`; MITRE and all feed connectors pass them |
| 2 | Successful MITRE relationship imports were reported `completed_empty` | Job status only looked at entity inserts | Persisted `relationships_created` (migration `d3e4f5a6b7c8`); status counts entities, updates and relationships |
| 3 | APTnotes could run without job tracking | Only API/CLI callers created jobs | `ingest_feed()` creates and finishes its own job when none is supplied, and returns `job_id` |
| 4 | NULL-typed genuine evidence disappeared from exports | SQL `NOT (... AND ...)` evaluates to NULL, excluding rows | NULL-safe provenance predicates; unlinked APTnotes reports (463) are visible again |
| 5 | Legacy relationships with NULL polymorphic fields leaked demo edges | Early rows store actor ids only in `source_actor_id`/`target_actor_id` | Endpoint filter checks both columns; dashboard returned to 19,481 genuine edges (was 19,721) |
| 6 | Dashboard counted demo investigations/analyses/sources/timeline | Counts queried whole tables | Provenance helpers applied to every aggregate and chart |
| 7 | Synthetic analyses/investigations were reachable by direct id | List filtering only | Detail routes return 404 unless `include_synthetic=true` |
| 8 | Demo indicators were reachable by direct id | No visibility check in detail | Detail/associations guarded; list and type counts share one filter |
| 9 | Demo seed could run in production | Only `--demo` consent was checked | `seed.py` now refuses when `ENVIRONMENT=production` |
| 10 | `.env.example` contained a stray `[TEMPLATE]` marker and described the key as ThreatFox-only | Historical template debt | Rewritten: no marker, both abuse.ch feeds documented, demo flag and production rule documented |

## 3. Current verified state

### Database

* Path: `backend/data/app.db`; Alembic head `d3e4f5a6b7c8`; 22 tables.
* Actors: 187 external, 58 legacy manual demo, 33 synthetic.
* Genuine relationships: 19,481 — USES 18,975, ASSOCIATED_WITH 480, ATTRIBUTED_TO 26.
* Demonstration relationships: 240 SHARED_IDENTIFIER (legacy, NULL polymorphic type) and
  3 POTENTIALLY_SAME_PERSONA.
* Evidence: 2,507 genuine (MITRE 1,820; APTnotes 687, of which 463 are unlinked
  reports), 54 demonstration.
* Indicators: 24, all demonstration; timeline events: 60, all demonstration.
* Analyses: 8, all demonstration. Investigations: 1 demonstration case with 1 pending
  analyst review — preserved, hidden from default views.
* Collection jobs: 1–5 historical MITRE/URLhaus runs, 6–7 APTnotes runs from this
  pass. Historical rows were not rewritten.

### Provenance

* New genuine evidence receives the source, external record id, original
  reference/URL, publication time, raw payload, `import_job_id` and (where published)
  `source_modified_at`.
* MITRE `modified` is stored as `source_modified_at`; APTnotes publishes no modified
  timestamp, so it remains NULL rather than being invented.
* Pre-existing rows were backfilled on 2026-11-20 from stored payloads only: 1,820 MITRE
  rows linked to job 1 with `source_modified_at` from STIX `modified`, 687 APTnotes rows
  linked to job 8 (`historical_backfill`). See `TEST_REPORT.md`.

### Job accounting

* `relationships_created` is a persisted column, exposed by the API and Settings UI.
* Statuses: `completed`, `completed_no_changes`, `completed_empty`,
  `completed_with_errors`, `not_modified`, `failed`.
* An idempotent APTnotes re-import (689 fetched, 0 written, 689 duplicates) is
  `completed_no_changes`, not an empty or failed run.
* A failed fetch/auth check marks the job `failed` and imports nothing.

### Demonstration isolation

Default (production) views hide synthetic actors, legacy demo actors, synthetic or demo
evidence, demo indicators, edges touching them, analyses involving them, demonstration
cases and their timeline events. `include_synthetic=true` restores them outside
production. Genuine records with incomplete fields are never hidden.

## 4. Feature status

Legend: **CV** complete and verified · **IV** implemented, not fully verified ·
**BE** blocked by external dependency · **NI** not implemented.

| Area | Status | Evidence |
| --- | --- | --- |
| Auth, RBAC, hashing | CV | pytest; live 401/403 checks |
| Actor CRUD, profile, identifiers, handles, evidence, timeline | CV | pytest + live API |
| CSV/JSON/STIX/single-record ingestion | CV | pytest |
| MITRE ATT&CK ingestion | CV | 26,699 objects, 1,820 entities, 19,481 relationships; ETag `not_modified` |
| APTnotes ingestion and job tracking | CV | 687 stored; live re-imports = `completed_no_changes` with jobs 6 and 7 |
| URLhaus | BE | `blocked_missing_credentials`; free Auth-Key required |
| ThreatFox | BE | `blocked_missing_credentials`; free Auth-Key required |
| Provenance stamping on new imports | CV | pytest asserts job id, modified time, reference, external id |
| Provenance for pre-existing rows | CV | backfill executed; 0 genuine rows without a job id |
| Relationship engine and graph | CV | 19,481 edges; focus/search/truncation checks |
| Analysis (stylometry, behaviour, scoring, clustering, inference) | CV | pytest and earlier live runs |
| Investigations and analyst decisions | CV | demonstration case preserved; review counts intact behind opt-in |
| Exports (CSV/JSON/PDF) | CV | counts match default views: actors 187, relationships 19,481, evidence 2,507, investigations 0 |
| Frontend build and pages | CV | `npm run build` passes; Settings shows relationship counts |
| Browser automation / frontend unit tests | NI | manual smoke checks only |
| Demonstration cleanup | PI | inventory exists; rows remain but are hidden from every default view |

## 5. Data quality notes

* The 58 legacy manual demo actors and 33 synthetic actors remain in the database but
  are hidden from every default view and export. Two actors are referenced by the
  demonstration investigation and its pending review, so cleanup must not delete them.
* The historical MITRE job 2 created 19,481 relationships before the counter existed;
  its row is preserved unchanged. The count is recorded here, in `TEST_REPORT.md` and in
  an append-only `audit_logs` note (`historical_job_note`) rather than by rewriting it.
* The `USES` relationships are ATT&CK catalogue links (group/software → technique),
  not claims of observed use against a victim.

## 6. Security review

* Secrets live only in `.env` (untracked); no secret is returned by the API.
* JWT in the `Authorization` header, not cookies; CORS restricts readable origins.
* Uploads are size-limited and parsed with format checks.
* CSV exports neutralise spreadsheet formula injection.
* SQL access uses SQLAlchemy parameter binding.
* Audit log records authentication, mutations, imports, reviews and backfills.
* Admin-only: feed imports, MITRE import, model training, destructive deletes.
