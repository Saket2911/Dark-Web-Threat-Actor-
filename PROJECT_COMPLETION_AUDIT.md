# Project Completion Audit — CN_project

Audit performed against the existing codebase on 2026-11-19. This document records
what existed, what was broken, the root causes, and what was changed. It is a
verification record, not a plan.

## 1. Original condition

The repository contained a FastAPI/SQLAlchemy backend, an Alembic history up to
`69255c01a2e`, a React/TypeScript frontend, a seed script and a small test suite.
Several modules were reported as complete (ingestion, relationship engine, ML,
reports), but verification showed:

* two SQLite databases with different schema levels and no unambiguous canonical
  path;
* administrative endpoints reachable by any authenticated user;
* an ingestion pipeline whose failures were partly swallowed;
* a relationship engine that rolled back the whole build on a single failure;
* a frontend that did not match several backend response shapes, contained
  placeholder calculations and dead interactions;
* a test suite that did not cover most endpoints.

The reported acceptance figures (34/34 tests, 33 actors, 12 identifiers) were stale.

## 2. Defects found and root causes

| # | Defect | Root cause | Resolution |
| --- | --- | --- | --- |
| 1 | Two databases (`data/app.db`, `backend/data/app.db`) with different schemas | Relative SQLite path resolved against the process working directory | Paths resolve against `backend/`; canonical DB documented and migrated to head |
| 2 | `MITRE ATT&CK` import crashed | `normalize()` called an undefined helper and referenced an undefined variable; tactic creation was unconditional | Import rewritten with STIX parsing, lookups and idempotent upserts |
| 3 | Relationship build lost work on one bad pair | `db.rollback()` inside per-pair loops | Per-pair `SAVEPOINT`; failures counted, prior links retained |
| 4 | Graph showed identifier ownership edges even when filtering by relationship type | Synthetic `HAS_IDENTIFIER` edges always emitted | Edge emission now honours `rel_types`; ownership nodes remain |
| 5 | Frontend graph used `d.created` and rendered no edges | Backend field names differ (`created_at`, `evidence`, `relationship_id`) | Typed API client and rewritten explorer use the real payload |
| 6 | Timeline chart had no data keys | Placeholder chart configuration | Chart reads `/dashboard/charts/activity` and `/timeline/summary` |
| 7 | Investigation review wrote `relationship_id=0` and a fixed decision | Placeholder implementation | Review modal posts a real relationship id and decision, persisted with reviewer and notes |
| 8 | Any authenticated user could register accounts and delete actors | Missing role checks | Registration and user administration are admin-only; actor and relationship deletion requires admin |
| 9 | CORS allowed every origin | `CORS_ORIGINS=*` | Restricted to development origins; foreign preflights rejected |
| 10 | Weak default secret silently accepted | Placeholder value | Startup warning retained; local `.env` now holds a random secret |
| 11 | Deprecated `datetime.utcnow()` throughout | Legacy code | `app.core.time.utcnow()` used in application code |
| 12 | Duplicate synthetic demo rows from an earlier seed run | Non-idempotent historical seed | Seeding is idempotent; duplicates are reported by `scripts/dedupe_synthetic.py` (not deleted without approval) |
| 13 | Tests mutated production data | Tests used the application database | Per-session temporary database in `tests/conftest.py` |

## 3. Feature status

Legend: **CV** complete and verified · **IV** implemented but not fully verified ·
**PI** partially implemented · **NI** not implemented · **BE** blocked by external
dependency.

| Area | Status | Evidence |
| --- | --- | --- |
| JWT login, token validation, expiry, logout | CV | pytest auth tests; live login/401 checks |
| PBKDF2 hashing, no password exposure | CV | auth tests; response inspection |
| Admin/analyst RBAC | CV | 403 for analyst train/delete; admin-only registration |
| Actor CRUD, search, filters, pagination, profile | CV | tests + live API + UI |
| Handles, identifiers, evidence, timeline CRUD | CV | tests + UI profile tabs |
| Identifier normalisation/validation | CV | strict email/domain/IP/wallet/PGP handling; 422 checks |
| CSV/JSON/STIX ingestion, dedup, job summaries | CV | ingestion tests |
| MITRE ATT&CK import | IV | code path repaired and status reported; full bundle import not executed in this session |
| APTnotes/URLhaus adapters | IV | documented endpoints, retries, provenance; live availability depends on upstream |
| ThreatFox | BE | requires abuse.ch Auth-Key; API reports `blocked_missing_credentials` |
| Direct relationships from shared identifiers | CV | 240 persisted links; rebuild idempotent |
| Inferred relationships from analysis | CV | 3 persisted hypotheses above threshold |
| Relationship validation/deduplication/self-link prevention | CV | validator + tests |
| Graph data, filters, focus neighbourhood, details | CV | tests + Cytoscape render with 138 edges |
| Graph build/infer/statistics/components/clusters | CV | live endpoints |
| Stylometric analysis | CV | tests; measured 0.5837 on short samples, 1.0 for identical text |
| Behavioural analysis | CV | tests; measured cosine 1.0 with insufficient-event flag |
| Weighted attribution with contributions/coverage | CV | measured 0.7422, coverage 0.70, Moderate |
| K-Means / DBSCAN with summaries and guards | CV | measured k=3 silhouette 0.5013; DBSCAN 2 clusters, 0 noise |
| Persisted style-inference model (train/infer/batch) | CV | tests; UI in Settings and Analysis |
| Dashboard aggregates and charts | CV | live values rendered |
| Infrastructure list/detail/associations | CV | 24 indicators; detail API |
| Timeline filters, summary, creation | CV | 60 events; chart populated |
| Investigations, entities, decisions, history | CV | case with 2 entities, 30 relationships, persisted review |
| CSV/JSON/PDF exports | CV | row counts match database; PDFs return `application/pdf` |
| Settings/status/weights/thresholds/feeds | CV | live pages |
| Frontend pages, navigation, states | CV | production build; live render checks |
| Browser end-to-end automation | NI | no suite configured; manual smoke checks only |
| Frontend unit/component tests | NI | not configured in the project |

## 4. Database changes

* Added `analyst_reviews.investigation_id` (migration `a1b2c3d4e5f6`, already present
  in history before this session).
* Added metadata-driven query indexes (migration `b7c1d2e3f4a5`, applied to
  `backend/data/app.db`).
* No rows were deleted or reset. Backups taken before migration remain in
  `backend/data/app.db.bak.*`.
* Two synthetic text samples were added by the idempotent seed for the shared-PGP
  scenario so the seeded investigation has evidence.

## 5. Data quality notes

* 91 actors exist: 33 synthetic, 58 manual. The manual actors include artifacts from
  earlier manual testing (`alpha1` copies, `testactor`) and an existing `tester`
  account.
* The seed duplicates created by the earlier run are still present (22 duplicate
  actors with dependent records). Merging them is an analyst decision; the dedupe
  script reports them and will not delete actors that own data.
* A stale database at the project root (`data/app.db`) is unused and was left intact.

## 6. Security review

* Secrets live only in `.env` (untracked); no secret is returned by the API.
* JWT in the `Authorization` header, not cookies, so token-bearing requests are not
  CSRF-forgeable by a browser; CORS restricts which origins can read responses.
* Uploads are size-limited (`MAX_UPLOAD_BYTES`) and parsed with format checks.
* CSV exports neutralise spreadsheet formula injection.
* SQL access uses SQLAlchemy parameter binding.
* Audit log records authentication, mutations, imports and reviews.
