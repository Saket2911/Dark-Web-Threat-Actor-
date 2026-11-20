# Implementation Status

Status categories: **COMPLETE AND VERIFIED**, **IMPLEMENTED BUT NOT FULLY VERIFIED**,
**PARTIALLY IMPLEMENTED**, **NOT IMPLEMENTED**, **BLOCKED BY EXTERNAL DEPENDENCY**.

Branch `version-2`, Alembic head `d3e4f5a6b7c8`, last verified 2026-11-19.

## Phase 0 — Codebase audit

**COMPLETE AND VERIFIED.** Backend, frontend, migrations, database, scripts and
configuration inspected; findings recorded in `PROJECT_COMPLETION_AUDIT.md`.

## Phase 1 — Backend completion

**COMPLETE AND VERIFIED.**

* Authentication: login, logout, `/auth/me`, JWT expiry, PBKDF2 hashing, admin-only
  user creation, role checks on destructive operations.
* Actor management: CRUD, search, filters, pagination, profile, handles, identifiers,
  evidence, timeline, related entities.
* Identifier normalisation and strict validation; exact-value matching only.
* Evidence and provenance service with a single validated creation entry point.
* Infrastructure, timeline, investigations, reports and settings endpoints.

## Phase 2 — Genuine intelligence ingestion

**COMPLETE AND VERIFIED** for MITRE ATT&CK, APTnotes and file ingestion.
**BLOCKED BY EXTERNAL DEPENDENCY** for URLhaus and ThreatFox.

* Official MITRE ATT&CK Enterprise STIX 2.1 import: 26,699 objects fetched, 1,820
  entities created, 19,481 documented relationships, 0 errors on the successful run;
  ETag conditional refresh returns `not_modified`.
* APTnotes public report index: 689 fetched, 687 stored, 224 linked to externally
  sourced groups, 0 rejected. Repeated imports are idempotent.
* URLhaus and ThreatFox implement the documented `Auth-Key` header and report
  `blocked_missing_credentials` without one; nothing is fabricated.
* CISA KEV evaluated and deliberately not integrated (no vulnerability entity).
* CSV, JSON, STIX 2.1 and single-record ingestion with validation, deduplication and
  per-job summaries.

## Phase 3 — Collection-job accounting and provenance

**COMPLETE AND VERIFIED** for every new import.

* Migration `d3e4f5a6b7c8` adds a persisted `relationships_created` counter.
* Jobs record fetched, validated, imported (entities), updated, skipped, rejected,
  relationships created, errors and structured details.
* Status is derived from counters: `completed`, `completed_no_changes`,
  `completed_empty`, `completed_with_errors`, `not_modified`, `failed`. A
  relationship-only import is a success; a failed run cannot be reported as success.
* `ingest_feed()` creates and finishes its own job when the caller does not supply one,
  so direct connector calls cannot run untracked. API and CLI pass the job id through.
* Evidence now stores the collection job id, source last-modified time (when published),
  external record id, reference/URL, publication time and raw payload.
* Historical job rows are preserved unchanged; no fact was rewritten.

**BACKFILL EXECUTED (2026-11-20).** Evidence imported before the provenance columns
existed was stamped from stored payloads in one transaction: 1,820 MITRE rows linked to
job 1 with `source_modified_at` from STIX `modified`, and 687 APTnotes rows linked to the
new `historical_backfill` job (id 8). Zero genuine rows now have a NULL `import_job_id`;
APTnotes `source_modified_at` stays NULL because the source publishes no timestamp. Both
changes are recorded in `audit_logs`; no historical job row was rewritten.

## Phase 4 — Relationship intelligence

**COMPLETE AND VERIFIED.**

* Direct links from identical normalised identifiers, inferred links from stored
  analyses, deduplication, self-link prevention, per-pair savepoints.
* Stored graph: 19,481 genuine edges (USES 18,975, ASSOCIATED_WITH 480,
  ATTRIBUTED_TO 26). Demonstration edges are excluded from default views.
* Graph API: nodes, edges, focus neighbourhood, depth, type/min-score/search filters,
  relationship detail, statistics, components, communities, edge-limit disclosure.

## Phase 5 — Demonstration-data isolation

**COMPLETE AND VERIFIED** across read paths.

* Hidden by default: synthetic actors, legacy demo actors, synthetic/demo evidence,
  demo indicators, relationships touching any of them, analyses involving them,
  demonstration investigations, demo timeline events.
* Applied consistently in dashboard aggregates and charts, actor lists, profiles,
  identifiers/evidence sub-resources, graph, infrastructure (list and detail),
  timeline (list and summary), analysis history, investigation list/detail, and CSV,
  JSON and PDF exports.
* NULL-safe filters: genuine records with incomplete links (for example unlinked
  APTnotes reports and unattributed inference results) remain visible.
* Production (`ENVIRONMENT=production`) ignores `include_synthetic` entirely, rejects
  synthetic ingestion, and the demo seed refuses to run.
* Demonstration actors were **not** deleted or merged; cleanup remains approval-gated.

## Phase 6 — Frontend

**COMPLETE AND VERIFIED.** `npm run build` passes.

Eleven pages: Login, Dashboard, Actors, Actor Profile, Relationship Explorer, AI
Analysis, Infrastructure, Timeline, Investigations, Reports, Settings. Settings shows
last success, last run, fetched/stored/rejected counts, relationship count and errors
per source; the MITRE action reports entities and relationships separately.

## Cross-cutting

* **COMPLETE AND VERIFIED:** SQLite/Alembic integrity at `d3e4f5a6b7c8`, 84 passing
  backend tests, production frontend build, audit logging, CSRF-resistant bearer auth,
  restricted CORS, upload limits, CSV injection protection, honest feed failure states.
* **PARTIALLY IMPLEMENTED:** demonstration-data deletion (inventory only; the rows stay
  in the database but are hidden everywhere by default); browser automation coverage
  (manual smoke checks).
* **NOT IMPLEMENTED:** frontend unit/component test suite, multi-user concurrency beyond
  SQLite capabilities.
