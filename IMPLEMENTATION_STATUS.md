# Implementation Status

Status categories: **COMPLETE AND VERIFIED**, **IMPLEMENTED BUT NOT FULLY VERIFIED**,
**PARTIALLY IMPLEMENTED**, **NOT IMPLEMENTED**, **BLOCKED BY EXTERNAL DEPENDENCY**.

## Phase 0 — Codebase audit

**COMPLETE AND VERIFIED.** The backend, frontend, migrations, database, seed script,
tests and configuration were inspected. Findings are recorded in
`PROJECT_COMPLETION_AUDIT.md`.

## Phase 1 — Backend completion

**COMPLETE AND VERIFIED.**

* Authentication: login, logout, `/auth/me`, JWT expiry, PBKDF2 hashing, admin-only
  user creation, role checks on destructive operations.
* Actor management: CRUD, search, category/status/origin filters, pagination, profile,
  handles, identifiers, evidence, timeline, related entities.
* Identifier management: PGP, wallet, email, domain, IP, username, certificate, URL
  and infrastructure values; canonicalisation and strict validation; exact-value
  matching only.
* Evidence and provenance: every imported record keeps source, collection timestamp,
  reference, reliability and synthetic/real origin.
* Infrastructure: list, filters, detail with associations and evidence.
* Timeline: creation, actor/date/type filters, ordering, summary.

## Phase 2 — Intelligence ingestion

**COMPLETE AND VERIFIED** for file and record ingestion; **IMPLEMENTED BUT NOT FULLY
VERIFIED** for external feeds; **BLOCKED BY EXTERNAL DEPENDENCY** for ThreatFox.

* CSV, JSON, STIX 2.1 and single-record ingestion with validation, deduplication and
  per-job summaries (processed/imported/duplicates/rejected/errors).
* Collection job tracking with start/finish timestamps.
* MITRE ATT&CK importer repaired; status and admin action exposed in Settings.
* APTnotes and URLhaus adapters implement documented endpoints with timeouts, retries,
  rate-limit handling and provenance.
* ThreatFox is implemented but disabled without `ABUSE_CH_AUTH_KEY`; the feed status
  endpoint returns `blocked_missing_credentials`.

## Phase 3 — Relationship intelligence

**COMPLETE AND VERIFIED.**

* Direct links from identical normalised identifiers (PGP, wallet, email and matching
  infrastructure), with evidence text and classification.
* Inferred links from stored analysis results at or above the configured threshold;
  always marked non-direct.
* Deduplication, self-link prevention, endpoint validation, idempotent rebuilds and
  per-pair savepoints.
* Graph API: nodes, edges, focus neighbourhood, depth, type/min-score/search filters,
  relationship detail, statistics, components, communities.
* Live graph contains 16 actor nodes, 2 identifier nodes and 138 edges for the
  seeded shared-fingerprint focus.

## Phase 4 — AI/ML and analysis

**COMPLETE AND VERIFIED.**

* Stylometry: TF-IDF (word 1–2 grams) + lexical/punctuation features, feature
  comparison, shared terms, short-sample and identical-text warnings.
* Behaviour: 24-bin hourly cosine with activity counts, active hours and sparse-data
  warnings.
* Evidence scoring: weighted mean over available features, coverage, per-feature
  contributions, missing-evidence list, limitations; overlapping evidence is not
  double counted.
* Attribution bands: Strong / Moderate / Weak / Insufficient with an explicit
  hypothesis disclaimer.
* K-Means and DBSCAN with scaling, summaries, silhouette where defined, noise
  handling and insufficient-data results.
* Persisted inference model: train (admin), status, single inference, batch inference,
  provenance persistence and API/UI integration.

## Phase 5 — Frontend completion

**COMPLETE AND VERIFIED.** `npm run build` passes. All eleven pages exist and are
reachable from the sidebar: Login, Dashboard, Actors, Actor Profile, Relationship
Explorer, AI Analysis, Infrastructure, Timeline, Investigations, Reports, Settings.

* Dashboard: live totals, category pie, provenance bars, activity line, relationship
  bars, sources, collection jobs and audit activity.
* Actors: search/filter/pagination table, creation, CSV/JSON/STIX upload, single
  record import with result summary.
* Actor profile: overview editing, handles, identifiers, evidence, timeline,
  relationships.
* Relationship Explorer: Cytoscape graph with actor/identifier/indicator nodes,
  direct and dashed inferred edges, filters, search, layouts, zoom/pan/fit, selection
  details, relationship reviews, build and infer actions.
* AI Analysis: attribution with contribution chart and limitations, stylometry,
  behaviour, clustering controls and summaries, model training/inference, history.
* Infrastructure: filterable table, detail modal with associations/evidence, create.
* Timeline: actor/date/type filters, aggregation chart, event creation.
* Investigations: case creation with actor selection, entity management, relationship
  review with persisted decisions, decision history, status update, PDF export.
* Reports: six CSV/JSON exports and actor/investigation PDFs with live row counts.
* Settings: system status, weights, thresholds, models, persisted model training and
  inference, external feed status and runs, MITRE import, source provenance.

## Cross-cutting

* **COMPLETE AND VERIFIED:** SQLite/Alembic integrity, idempotent seed, synthetic
  labelling, CORS restriction, admin-only destructive actions, upload limits,
  audit logging, CSV injection protection, 67 passing backend tests, production
  frontend build.
* **PARTIALLY IMPLEMENTED:** duplicate synthetic actor cleanup (detection only, since
  deletion requires approval), browser automation coverage (manual smoke checks).
* **NOT IMPLEMENTED:** frontend unit/component test suite (none exists in the
  project), multi-user concurrency beyond SQLite capabilities.
