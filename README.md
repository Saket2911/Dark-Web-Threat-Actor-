# Threat Actor Intelligence Platform (CN_Project)

An evidence-driven threat-intelligence platform for investigating threat actors. It
imports **genuine public intelligence**, keeps the provenance of every record, derives
relationships only from documented evidence, and supports analyst review, analysis and
reporting.

The platform produces **investigative hypotheses**, never identity verdicts. Direct links
come from documented source records; analytical similarity is labelled as an inference
and requires analyst review.

> **Data policy.** Production views contain records that trace back to a real source.
> Synthetic demonstration data exists only for automated tests and an explicitly
> requested demo mode. It is never presented as intelligence, and feeds that cannot
> authenticate report that state instead of inventing data.

## Stack

| Layer | Technology |
| --- | --- |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2, SQLite, Alembic, Pydantic v2 |
| Auth | JWT (HS256), PBKDF2-SHA256 hashing, admin/analyst roles |
| Analysis | scikit-learn (TF-IDF, K-Means, DBSCAN), NetworkX, NumPy |
| Reporting | CSV, JSON, ReportLab PDF |
| Frontend | React 19, TypeScript, Vite 8, Tailwind CSS, Cytoscape.js, Recharts |

## Repository layout

```
backend/
  app/api/          REST routers (auth, actors, ingestion, graph, analysis, infra,
                    timeline, investigations, reports, settings, dashboard, health)
  app/core/         configuration, security, provenance filters, time helpers
  app/ingestion/    base adapter, MITRE ATT&CK, public feeds, job tracking,
                    validation, normalisation, deduplication
  app/services/     audit, identifiers, relationship engine/validators, evidence
  app/ml/           stylometry, behavioural, scoring, clustering, inference
  migrations/       Alembic revisions (head: d3e4f5a6b7c8)
  scripts/          import_intel.py, seed.py (demo only), dedupe_synthetic.py
  tests/            pytest suite (84 tests)
  data/app.db       canonical SQLite database (not committed)
frontend/           React application (11 pages) and typed API client
```

## Quick start

```bash
# Backend
cd backend
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
./.venv/Scripts/python.exe -m alembic upgrade head
./.venv/Scripts/python.exe scripts/import_intel.py --source all   # genuine data
./.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend (second terminal)
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open <http://127.0.0.1:5173>; API docs at <http://127.0.0.1:8000/docs>. Linux/macOS
uses `backend/.venv/bin/python`.

### Accounts

Create the first accounts through your deployment process or the demo seed below.
The demo seed adds `admin/admin123` (admin) and `analyst/analyst123` (analyst); change
or remove them before any non-local deployment. Registration is admin-only.

## Configuration

Settings come from `backend/.env` or the project-root `.env` (root wins on conflicts).
Copy `.env.example` to `.env`:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | JWT signing secret. Required outside local development. |
| `DATABASE_URL` | Defaults to `sqlite:///./data/app.db`, resolved against `backend/`. |
| `CORS_ORIGINS` | Comma-separated browser origins; defaults to the two Vite origins. |
| `ENVIRONMENT` | `development` or `production`. Production disables synthetic ingestion, demo seeding and every synthetic read path. |
| `ABUSE_CH_AUTH_KEY` | Free abuse.ch Auth-Key. Required by **both** URLhaus and ThreatFox. |
| `FEED_TIMEOUT_SECONDS`, `FEED_MAX_RETRIES` | Feed HTTP timeout and retry budget. |

Secrets are never returned by the API; `/api/settings/system` reports only whether the
JWT secret is configured.

## Genuine intelligence sources

| Source | Interface | Requires key | Verified |
| --- | --- | --- | --- |
| MITRE ATT&CK Enterprise | Official STIX 2.1 bundle from `attack-stix-data` | no | Yes — 26,699 objects fetched, 1,820 entities and 19,481 relationships imported |
| APTnotes | Public report index JSON from `aptnotes/data` | no | Yes — 689 records fetched, 687 stored, 0 rejected; repeated imports are no-ops |
| URLhaus | abuse.ch API (`/v1/urls/recent/`) | **yes** | Blocked — `blocked_missing_credentials` without a key |
| ThreatFox | abuse.ch API (`get_iocs`) | **yes** | Blocked — `blocked_missing_credentials` without a key |
| CISA KEV | Public JSON catalogue | no | Evaluated, not integrated: it lists exploited vulnerabilities, and the platform has no vulnerability entity that would materialise into actor intelligence |

Import from the Settings page, the API, or the CLI:

```bash
./.venv/Scripts/python.exe scripts/import_intel.py --source mitre
./.venv/Scripts/python.exe scripts/import_intel.py --source aptnotes --limit 500
./.venv/Scripts/python.exe scripts/import_intel.py --source urlhaus   # needs the key
```

### Collection jobs and honest statistics

Every run — including a direct `ingest_feed()` call — creates a `collection_jobs` row
with the source key, URL, retrieval time and separate counters:

`records_fetched`, `records_validated`, `records_imported` (entities created),
`records_updated`, `records_skipped`, `records_rejected`, `relationships_created`,
`error_count`, plus a bounded error list and structured `details`.

Status values are derived from those counters, not assumed:

| Status | Meaning |
| --- | --- |
| `completed` | At least one entity, update or relationship was written |
| `completed_no_changes` | Everything fetched was already stored; a successful idempotent no-op |
| `completed_empty` | The source answered but nothing usable was stored |
| `completed_with_errors` | Records were stored, but some failed validation |
| `not_modified` | Conditional refresh (ETag) confirmed the source is unchanged |
| `failed` | The run could not produce a usable result; nothing is reported as success |

A relationship-only import is therefore a success: MITRE runs that add documented
relationships but no new entities are reported with `relationships_created`, never as
`completed_empty`.

Historical rows are preserved. Job 2, which created the 19,481 relationships before the
`relationships_created` column existed, keeps its original counters; the known count is
recorded in `TEST_REPORT.md` and is proposed for an audit-log annotation only.

### What each connector stores

* **MITRE ATT&CK** — groups (intrusion sets), campaigns, malware, tools, tactics,
  techniques and the relationships MITRE documents between them. Original STIX IDs,
  aliases, external references and created/modified timestamps are preserved. Revoked
  and deprecated objects are skipped and counted. MITRE group attribution is stored as
  `relationship_classification='documented'`, `confidence_level='limited'` because
  ATT&CK attribution is a catalogued assessment, not verified identity.
* **APTnotes** — report metadata exactly as published: filename, title, publisher,
  link, SHA-1, date/year. No fields are invented. A report is linked to a group only
  when its title contains that group's name or alias as a whole word, and only groups
  imported from a real source are eligible. Every import creates a tracked job.
* **URLhaus / ThreatFox** — indicators (URL/domain/IP/hash), source identifiers,
  timestamps, tags, reporter and malware family, plus `INDICATES` links from the
  indicator to the malware family the source names. Without an Auth-Key they report
  `blocked_missing_credentials` and write nothing.

## Provenance model

Each imported record keeps:

* the intelligence source (`intelligence_sources`, `origin='external'` and health fields);
* the source's own record identifier (`evidence.external_record_id`);
* the original reference/URL (`evidence.reference`, `evidence.source_url`);
* the source publication time (`source_published_at`) and, when the provider publishes
  one, the source last-modified time (`source_modified_at`);
* the raw source payload (`evidence.raw_payload`);
* the collection job that first stored it (`evidence.import_job_id`).

New imports populate all of these. Evidence imported before the columns existed has been
backfilled from stored payloads only (`TEST_REPORT.md`): the 1,820 MITRE rows are linked
to collection job 1 with `source_modified_at` taken from STIX `modified`, and the 687
APTnotes rows are linked to job 8, status `historical_backfill` — the source publishes no
modified timestamp, so theirs stays NULL. No interleaved import can claim another job's
rows: evidence is deduplicated on (source, external record ID, entity), so the first
storing job owns it.

Deduplication keys: entities on `external_id` (STIX/source ID), evidence on
(source, external record ID, entity), relationships on their endpoints and type.
Re-imports are idempotent; MITRE also supports conditional refresh with the stored
ETag (`status: not_modified` when the bundle is unchanged).

## Demonstration data and cleanup

`scripts/seed.py` inserts synthetic scenarios and **requires `--demo`** (or
`ALLOW_SYNTHETIC_SEED=true`). It refuses to run in `ENVIRONMENT=production`, and the API
rejects synthetic ingestion there as well.

Default read paths hide every demonstration artefact consistently: synthetic actors,
legacy demo actors, synthetic/demo evidence, demo indicators, synthetic-only
relationships, synthetic analyses, demonstration investigations and demo timeline
events. Genuine records with missing fields (for example an APTnotes report with no
linked actor) stay visible. Pass `include_synthetic=true` in a non-production
environment to see demonstration rows.

`scripts/dedupe_synthetic.py` inventories every demonstration record, its dependents
and any analyst artefacts attached to it:

```bash
./.venv/Scripts/python.exe scripts/dedupe_synthetic.py          # dry run
./.venv/Scripts/python.exe scripts/dedupe_synthetic.py --json   # machine readable
./.venv/Scripts/python.exe scripts/dedupe_synthetic.py --apply --yes
```

A record is never deleted automatically when it belongs to an investigation, carries an
analyst review/decision, or is compared against a real actor. Those are reported for
analyst review. The `--apply` step requires explicit confirmation and never touches
real records. The live database still contains 58 legacy demo and 33 synthetic actors;
they are hidden from production views and were not deleted.

## Verification

```bash
cd backend
./.venv/Scripts/python.exe -m alembic current      # d3e4f5a6b7c8 (head)
./.venv/Scripts/python.exe -m pytest tests -q      # 84 passed
cd ../frontend
npm run build                                      # tsc -b + vite build
```

Verified live against the canonical database: 187 genuine actors, 19,481 documented
relationships, 2,507 genuine evidence rows, zero demonstration rows in default views
and exports, accurate APTnotes job statistics with idempotent re-imports, MITRE
provenance fields, and the preserved demonstration investigation plus its pending
analyst decision. See `TEST_REPORT.md` for the full run.

## Known limitations

* APTnotes publishes no last-modified timestamp, so `source_modified_at` is NULL for its
  evidence by design; MITRE and other providers are stamped automatically.
* URLhaus and ThreatFox cannot be verified without a free abuse.ch Auth-Key; the
  connectors implement the documented `Auth-Key` header and fail honestly without it.
* MITRE ATT&CK relationships describe ATT&CK's own catalogue; they do not prove actor
  identity, and the UI labels them as limited-confidence documented associations.
* APTnotes provides report metadata only (no structured indicators), so it is stored
  as report evidence, not as IOCs.
* Stylometric, behavioural and clustering analyses report `insufficient data` when the
  genuine corpus is too small; no result is fabricated.
* The graph caps displayed edges (default 1,500, disclosed in the UI); the full
  catalogue stays in the database.
