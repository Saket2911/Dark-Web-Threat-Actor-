# Test Report — 2026-11-19

All results below were produced by executing the commands shown against branch
`version-2`. Nothing is copied from an earlier report.

## Environment

* Windows 11, Python 3.12 virtual environment at `backend/.venv`
* Node.js 20.20.2, npm 10.8.2, Vite 8.3.8, TypeScript 7.0.2
* Database: `backend/data/app.db`, Alembic head **`d3e4f5a6b7c8`**
* Backend `127.0.0.1:8000`, frontend `127.0.0.1:5173`

## Migration

```bash
cd backend
./.venv/Scripts/python.exe -m alembic current
./.venv/Scripts/python.exe -m alembic upgrade head
```

* Before: `c2d3e4f5a6b7`
* Applied: `c2d3e4f5a6b7 -> d3e4f5a6b7c8` ("collection job relationship counts")
* After: `d3e4f5a6b7c8 (head)`
* The migration only adds a nullable `collection_jobs.relationships_created` column.
  Existing rows keep their original values (NULL); nothing is rewritten or deleted.

## Backend test suite

```bash
cd backend
./.venv/Scripts/python.exe -m pytest tests -q
```

Result: **84 passed, 0 failed, 266 warnings in 5.51s** (exit code 0).

Warnings are third-party deprecations (`python-jose`, `multipart`) and FastAPI
`on_event`; application code emits none of them. New coverage in this pass:

| Test | Assertion |
| --- | --- |
| `test_mitre_run_persists_relationship_count_and_evidence_provenance` | Job stores the real relationship count, status is `completed`, evidence carries `import_job_id`, `source_modified_at`, reference and external id |
| `test_aptnotes_direct_call_creates_tracked_job_and_stamps_evidence` | A direct connector call creates a job with accurate counts; evidence points at it; the repeat call is `completed_no_changes` |
| `test_dashboard_hides_synthetic_analyses_and_investigations` | Dashboard counts exclude demo analyses; demo case hidden by default, visible with opt-in, absent from exports |
| `test_infrastructure_detail_hides_demo_indicator` | Demo indicator 404s by id and is absent from the list |
| `test_legacy_relationship_without_polymorphic_fields_is_hidden` | Edges stored only in the legacy actor columns obey provenance filtering |
| `test_reports_keep_genuine_evidence_without_an_entity_link` | NULL entity links do not hide genuine evidence |

## Frontend

```bash
cd frontend
npm run build
```

Result: **success** (exit code 0). `tsc -b` clean; Vite built `dist/` in 13.25 s,
1,312.08 kB JS (385.72 kB gzip). The >500 kB chunk advisory remains a performance
warning, not a failure.

## Live API verification (after restart)

Backend restarted on the migrated database; `/api/health` returned 200 and the startup
log contained no errors.

| Check | Result |
| --- | --- |
| Dashboard (default) | 187 actors, 19,481 relationships, 2,507 evidence, 0 indicators, 0 timeline events, 0 investigations, 0 analyses, 2 genuine sources; `synthetic_hidden=true` |
| Actors export | 187 |
| Relationships export | 19,481 |
| Evidence export | 2,507 (was incorrectly 2,044 before the NULL fix) |
| Identifiers / timeline / investigations exports | 0 / 0 / 0 |
| Infrastructure list | total 0, `types: []` (24 demo indicators hidden) |
| Timeline list + summary | 0 events, 0 actor rows |
| Graph (limit 1,500) | 187 actor nodes, 1,500 edges, `truncated=true` |
| APTnotes import via API, run 1 | 200; fetched 689, imported 0, duplicates 689, rejected 0; job 6 `completed_no_changes` |
| APTnotes import via API, run 2 | 200; identical counts; job 7 `completed_no_changes`, skipped 689 |
| Demonstration case, default view | absent from `/investigations` |
| Demonstration case, `include_synthetic=true` | listed and detail 200; 1 pending analyst review preserved |
| Genuine MITRE data | 187 external actors, 19,481 edges, 2,507 evidence returned |
| Job fields | `relationships_created` exposed by `/ingestion/jobs` and Settings |

### Historical job rows (unchanged)

| Job | Source | Status | Fetched | Imported | Updated | Skipped | Rejected | Relationships | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | mitre_attack | completed_with_errors | 26,699 | 1,820 | 0 | 157 | 21,822 | NULL | 50 |
| 2 | mitre_attack | completed_empty | 26,699 | 0 | 1,820 | 2,498 | 0 | NULL | 0 |
| 3 | mitre_attack | not_modified | 0 | 0 | 0 | 0 | 0 | NULL | 0 |
| 4 | mitre_attack | completed_empty | 26,699 | 0 | 1,820 | 21,979 | 0 | NULL | 0 |
| 5 | urlhaus | failed | 0 | 0 | 0 | 0 | 0 | NULL | 1 |
| 6 | aptnotes | completed_no_changes | 689 | 0 | 0 | 689 | 0 | 0 | 0 |
| 7 | aptnotes | completed_no_changes | 689 | 0 | 0 | 689 | 0 | 0 | 0 |

Job 2 is the run that created the 19,481 relationships. Its counters are historically
accurate for the schema of the time (entities updated, not relationships). The row is
preserved; its known relationship count is recorded here.

## Database inventory (read-only inspection)

* Actors: 187 external, 58 manual (legacy demo), 33 synthetic.
* Relationships: 19,481 genuine; 243 demonstration (240 legacy `SHARED_IDENTIFIER`
  with NULL polymorphic fields, 3 inferred).
* Evidence: 2,561 total — 1,820 MITRE, 687 APTnotes (224 actor-linked, 463 unlinked),
  54 demonstration. `import_job_id` non-null: **0**; `source_modified_at` non-null: **0**.
* Indicators: 24 demonstration. Timeline: 60 demonstration. Analyses: 8 demonstration.
* Investigations: 1 demonstration case; analyst reviews: 1 pending. Preserved.

## External integrations

| Integration | Executed | Result |
| --- | --- | --- |
| MITRE ATT&CK | Yes (earlier in the phase) | 26,699 objects, 1,820 entities, 19,481 relationships, 0 errors; ETag `not_modified` on repeat |
| APTnotes | Yes, twice in this pass | 689 fetched, 0 new, 689 duplicates each time; jobs 6 and 7 |
| URLhaus | Yes, credential probe | `failed` job with `blocked_missing_credentials`; no records |
| ThreatFox | Credential probe | `blocked_missing_credentials`; no records |
| CISA KEV | Evaluated | Not integrated (no vulnerability entity) |

## Provenance backfill — EXECUTED 2026-11-20

Existing evidence was imported before `import_job_id`/`source_modified_at` were wired.
The dry-run counts were checked first and matched the plan exactly (1,820 / 1,820 /
687), the database was backed up to `backend/data/app.db.bak-pre-backfill-20261120`,
and the transaction below was committed in a single `BEGIN IMMEDIATE` block after
partner approval.

### Result

| Step | Rows | Outcome |
| --- | --- | --- |
| MITRE evidence linked to job 1 | 1,820 | `import_job_id = 1` |
| MITRE `source_modified_at` from STIX `modified` | 1,820 | all non-NULL |
| APTnotes rows linked to job 8 (`historical_backfill`) | 687 | `import_job_id = 8` |
| Audit rows written | 2 | `evidence_provenance_backfill`, `historical_job_note` |

Post-run verification: 0 genuine evidence rows with a NULL `import_job_id`; the 687
remaining NULL `source_modified_at` values are exactly the APTnotes rows, whose source
publishes no modified timestamp; 72 NULL job ids belong to synthetic evidence and stay
untouched. No evidence, relationship, investigation, review or job row was deleted or
rewritten, and job 2 keeps its original counters.

### Dry run (expected counts)

```sql
-- MITRE evidence rows that would receive job 1
SELECT COUNT(*) FROM evidence
WHERE import_job_id IS NULL
  AND source_id = (SELECT id FROM intelligence_sources
                   WHERE name='mitre-attack-enterprise' AND is_synthetic=0
                   ORDER BY id LIMIT 1);                       -- expect 1820

-- Of those, rows whose raw STIX payload publishes a modified timestamp
SELECT COUNT(*) FROM evidence
WHERE import_job_id IS NULL
  AND source_id = (SELECT id FROM intelligence_sources
                   WHERE name='mitre-attack-enterprise' AND is_synthetic=0
                   ORDER BY id LIMIT 1)
  AND json_extract(raw_payload, '$.modified') IS NOT NULL;      -- expect 1820

-- APTnotes evidence rows to link to the explicit backfill job
SELECT COUNT(*) FROM evidence
WHERE import_job_id IS NULL
  AND source_id = (SELECT id FROM intelligence_sources
                   WHERE name='APTnotes' AND is_synthetic=0
                   ORDER BY id LIMIT 1);                       -- expect 687
```

### Proposed transaction

```sql
BEGIN;

-- 1. MITRE evidence was first stored by collection job 1 (the successful entity run).
UPDATE evidence
SET import_job_id = 1
WHERE import_job_id IS NULL
  AND source_id = (SELECT id FROM intelligence_sources
                   WHERE name='mitre-attack-enterprise' AND is_synthetic=0
                   ORDER BY id LIMIT 1);

-- 2. MITRE publishes STIX `modified`; extract it from the stored raw payload.
UPDATE evidence
SET source_modified_at = datetime(json_extract(raw_payload, '$.modified'))
WHERE import_job_id = 1
  AND source_modified_at IS NULL
  AND json_extract(raw_payload, '$.modified') IS NOT NULL;

-- 3. APTnotes ran before job tracking. Record that fact explicitly instead of
--    fabricating an original job: a new row labelled historical_backfill.
INSERT INTO collection_jobs (
    source_name, source_key, source_url, status,
    records_fetched, records_validated, records_imported, records_updated,
    records_skipped, records_rejected, relationships_created, errors, error_count,
    details, started_at, finished_at
) VALUES (
    'APTnotes (historical backfill)', 'aptnotes',
    'https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json',
    'historical_backfill',
    689, 689, 687, 0, 2, 0, 0, NULL, 0,
    '{"reason":"imported 2026-11-19 before collection-job tracking existed; linked retroactively","original_run":"2026-11-19T15:48:28"}',
    '2026-11-19 15:48:28', '2026-11-19 15:48:28'
);

UPDATE evidence
SET import_job_id = (SELECT MAX(id) FROM collection_jobs WHERE status='historical_backfill')
WHERE import_job_id IS NULL
  AND source_id = (SELECT id FROM intelligence_sources
                   WHERE name='APTnotes' AND is_synthetic=0
                   ORDER BY id LIMIT 1);

-- 4. Audit trail for the backfill itself.
INSERT INTO audit_logs (user, action, details, created_at)
VALUES ('system', 'evidence_provenance_backfill',
        'Linked 1820 MITRE evidence rows to job 1, filled MITRE source_modified_at from raw STIX, linked 687 APTnotes rows to the historical_backfill job',
        CURRENT_TIMESTAMP);

COMMIT;
```

Notes:

* APTnotes publishes no modified timestamp, so `source_modified_at` stays NULL for
  those rows; nothing is invented.
* Job 2 is not modified. If an explicit correction record is wanted, the only proposed
  write is an append-only audit row, e.g.
  `INSERT INTO audit_logs (...) VALUES ('system','historical_job_note','Job 2 created 19,481 relationships before the relationships_created column existed; original row preserved', CURRENT_TIMESTAMP);`
* Rollback, if ever needed, is `import_job_id = NULL` for the affected ids plus deletion
  of the single `historical_backfill` job; no evidence, relationship, investigation or
  review is deleted. The pre-backfill database copy is retained.

## Limitations of this report

* No frontend automation suite exists; UI coverage is type checking, production build
  and API-level verification. The pages were not clicked through in this pass.
* Provenance stamping is proven by tests and by the executed backfill, but no live
  import created a *new* record in this pass: all live APTnotes records already existed,
  so the live re-imports were idempotent no-ops.
* URLhaus/ThreatFox remain unverified end-to-end without an abuse.ch Auth-Key.
* The 58 legacy demo and 33 synthetic actors remain in the database (hidden); cleanup
  requires approval and was not run.
