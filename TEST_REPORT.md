# Test Report — 2026-11-19

All results below were produced by executing the commands shown. Nothing is copied
from earlier reports.

## Environment

* Windows 11, Python 3.12 virtual environment at `backend/.venv`
* Node.js 20.20.2, npm 10.8.2, Vite 8.3.8, TypeScript 7.0.2
* Database: `backend/data/app.db`, Alembic head `b7c1d2e3f4a5`

## Backend test suite

```bash
cd backend
./.venv/Scripts/python.exe -m pytest tests -q
```

Result: **67 passed, 0 failed, 245 warnings in 6.25s** (exit code 0).

Coverage by module:

| Test module | Focus |
| --- | --- |
| `test_auth.py` | login success/failure, token validation, `/me`, admin-only registration, RBAC |
| `test_actors.py` | create/read/update/delete, filters, pagination, identifiers, handles, evidence, timeline |
| `test_ingestion.py` | record, CSV, JSON, STIX, deduplication, validation, job summaries, upload limits |
| `test_relationships_graph.py` | direct build, idempotency, shared identifiers, self-link rejection, graph filters, detail |
| `test_analysis.py` | stylometry, behaviour, attribution, K-Means, DBSCAN, model train/infer/batch, insufficient-data paths |
| `test_stix_mitre.py` | STIX normalisation/validation and MITRE importer |
| `test_workflow.py` | login → ingest → identifiers → evidence → relationships → graph → attribution → investigation → review → export |

Warnings: 245, dominated by third-party `python-jose`'s internal `datetime.utcnow()`
use and a `multipart` deprecation warning. Application code no longer emits
`datetime.utcnow()` deprecations.

## Frontend

```bash
cd frontend
npm run build
```

Result: **success** — `tsc -b` clean, Vite produced `dist/` (1,309.65 kB JS,
385.18 kB gzip; 20.66 kB CSS). Exit code 0.

Note: Vite reports a chunk-size advisory (>500 kB). This is a performance warning,
not a failure; code splitting was not configured.

`npm run lint` could not run in this environment: Windows Application Control
blocks the native `oxlint.win32-x64-msvc.node` binding (`An Application Control
policy has blocked this file` / `Cannot find module`). This is a host policy issue,
not a lint finding. TypeScript strict checks in `npm run build` did run and passed.

## Live integration checks

Backend on `127.0.0.1:8000`, frontend on `127.0.0.1:5173`, real database and browser.

| Check | Result |
| --- | --- |
| Login `admin/admin123` | 200; dashboard loaded with live figures |
| Unauthenticated `/dashboard/stats` | 401 |
| Bad password | 401 |
| Analyst calling model training | 403 |
| Analyst deleting an actor | 403 |
| Invalid email identifier | 422 |
| CORS preflight from `http://127.0.0.1:5173` | 200 |
| CORS preflight from `https://evil.example` | 400 (rejected) |
| Dashboard totals | 91 actors, 34 identifiers, 243 relationships (240 direct, 3 inferred), 54 evidence, 24 indicators, 16 sources, 60 timeline events, 7 analyses |
| Actor search (`ghostsec`, `ciphermoth`) | 8 matches each (historical duplicate seed rows) |
| Graph data, focus actor 1, depth 1 | 16 actor nodes, 2 identifier nodes, 138 edges; canvas rendered in browser |
| Graph `rel_types=SHARED_IDENTIFIER`, identifiers off | 91 actor nodes, 240 edges, no ownership edges |
| Relationship build (repeat run) | 0 created, 240 already present, 0 failed — idempotent |
| Inference (repeat run) | 0 created, 3 already present above threshold 0.6 |
| Attribution ghostsec/ciphermoth | 0.7422, "Moderate evidence", coverage 0.70; identifier 1.0, stylometric 0.8476, temporal 0.0 |
| Behavioural comparison | cosine 1.0 with `sufficient=false` (sparse events) |
| Stylometry, two short samples | 0.5837, `sufficient=false`, warning returned |
| K-Means | status `ok`, 3 clusters, silhouette 0.5013 |
| DBSCAN (eps 0.5, min 2) | status `ok`, 2 clusters, 0 noise |
| Timeline | 60 events; summary chart populated |
| Infrastructure | 24 indicators (cert, domain, ip) |
| Investigation detail | 2 entities, 30 relationships, 2 evidence, 1 pending review |
| Review workflow | Decision modal posts real relationship id; decision persisted and shown in history |
| CSV exports | actors 91, identifiers 34, relationships 243, evidence 54, timeline 60, investigations 1 — all match database |
| JSON exports | same record counts, includes provenance note |
| Actor PDF | 200, `application/pdf`, 5,438 bytes |
| Investigation PDF | 200, `application/pdf`, 2,771 bytes |
| Feeds | aptnotes available, urlhaus available, mitre_attack available, threatfox `blocked_missing_credentials` |
| Browser pages rendered | Dashboard, Actors, Graph (Cytoscape canvas), Analysis (attribution result), Investigations (case detail) |

Manual browser checks covered the dashboard, actor list, graph, analysis run and case
detail. Other pages were verified by build/type checks and their API calls, not by
clicking every control.

## External integrations

| Integration | Executed? | Result |
| --- | --- | --- |
| MITRE ATT&CK | No full import in this session | Code repaired; endpoint and UI available; upstream bundle is large and import was not run to avoid unrequested database growth |
| APTnotes | No | Adapter implemented against the public JSON index; not fetched in this session |
| URLhaus | No | Adapter implemented against the public recent-URL API; not fetched in this session |
| ThreatFox | No | Blocked: no abuse.ch Auth-Key configured |

## Limitations of this report

* No frontend unit/component or browser-automation suite exists, so UI behaviour is
  covered by type checking, production build and the manual checks listed above.
* Oxlint could not execute because the host blocked its native binary; no lint
  findings were produced or suppressed.
* External feed imports were not executed; their availability is reported by the
  running API, not proven end-to-end here.
* Silhouette 0.5013 reflects the current synthetic dataset and will change with data.
* Duplicate synthetic actors from an earlier seed run remain; see
  `PROJECT_COMPLETION_AUDIT.md`.
