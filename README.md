# Dark Web Threat Actor De-anonymization and Intelligence Platform

An intelligence-analysis and decision-support platform for investigating pseudonymous
threat actors. Analysts can correlate accounts through shared identifiers, inspect
writing-style and behavioural similarity, map infrastructure associations, review
relationships in a case workflow, and export reports.

The platform produces **investigative hypotheses**, never identity verdicts. Direct
links come only from identical, normalised identifiers; every analytical link is
labelled as an inference and requires analyst review.

## Stack

| Layer | Technology |
| --- | --- |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2, SQLite, Alembic, Pydantic v2 |
| Auth | JWT (HS256), PBKDF2-SHA256 password hashing, admin/analyst roles |
| Analysis | scikit-learn (TF-IDF, K-Means, DBSCAN), NetworkX, NumPy |
| Reporting | CSV, JSON, ReportLab PDF |
| Frontend | React 19, TypeScript, Vite 8, Tailwind CSS, Cytoscape.js, Recharts |

## Repository layout

```
backend/
  app/api/          REST routers (auth, actors, ingestion, graph, analysis, infra,
                    timeline, investigations, reports, settings, dashboard, health)
  app/core/         configuration, security, dependencies, time helpers
  app/database/     engine/session configuration
  app/models/       SQLAlchemy models
  app/schemas/      Pydantic request/response models
  app/services/     audit, identifier normalisation, relationship engine/validator
  app/ml/           stylometry, behavioural, scoring, clustering, inference
  app/ingestion/    record processor, CSV/JSON, STIX 2.1, public feeds, MITRE ATT&CK
  migrations/       Alembic environment and revisions
  scripts/          seed.py, dedupe_synthetic.py
  tests/            pytest suite (67 tests)
  data/app.db       canonical SQLite database
frontend/
  src/pages/        Login, Dashboard, Actors, ActorProfile, Graph, Analysis,
                    Infrastructure, Timeline, Investigations, Reports, Settings
  src/services/api.ts   typed API client
  src/components/   shared UI primitives and toast notifications
  src/layouts/      application shell and navigation
```

## Quick start (Windows, PowerShell/Git Bash)

```bash
# Backend
cd backend
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
./.venv/Scripts/python.exe -m alembic upgrade head
./.venv/Scripts/python.exe scripts/seed.py          # idempotent demonstration data
./.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend (second terminal)
cd frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open <http://127.0.0.1:5173>. API docs: <http://127.0.0.1:8000/docs>.

Linux/macOS uses `backend/.venv/bin/python` in the same commands.

### Default development accounts

| Username | Password | Role |
| --- | --- | --- |
| `admin` | `admin123` | admin |
| `analyst` | `analyst123` | analyst |

These accounts are seeded demonstration credentials. Change or remove them before
any non-local deployment.

## Configuration

Configuration is read from `backend/.env` or the project-root `.env` (the root file
wins when both define a key). Copy `.env.example` to `.env` and set:

* `SECRET_KEY` – required for production; the app logs a warning while it is the
  placeholder value.
* `DATABASE_URL` – defaults to `sqlite:///./data/app.db`, resolved against
  `backend/`, so commands work from any working directory.
* `CORS_ORIGINS` – comma-separated browser origins. Defaults to the two Vite
  development origins; `*` is rejected for anything beyond local experiments.
* `ABUSE_CH_AUTH_KEY` – optional; required only for ThreatFox.

Secrets are never returned by the API. `/api/settings/system` reports only whether
the JWT secret is configured.

## Database and migrations

The canonical database is `backend/data/app.db`; current Alembic head is
`b7c1d2e3f4a5` (query indexes). Migrations are additive and were applied without
resetting existing rows.

```bash
cd backend
./.venv/Scripts/python.exe -m alembic current
./.venv/Scripts/python.exe -m alembic upgrade head
```

A stale database from the earlier layout may exist at `data/app.db` (project root).
It is not used by the application. Remove it only after taking a backup and
confirming it contains nothing you need.

### Demonstration data and provenance

`scripts/seed.py` is idempotent: it reuses existing demo actors and records, and
creates only what is missing. It seeds six scenarios (shared PGP fingerprint, similar
writing, similar hourly behaviour, marketplace migration, superficially similar but
unrelated writing, conflicting evidence), analysis results derived from the seeded
samples, direct relationships built from shared identifiers, one inferred hypothesis,
and an investigation with a pending review.

All demonstration actors use `origin='synthetic'` and their sources are marked
`is_synthetic=true`. The UI exposes origin filters and labels synthetic evidence, so
synthetic records remain distinguishable from external intelligence.

An earlier run created multiple copies of each demo handle. `scripts/dedupe_synthetic.py`
reports those groups (dry-run by default). It only removes duplicates that have no
dependent records, and `--apply` additionally requires `--yes`. Duplicates with
identifiers, evidence or relationships are reported as skipped and must be merged by
an analyst.

## Testing

```bash
cd backend
./.venv/Scripts/python.exe -m pytest tests -q

cd ../frontend
npm run build      # tsc -b && vite build
npm run lint       # oxlint (requires its native binary to be permitted by the host)
```

The backend suite uses a temporary SQLite database per test session
(`tests/conftest.py`), so it never touches `backend/data/app.db`. See
`TEST_REPORT.md` for the latest results.

## API overview

All endpoints are under `/api` and require a bearer token except `/auth/login` and
`/health`.

| Area | Endpoints |
| --- | --- |
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/register` (admin), users list (admin) |
| Actors | `GET/POST /actors`, `GET/PATCH/DELETE /actors/{id}`, `/profile`, `/identifiers`, `/handles`, `/evidence`, `/timeline`, `GET /actors/categories` |
| Ingestion | `POST /ingestion/record`, `/csv`, `/json`, `/stix`, `/mitre-attack`, `/feeds/{key}`, `GET /ingestion/jobs`, `/ingestion/feeds` |
| Graph | `GET /graph/data`, `/stats`, `/components`, `/clusters`, `/relationships/{id}`; `POST /graph/build`, `/infer`, `/relationships` |
| Analysis | `POST /analysis/stylometry`, `/behavioural`, `/score`, `/cluster`, `/cluster/kmeans`, `/cluster/behavioural`; models train/infer/batch/status; `GET /analysis/history` |
| Infrastructure | `GET/POST /infrastructure`, `GET /infrastructure/{id}`, `/associations` |
| Timeline | `GET/POST /timeline`, `GET /timeline/summary` |
| Investigations | `GET/POST /investigations`, `GET/PATCH/DELETE /investigations/{id}`, `/entities`, `/review`, `/reviews` |
| Reports | `GET /reports/export/csv?kind=`, `/export/json?kind=`, `/pdf/{actor_id}`, `/pdf/investigation/{id}` |
| Dashboard | `GET /dashboard/stats`, `/charts/{category,activity,sources,identifiers,relationships,origin}`, `/recent`, `/activity-log` |
| Settings | `/settings/sources`, `/weights/default`, `/thresholds`, `/models`, `/feeds`, `/system`, `/health` |

Export kinds: `actors`, `identifiers`, `relationships`, `evidence`, `timeline`,
`investigations`.

## External intelligence

| Source | Interface | Status |
| --- | --- | --- |
| MITRE ATT&CK | Official enterprise STIX bundle from `mitre-attack/attack-stix-data` | Implemented; import is admin-only and can be run from Settings |
| APTnotes | Public JSON index on GitHub | Implemented, no key required |
| URLhaus | abuse.ch public recent-URL endpoint | Implemented, no key required |
| ThreatFox | abuse.ch IOC API | Implemented but disabled without `ABUSE_CH_AUTH_KEY`; the API reports `blocked_missing_credentials` rather than pretending to work |

Feeds use timeouts, bounded retries with backoff, 429 handling, provenance records and
deduplication on the feed record ID. Availability depends on the upstream service and
network access. No restricted service is scraped and no access control is bypassed.

## Analysis semantics

* **Stylometry** – word 1–2 gram TF-IDF cosine (55%) plus lexical/punctuation closeness
  (45%). Short samples and identical text are flagged; identical samples are not treated
  as independent evidence.
* **Behavioural** – cosine similarity of normalised 24-bin hourly activity histograms.
  Fewer than three events per actor is marked insufficient; low-event scores are shown
  as indicative only.
* **Attribution** – weighted mean over *available* features with a coverage figure.
  Missing evidence lowers coverage; coverage below 40% caps the result at
  "Insufficient". Contributions are reported per feature and the same underlying
  evidence is not counted twice.
* **Clustering** – K-Means over standardised structural features, DBSCAN over hourly
  activity vectors with cosine metric. Small datasets return an explicit
  `insufficient_data` result. Silhouette is only reported when mathematically defined.

## Known limitations

* The database is SQLite with no concurrent-writer scaling; suitable for single-analyst
  or small-team deployments.
* Similarity scores depend on sample quality. Copied text, shared templates, common
  time zones and shared hosting can inflate scores.
* Synthetic demonstration records remain in the database and are labelled, not hidden.
* Duplicate synthetic handles created by an earlier seed run have not been merged
  because merging requires analyst decisions; use `scripts/dedupe_synthetic.py` to
  review them.
* ThreatFox cannot be exercised without an abuse.ch key.
* Frontend bundle is a single ~1.3 MB chunk (385 KB gzip); code splitting is not
  configured.
* No automated browser end-to-end suite is configured; integration checks were run
  against the live servers and are documented in `TEST_REPORT.md`.

## Documentation

* `PROJECT_COMPLETION_AUDIT.md` – original state, defects, root causes, fixes.
* `IMPLEMENTATION_STATUS.md` – phase-by-phase completion status.
* `TEST_REPORT.md` – executed tests, results and limitations.
* `AUDIT_REPORT.md` – historical audit retained for reference.
#   D a r k - W e b - T h r e a t - A c t o r -  
 