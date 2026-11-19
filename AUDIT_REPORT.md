# AUDIT REPORT

## 1. Implemented (verified)
- Backend FastAPI app with auth (login/register/me), dashboard stats, actors CRUD-lite, ingestion CSV/JSON/record, graph data+build, analysis stylometry/score, infra list, timeline, investigations, reports CSV/JSON/PDF, settings sources/health.
- SQLite DB auto-created, models present, admin seeded.
- ML stylometry (TF-IDF + feature similarity), behavioural (hourly cosine), scoring engine.
- Frontend: Login, Dashboard, Actors, Graph (raw JSON), Analysis (stylometry compare). Routes only these 5 pages.

## 2. Partially implemented
- Graph build creates relationships only on manual POST /graph/build; frontend has no trigger.
- Dashboard counters real but only 6 metrics, no charts.
- Reports PDF only single actor.
- Settings no UI.

## 3. Missing
- Sidebar/navigation, most pages (Infrastructure, Timeline, Investigations, Reports UI, Settings), actor detail, identifier management, filtering/pagination, search.
- Neo4j (fallback NetworkX not wired as DB; only in-memory-ish via SQL). Docker-compose absent.
- Migrations (none; create_all only). Tests none.
- Synthetic seed data (none loaded).
- Audit logs, role enforcement beyond token.

## 4. Broken
- None critical; backend health ok.

## 5. Placeholder/mock
- Graph page dumps JSON instead of Cytoscape visualization.
- No charts (Recharts unused).

## 6. Backend/DB status
- SQLite file exists; 0 actors etc. after seed (only user). Auth works.

## 7. Frontend route inventory
- /login, /, /actors, /graph, /analysis. No others.

## 8. Test results
- No automated tests. Manual: health ok, login returns token, dashboard stats returns zeros.

## 9. Recommended order
1. Seed synthetic data + build graph.
2. Add navigation + missing pages wired to APIs.
3. Add Cytoscape graph + Recharts.
4. Add tests.
5. Add Docker-compose + migrations.
