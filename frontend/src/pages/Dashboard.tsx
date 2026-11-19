import { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../services/api";
import { Badge, Card, ErrorState, LoadingState, PageHeader, Stat, statusTone } from "../components/ui";

const COLORS = ["#22d3ee", "#3b82f6", "#a855f7", "#f472b6", "#fbbf24", "#34d399", "#f97316"];

type Stats = Record<string, number | string | null>;

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({});
  const [categories, setCategories] = useState<{ name: string; value: number }[]>([]);
  const [activity, setActivity] = useState<{ date: string; count: number }[]>([]);
  const [sources, setSources] = useState<{ name: string; value: number }[]>([]);
  const [relationships, setRelationships] = useState<{ name: string; value: number }[]>([]);
  const [origins, setOrigins] = useState<{ name: string; value: number }[]>([]);
  const [recent, setRecent] = useState<
    { id: number; source: string; status: string; records: number; started: string }[]
  >([]);
  const [log, setLog] = useState<
    { id: number; user: string; action: string; details: string; created_at: string }[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, cat, act, src, rel, org, jobs, activityLog] = await Promise.all([
        api.dashboard.stats(),
        api.dashboard.category(),
        api.dashboard.activity(),
        api.dashboard.sources(),
        api.dashboard.relationships(),
        api.dashboard.origin(),
        api.dashboard.recent(),
        api.dashboard.activityLog(),
      ]);
      setStats(statsData);
      setCategories(cat);
      setActivity(act);
      setSources(src);
      setRelationships(rel);
      setOrigins(org);
      setRecent(jobs);
      setLog(activityLog);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <LoadingState label="Loading intelligence overview…" />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const cards: { label: string; key: string; hint?: string; tone?: "cyan" | "violet" | "amber" | "green" }[] = [
    { label: "Pseudonymous actors", key: "actors", tone: "cyan" },
    { label: "Identifiers", key: "identifiers", tone: "cyan" },
    { label: "Relationships", key: "relationships", hint: `${stats.direct_relationships ?? 0} direct · ${stats.inferred_relationships ?? 0} inferred` },
    { label: "Infrastructure indicators", key: "infra", tone: "violet" },
    { label: "Intelligence sources", key: "sources", hint: `${stats.synthetic_sources ?? 0} synthetic` },
    { label: "Timeline events", key: "timeline_events" },
    { label: "Analysis results", key: "analyses", tone: "green" },
    { label: "Reviews pending", key: "investigations_review", tone: "amber" },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Intelligence Dashboard"
        subtitle="All figures are read live from the platform database. Synthetic demonstration records are counted separately from external intelligence."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => (
          <Stat
            key={card.key}
            label={card.label}
            value={stats[card.key] ?? 0}
            hint={card.hint}
            tone={card.tone ?? "slate"}
          />
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card title="Threat category distribution" className="lg:col-span-2">
          <div className="h-64">
            {categories.length === 0 ? (
              <p className="flex h-full items-center justify-center text-sm text-slate-500">
                No actor categories recorded yet.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={categories}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={90}
                    paddingAngle={2}
                  >
                    {categories.map((entry, index) => (
                      <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value) => [`${value} actors`, "Actors"]} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title="Data provenance" subtitle="Synthetic vs real intelligence">
          <div className="mb-3 flex flex-wrap gap-2">
            <Badge tone="amber">{stats.actors_synthetic ?? 0} synthetic actors</Badge>
            <Badge tone="cyan">{stats.actors_external ?? 0} external actors</Badge>
            <Badge tone="slate">{stats.actors_manual ?? 0} manual actors</Badge>
          </div>
          <div className="h-44">
            {origins.length === 0 ? (
              <p className="flex h-full items-center justify-center text-sm text-slate-500">
                No provenance data.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={origins}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={11} />
                  <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#a855f7" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card title="Activity over time" subtitle="All dated timeline events, grouped by day">
          <div className="h-64">
            {activity.length === 0 ? (
              <p className="flex h-full items-center justify-center text-sm text-slate-500">
                No dated activity in the last 90 days.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={activity}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="date" stroke="#94a3b8" fontSize={10} />
                  <YAxis stroke="#94a3b8" fontSize={10} allowDecimals={false} />
                  <Tooltip />
                  <Line type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title="Relationship basis" subtitle="How links were established">
          <div className="h-64">
            {relationships.length === 0 ? (
              <p className="flex h-full items-center justify-center text-sm text-slate-500">
                No relationships yet — build them from the Relationship Explorer.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={relationships}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={10} />
                  <YAxis stroke="#94a3b8" fontSize={10} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card title="Collection jobs" subtitle="Most recent imports">
          {recent.length === 0 ? (
            <p className="text-sm text-slate-500">No collection jobs recorded yet.</p>
          ) : (
            <ul className="divide-y divide-slate-800">
              {recent.map((job) => (
                <li key={job.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <div className="min-w-0">
                    <div className="truncate text-slate-200">{job.source}</div>
                    <div className="text-xs text-slate-500">
                      {job.records} records · {new Date(job.started).toLocaleString()}
                    </div>
                  </div>
                  <Badge tone={statusTone(job.status)}>{job.status}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Analyst activity" subtitle="Audit trail (latest 20 actions)">
          {log.length === 0 ? (
            <p className="text-sm text-slate-500">No audited actions yet.</p>
          ) : (
            <ul className="divide-y divide-slate-800">
              {log.map((entry) => (
                <li key={entry.id} className="py-2 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-mono text-xs text-cyan-300">{entry.action}</span>
                    <span className="text-xs text-slate-500">
                      {entry.user} · {new Date(entry.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="truncate text-xs text-slate-400">{entry.details}</div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card title="Intelligence sources" subtitle="Records per source">
          <div className="h-52">
            {sources.length === 0 ? (
              <p className="flex h-full items-center justify-center text-sm text-slate-500">
                No sources recorded.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sources}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={10} />
                  <YAxis stroke="#94a3b8" fontSize={10} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#34d399" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
        <Card title="Interpretation guidance">
          <ul className="space-y-3 text-sm text-slate-400">
            <li>
              <span className="font-medium text-slate-200">Direct links</span> come from identical
              identifier values (PGP fingerprint, wallet, verified email, infrastructure) and are
              documented observations — not proof of one operator.
            </li>
            <li>
              <span className="font-medium text-slate-200">Inferred links</span> come from
              analytical similarity above the configured threshold and are always marked as
              hypotheses requiring analyst review.
            </li>
            <li>
              <span className="font-medium text-slate-200">Synthetic records</span> are demonstration
              data. Use the origin filters to exclude them before drawing conclusions.
            </li>
          </ul>
        </Card>
      </div>
    </div>
  );
}
