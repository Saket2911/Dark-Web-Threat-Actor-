import { useEffect, useState } from "react";
import { Download, FileText } from "lucide-react";
import { api, saveBlob } from "../services/api";
import type { Actor, InvestigationSummary } from "../services/api";
import { useToast } from "../components/Toast";
import { Badge, Button, Card, Field, LoadingState, PageHeader, Stat, inputClass } from "../components/ui";

const EXPORTS: { kind: string; label: string; description: string }[] = [
  { kind: "actors", label: "Actors", description: "Actor inventory with origin and status." },
  { kind: "identifiers", label: "Identifiers", description: "Normalised identifiers and reliability." },
  { kind: "relationships", label: "Relationships", description: "All links with basis, score and evidence." },
  { kind: "evidence", label: "Evidence", description: "Evidence records with source provenance." },
  { kind: "timeline", label: "Timeline", description: "Chronological events." },
  { kind: "investigations", label: "Investigations", description: "Case files and status." },
];

export default function Reports() {
  const [stats, setStats] = useState<Record<string, number | string | null>>({});
  const [actors, setActors] = useState<Actor[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [actorId, setActorId] = useState("");
  const [investigationId, setInvestigationId] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const { add } = useToast();

  useEffect(() => {
    Promise.all([
      api.dashboard.stats(),
      api.actors.list({ page_size: 100 }),
      api.investigations.list(),
    ])
      .then(([statsData, actorData, investigationData]) => {
        setStats(statsData);
        setActors(actorData.items);
        setInvestigations(investigationData);
        if (actorData.items[0]) setActorId(String(actorData.items[0].id));
        if (investigationData[0]) setInvestigationId(String(investigationData[0].id));
      })
      .catch((err) => add("error", err instanceof Error ? err.message : "Failed to load report data"))
      .finally(() => setLoading(false));
  }, [add]);

  const download = async (kind: string, format: "csv" | "json") => {
    setBusy(`${kind}-${format}`);
    try {
      const { blob, filename } = await (format === "csv" ? api.reports.csv(kind) : api.reports.json(kind));
      saveBlob(blob, filename);
      add("success", `${filename} downloaded`);
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Export failed");
    } finally {
      setBusy(null);
    }
  };

  const downloadPdf = async (type: "actor" | "investigation") => {
    setBusy(type);
    try {
      const { blob, filename } =
        type === "actor"
          ? await api.reports.pdf(Number(actorId))
          : await api.reports.investigationPdf(Number(investigationId));
      saveBlob(blob, filename);
      add("success", `${filename} downloaded`);
    } catch (err) {
      add("error", err instanceof Error ? err.message : "PDF generation failed");
    } finally {
      setBusy(null);
    }
  };

  if (loading) return <LoadingState label="Preparing report data…" />;

  const counts: Record<string, number> = {
    actors: Number(stats.actors ?? 0),
    identifiers: Number(stats.identifiers ?? 0),
    relationships: Number(stats.relationships ?? 0),
    evidence: Number(stats.evidence ?? 0),
    timeline: Number(stats.timeline_events ?? 0),
    investigations: Number(stats.investigations ?? 0),
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Reports and Exports"
        subtitle="Every export is generated from the live database. CSV cells are neutralised against spreadsheet formula injection."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Actors" value={counts.actors} />
        <Stat label="Identifiers" value={counts.identifiers} />
        <Stat label="Relationships" value={counts.relationships} hint={`${stats.direct_relationships ?? 0} direct`} />
        <Stat label="Investigations" value={counts.investigations} tone="violet" />
      </div>

      <Card title="Structured exports" subtitle="Choose CSV for spreadsheets or JSON for pipeline ingestion.">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {EXPORTS.map((item) => (
            <div key={item.kind} className="rounded-lg border border-slate-800 p-4">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">{item.label}</h3>
                  <p className="text-xs text-slate-500">{item.description}</p>
                </div>
                <Badge tone="slate">{counts[item.kind] ?? 0} rows</Badge>
              </div>
              <div className="mt-3 flex gap-2">
                <Button
                  variant="secondary"
                  className="px-2.5 py-1.5 text-xs"
                  onClick={() => download(item.kind, "csv")}
                  disabled={busy !== null}
                >
                  <Download className="h-3.5 w-3.5" /> CSV
                </Button>
                <Button
                  variant="secondary"
                  className="px-2.5 py-1.5 text-xs"
                  onClick={() => download(item.kind, "json")}
                  disabled={busy !== null}
                >
                  <Download className="h-3.5 w-3.5" /> JSON
                </Button>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card title="Actor PDF report" subtitle="Profile, identifiers, relationships, evidence and hypotheses.">
          <div className="space-y-3">
            <Field label="Actor">
              <select className={inputClass} value={actorId} onChange={(event) => setActorId(event.target.value)}>
                {actors.length === 0 && <option value="">No actors available</option>}
                {actors.map((actor) => (
                  <option key={actor.id} value={actor.id}>
                    {actor.primary_handle || actor.internal_id} #{actor.id}
                  </option>
                ))}
              </select>
            </Field>
            <Button onClick={() => downloadPdf("actor")} disabled={!actorId || busy !== null}>
              <FileText className="h-4 w-4" /> Generate PDF
            </Button>
          </div>
        </Card>

        <Card title="Investigation PDF report" subtitle="Case entities, analyst decisions and limitations.">
          <div className="space-y-3">
            <Field label="Investigation">
              <select
                className={inputClass}
                value={investigationId}
                onChange={(event) => setInvestigationId(event.target.value)}
              >
                {investigations.length === 0 && <option value="">No investigations available</option>}
                {investigations.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.title} #{item.id}
                  </option>
                ))}
              </select>
            </Field>
            <Button onClick={() => downloadPdf("investigation")} disabled={!investigationId || busy !== null}>
              <FileText className="h-4 w-4" /> Generate PDF
            </Button>
          </div>
        </Card>
      </div>

      <Card title="Export provenance">
        <p className="text-sm text-slate-400">
          JSON exports include a <code className="text-slate-300">provenance_note</code> and a record count.
          Records with <code className="text-slate-300">origin=synthetic</code> are demonstration data and must not
          be treated as real-world intelligence. Reports are analytical products: shared identifiers and
          similarity scores are indicators, not proof of identity.
        </p>
      </Card>
    </div>
  );
}
