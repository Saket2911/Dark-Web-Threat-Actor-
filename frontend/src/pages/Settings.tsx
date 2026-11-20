import { useCallback, useEffect, useState } from "react";
import { Play, RefreshCw } from "lucide-react";
import { api, getRole } from "../services/api";
import { useToast } from "../components/Toast";
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  inputClass,
  statusTone,
} from "../components/ui";

type Feed = {
  key: string;
  name: string;
  description: string;
  requires_key: boolean;
  configured: boolean;
  status: string;
  reason: string;
  docs?: string;
  produces?: string;
  last_job?: {
    status: string;
    fetched: number;
    imported: number;
    updated: number;
    skipped: number;
    rejected: number;
    relationships_created: number;
    error_count: number;
    finished?: string | null;
  } | null;
  source_record?: {
    last_success_at?: string | null;
    last_object_count?: number | null;
    last_error?: string | null;
  } | null;
};

type Source = {
  id: number;
  name: string;
  type: string;
  reliability: number;
  is_synthetic: boolean;
  origin: string;
  url: string | null;
  collected_at: string;
  last_success_at?: string | null;
  last_error?: string | null;
  last_object_count?: number | null;
};

export default function Settings() {
  const [system, setSystem] = useState<Record<string, any> | null>(null);
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [thresholds, setThresholds] = useState<Record<string, number>>({});
  const [models, setModels] = useState<Record<string, any> | null>(null);
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [inferText, setInferText] = useState("");
  const [inferResult, setInferResult] = useState<Record<string, any> | null>(null);
  const { add } = useToast();
  const isAdmin = getRole() === "admin";

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [systemData, weightData, thresholdData, modelData, feedData, sourceData] = await Promise.all([
        api.settings.system(),
        api.settings.weights(),
        api.settings.thresholds(),
        api.settings.models(),
        api.settings.feeds(),
        api.settings.sources(),
      ]);
      setSystem(systemData);
      setWeights(weightData);
      setThresholds(thresholdData);
      setModels(modelData);
      setFeeds(feedData as unknown as Feed[]);
      setSources(sourceData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const runFeed = async (key: string) => {
    setRunning(key);
    try {
      const result = await api.ingestion.ingestFeed(key, 100);
      const imported = Number(result.imported ?? result.records_imported ?? 0);
      add("success", `${key} import finished — ${imported} record(s) imported`);
      load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : `${key} import failed`);
    } finally {
      setRunning(null);
    }
  };

  const train = async () => {
    setRunning("train");
    try {
      const result = await api.analysis.train();
      add("success", `Style model trained on ${result.samples ?? "available"} samples`);
      const [modelData, modelRegistry] = await Promise.all([api.analysis.modelStatus(), api.settings.models()]);
      setModels({ ...modelRegistry, persisted: modelData });
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Training failed");
    } finally {
      setRunning(null);
    }
  };

  const infer = async () => {
    if (!inferText.trim()) {
      add("error", "Provide a text sample");
      return;
    }
    setRunning("infer");
    try {
      setInferResult(await api.analysis.infer(inferText));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Inference failed");
    } finally {
      setRunning(null);
    }
  };

  if (loading) return <LoadingState label="Loading configuration…" />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const persisted = (models?.persisted ?? {}) as Record<string, any>;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Settings and System Status"
        subtitle="Only configuration that is genuinely implemented is shown. Secrets are never returned by the API."
        actions={
          <Button variant="secondary" onClick={load}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card title="Platform">
          <dl className="grid grid-cols-2 gap-3 text-sm">
            {[
              ["Application", system?.app_name],
              ["Version", system?.version],
              ["Environment", system?.environment],
              ["Database driver", system?.database?.driver],
              ["Database", system?.database?.path],
              ["Database present", system?.database?.exists ? "yes" : "no"],
              ["Actor rows", system?.database?.actors],
              ["Identifier rows", system?.database?.identifiers],
              ["Relationship rows", system?.database?.relationships],
              ["Upload limit", `${Math.round(Number(system?.uploads?.max_bytes ?? 0) / 1024)} KB`],
              ["Auth scheme", system?.auth?.scheme],
              ["Password hashing", system?.auth?.password_hashing],
              ["Token TTL", `${system?.auth?.token_ttl_minutes} min`],
              ["JWT secret configured", system?.auth?.secret_key_configured ? "yes" : "no"],
            ].map(([label, value]) => (
              <div key={String(label)}>
                <dt className="text-xs uppercase text-slate-500">{label}</dt>
                <dd className="break-words text-slate-200">{String(value ?? "—")}</dd>
              </div>
            ))}
          </dl>
        </Card>

        <Card title="Scoring weights" subtitle="Used by the explainable attribution model.">
          <div className="space-y-2">
            {Object.entries(weights).map(([key, value]) => (
              <div key={key}>
                <div className="flex items-center justify-between text-sm">
                  <span className="capitalize text-slate-300">{key}</span>
                  <span className="text-cyan-300">{value.toFixed(2)}</span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded bg-slate-800">
                  <div className="h-full bg-cyan-500" style={{ width: `${Math.min(100, value * 100)}%` }} />
                </div>
              </div>
            ))}
            <p className="pt-2 text-xs text-slate-500">
              Total weight {Object.values(weights).reduce((sum, value) => sum + value, 0).toFixed(2)}. Missing
              evidence lowers coverage and the model reports it rather than inventing a score.
            </p>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card title="Decision thresholds">
          <dl className="grid grid-cols-2 gap-3 text-sm">
            {Object.entries(thresholds).map(([key, value]) => (
              <div key={key}>
                <dt className="text-xs uppercase text-slate-500">{key.replace(/_/g, " ")}</dt>
                <dd className="text-slate-200">
                  {key === "upload_limit_bytes"
                    ? `${Math.round(value / 1024)} KB`
                    : value}
                </dd>
              </div>
            ))}
          </dl>
        </Card>

        <Card title="Models" subtitle={String(models?.note ?? "")}>
          <ul className="space-y-2 text-sm">
            {(models?.deterministic as Record<string, any>[] | undefined)?.map((model) => (
              <li key={model.name} className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-slate-200">{model.name}</div>
                  <div className="text-xs text-slate-500">{model.detail}</div>
                </div>
                <Badge tone={model.available ? "green" : "red"}>{model.available ? "available" : "unavailable"}</Badge>
              </li>
            ))}
          </ul>
          <div className="mt-4 rounded-lg border border-slate-800 p-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm text-slate-200">Persisted style-inference model</span>
              <Badge tone={persisted.trained ? "green" : "amber"}>
                {persisted.trained ? "trained" : "not trained"}
              </Badge>
            </div>
            {persisted.trained && (
              <p className="text-xs text-slate-500">
                {persisted.actor_count ?? 0} actor centroids · {persisted.sample_count ?? 0} samples ·
                trained {persisted.trained_at ?? "—"}
              </p>
            )}
            <div className="mt-2 flex flex-wrap gap-2">
              <Button
                variant="secondary"
                disabled={!isAdmin || running !== null}
                onClick={train}
                title={isAdmin ? "Train model" : "Admin role required"}
              >
                <Play className="h-4 w-4" /> {running === "train" ? "Training…" : "Train model"}
              </Button>
            </div>
          </div>

          <div className="mt-4 space-y-2">
            <Field label="Single-text inference">
              <textarea
                className={inputClass}
                rows={3}
                value={inferText}
                onChange={(event) => setInferText(event.target.value)}
                placeholder="Paste a writing sample…"
              />
            </Field>
            <Button variant="secondary" onClick={infer} disabled={running !== null || !persisted.trained}>
              Run inference
            </Button>
            {inferResult && (
              <div className="rounded-lg border border-slate-800 p-3 text-xs text-slate-300">
                <div>
                  Predicted:{" "}
                  <span className="text-cyan-300">
                    {inferResult.predicted_handle || "no match"} (#{inferResult.predicted_actor_id ?? "—"})
                  </span>{" "}
                  · score {Number(inferResult.score ?? 0).toFixed(3)}
                </div>
                <div className="mt-1 text-slate-500">{inferResult.note}</div>
              </div>
            )}
          </div>
        </Card>
      </div>

      <Card title="External intelligence feeds" subtitle="Documented public interfaces only. Unavailable feeds say so.">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {feeds.map((feed) => (
            <div key={feed.key} className="rounded-lg border border-slate-800 p-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-200">{feed.name}</h3>
                <Badge tone={statusTone(feed.status)}>{feed.status}</Badge>
              </div>
              <p className="mt-1 text-xs text-slate-500">{feed.description}</p>
              <p className="mt-2 text-xs text-slate-400">{feed.reason}</p>
              {feed.produces && <p className="mt-1 text-xs text-slate-600">{feed.produces}</p>}
              <dl className="mt-2 space-y-1 text-xs text-slate-400">
                <div>
                  <dt className="inline text-slate-500">Last successful import: </dt>
                  <dd className="inline">
                    {feed.source_record?.last_success_at
                      ? new Date(feed.source_record.last_success_at).toLocaleString()
                      : "never"}
                  </dd>
                </div>
                {feed.last_job && (
                  <div>
                    <dt className="inline text-slate-500">Last run: </dt>
                    <dd className="inline">
                      {feed.last_job.status} · {feed.last_job.imported} entities stored /{" "}
                      {feed.last_job.fetched} fetched · {feed.last_job.rejected} rejected
                      {feed.last_job.relationships_created > 0 && (
                        <span> · {feed.last_job.relationships_created} relationships</span>
                      )}
                      {feed.last_job.error_count > 0 && (
                        <span className="text-amber-400"> · {feed.last_job.error_count} error(s)</span>
                      )}
                    </dd>
                  </div>
                )}
              </dl>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  className="px-2.5 py-1.5 text-xs"
                  disabled={running !== null || !feed.configured}
                  onClick={() => runFeed(feed.key)}
                >
                  <Play className="h-3.5 w-3.5" />
                  {running === feed.key ? "Running…" : "Run import"}
                </Button>
                {feed.docs && (
                  <a
                    href={feed.docs}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-cyan-400 hover:underline"
                  >
                    Docs
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>

        <div className="mt-4 rounded-lg border border-slate-800 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">MITRE ATT&CK</h3>
              <p className="text-xs text-slate-500">
                Official enterprise STIX bundle: techniques, tactics, malware, tools and groups with
                ATT&CK external IDs.
              </p>
            </div>
            <Button
              variant="secondary"
              disabled={!isAdmin || running !== null}
              onClick={async () => {
                setRunning("mitre");
                try {
                  const result = await api.ingestion.mitre();
                  add(
                    "success",
                    `MITRE ATT&CK: ${Number(result.records_imported ?? 0)} objects imported, ${Number(
                      result.relationships_created ?? 0,
                    )} relationships created`,
                  );
                } catch (err) {
                  add("error", err instanceof Error ? err.message : "MITRE import failed");
                } finally {
                  setRunning(null);
                }
              }}
              title={isAdmin ? "Import ATT&CK" : "Admin role required"}
            >
              <Play className="h-3.5 w-3.5" /> {running === "mitre" ? "Importing…" : "Import ATT&CK"}
            </Button>
          </div>
        </div>
      </Card>

      <Card title="Intelligence sources" subtitle="Provenance of every record; synthetic sources are labelled.">
        {sources.length === 0 ? (
          <p className="text-sm text-slate-500">No sources recorded.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-xs uppercase text-slate-400">
                  <th className="py-2">Name</th>
                  <th className="py-2">Type</th>
                  <th className="py-2">Origin</th>
                  <th className="py-2">Reliability</th>
                  <th className="py-2">Synthetic</th>
                  <th className="py-2">Last success</th>
                  <th className="py-2">Collected</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => (
                  <tr key={source.id} className="border-b border-slate-800/60">
                    <td className="py-2 text-slate-200">{source.name}</td>
                    <td className="py-2 text-xs text-slate-400">{source.type}</td>
                    <td className="py-2">
                      <Badge tone={source.origin === "synthetic" ? "amber" : source.origin === "external" ? "cyan" : "slate"}>
                        {source.origin}
                      </Badge>
                    </td>
                    <td className="py-2 text-xs text-slate-400">{source.reliability.toFixed(2)}</td>
                    <td className="py-2 text-xs text-slate-400">{source.is_synthetic ? "yes" : "no"}</td>
                    <td className="py-2 text-xs text-slate-500">
                      {source.last_success_at ? new Date(source.last_success_at).toLocaleDateString() : "—"}
                      {source.last_error && (
                        <span className="ml-1 text-amber-400" title={source.last_error}>
                          error
                        </span>
                      )}
                    </td>
                    <td className="py-2 text-xs text-slate-500">
                      {source.collected_at ? new Date(source.collected_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
