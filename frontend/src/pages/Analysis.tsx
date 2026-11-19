import { useEffect, useState } from "react";
import { Play } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../services/api";
import type { Actor, AttributionResult, ClusterResult } from "../services/api";
import { useToast } from "../components/Toast";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  LoadingState,
  PageHeader,
  formatDateTime,
  inputClass,
  statusTone,
} from "../components/ui";

const TABS = ["attribution", "style", "behaviour", "clustering", "models", "history"] as const;
type Tab = (typeof TABS)[number];

type StylometryResult = Awaited<ReturnType<typeof api.analysis.stylometry>>;
type BehaviourResult = Awaited<ReturnType<typeof api.analysis.behavioural>>;

export default function Analysis() {
  const [actors, setActors] = useState<Actor[]>([]);
  const [actorA, setActorA] = useState("");
  const [actorB, setActorB] = useState("");
  const [tab, setTab] = useState<Tab>("attribution");
  const [busy, setBusy] = useState<string | null>(null);
  const [attribution, setAttribution] = useState<AttributionResult | null>(null);
  const [styleA, setStyleA] = useState("");
  const [styleB, setStyleB] = useState("");
  const [style, setStyle] = useState<StylometryResult | null>(null);
  const [behaviour, setBehaviour] = useState<BehaviourResult | null>(null);
  const [cluster, setCluster] = useState<ClusterResult | null>(null);
  const [method, setMethod] = useState<"kmeans" | "dbscan">("kmeans");
  const [k, setK] = useState(3);
  const [eps, setEps] = useState(0.5);
  const [minSamples, setMinSamples] = useState(2);
  const [modelStatus, setModelStatus] = useState<Record<string, any> | null>(null);
  const [inferText, setInferText] = useState("");
  const [inferResult, setInferResult] = useState<Record<string, any> | null>(null);
  const [batchText, setBatchText] = useState("");
  const [batchResult, setBatchResult] = useState<Record<string, any> | null>(null);
  const [history, setHistory] = useState<Awaited<ReturnType<typeof api.analysis.history>>>([]);
  const { add } = useToast();

  const loadActors = () => {
    api.actors
      .list({ page_size: 100, sort: "handle" })
      .then((data) => {
        setActors(data.items);
        if (data.items[0]) setActorA(String(data.items[0].id));
        if (data.items[1]) setActorB(String(data.items[1].id));
      })
      .catch((err) => add("error", err instanceof Error ? err.message : "Failed to load actors"));
  };

  useEffect(() => {
    loadActors();
  }, []);

  useEffect(() => {
    if (tab === "history") {
      api.analysis
        .history()
        .then(setHistory)
        .catch((err) => add("error", err instanceof Error ? err.message : "Failed to load history"));
    }
    if (tab === "models") {
      api.analysis
        .modelStatus()
        .then(setModelStatus)
        .catch((err) => add("error", err instanceof Error ? err.message : "Failed to load model status"));
    }
  }, [tab, add]);

  const guardPair = () => {
    if (!actorA || !actorB) {
      add("error", "Select two actors");
      return false;
    }
    if (actorA === actorB) {
      add("error", "Select two different actors");
      return false;
    }
    return true;
  };

  const runAttribution = async () => {
    if (!guardPair()) return;
    setBusy("attribution");
    try {
      setAttribution(await api.analysis.score(Number(actorA), Number(actorB)));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Attribution failed");
    } finally {
      setBusy(null);
    }
  };

  const runStyle = async () => {
    setBusy("style");
    try {
      setStyle(await api.analysis.stylometry(styleA, styleB));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Stylometry failed");
    } finally {
      setBusy(null);
    }
  };

  const runBehaviour = async () => {
    if (!guardPair()) return;
    setBusy("behaviour");
    try {
      setBehaviour(await api.analysis.behavioural(Number(actorA), Number(actorB)));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Behavioural analysis failed");
    } finally {
      setBusy(null);
    }
  };

  const runCluster = async () => {
    setBusy("cluster");
    try {
      setCluster(
        await api.analysis.cluster(method, method === "kmeans" ? { k } : { eps, min_samples: minSamples }),
      );
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Clustering failed");
    } finally {
      setBusy(null);
    }
  };

  const train = async () => {
    setBusy("train");
    try {
      const result = await api.analysis.train();
      add("success", `Model trained (${result.samples ?? 0} samples)`);
      setModelStatus(await api.analysis.modelStatus());
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Training failed");
    } finally {
      setBusy(null);
    }
  };

  const infer = async () => {
    setBusy("infer");
    try {
      setInferResult(await api.analysis.infer(inferText));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Inference failed");
    } finally {
      setBusy(null);
    }
  };

  const batch = async () => {
    const texts = batchText
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    if (texts.length === 0) {
      add("error", "Add at least one text (one per line)");
      return;
    }
    setBusy("batch");
    try {
      setBatchResult(await api.analysis.batch(texts));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Batch inference failed");
    } finally {
      setBusy(null);
    }
  };

  const actorName = (id: number) => {
    const actor = actors.find((item) => item.id === id);
    return actor?.primary_handle || `Actor ${id}`;
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="AI Analysis"
        subtitle="Writing-style, behavioural, temporal and identifier evidence are combined into an explainable investigative hypothesis. Scores are never presented as proof of identity."
      />

      <Card>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Actor A">
            <select className={inputClass} value={actorA} onChange={(event) => setActorA(event.target.value)}>
              {actors.length === 0 && <option value="">No actors</option>}
              {actors.map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.primary_handle || actor.internal_id} (#{actor.id}, {actor.origin})
                </option>
              ))}
            </select>
          </Field>
          <Field label="Actor B">
            <select className={inputClass} value={actorB} onChange={(event) => setActorB(event.target.value)}>
              {actors.length === 0 && <option value="">No actors</option>}
              {actors.map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.primary_handle || actor.internal_id} (#{actor.id}, {actor.origin})
                </option>
              ))}
            </select>
          </Field>
        </div>
      </Card>

      <div className="flex flex-wrap gap-1 border-b border-slate-800">
        {TABS.map((item) => (
          <button
            key={item}
            onClick={() => setTab(item)}
            className={
              tab === item
                ? "border-b-2 border-cyan-400 px-3 py-2 text-sm font-medium capitalize text-cyan-300"
                : "border-b-2 border-transparent px-3 py-2 text-sm capitalize text-slate-400 hover:text-slate-200"
            }
          >
            {item === "style" ? "stylometry" : item}
          </button>
        ))}
      </div>

      {tab === "attribution" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <Card title="Weighted attribution" subtitle="Coverage-aware scoring with per-feature contributions.">
            <Button onClick={runAttribution} disabled={busy !== null}>
              <Play className="h-4 w-4" /> {busy === "attribution" ? "Scoring…" : "Run attribution"}
            </Button>
            <p className="mt-3 text-xs text-slate-500">
              Strong identifiers (PGP, wallet, email) are the only features that can produce a strong
              band; every other feature is corroborating context. Missing evidence reduces coverage and
              can cap the category at “Insufficient”.
            </p>
          </Card>

          <Card title="Result">
            {!attribution ? (
              <EmptyState title="No attribution run yet" message="Select two actors and run the model." />
            ) : (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-3xl font-bold text-cyan-300">
                    {attribution.final.toFixed(2)}
                  </span>
                  <Badge
                    tone={
                      attribution.category.startsWith("Strong")
                        ? "green"
                        : attribution.category.startsWith("Moderate")
                          ? "cyan"
                          : attribution.category.startsWith("Weak")
                            ? "amber"
                            : "red"
                    }
                  >
                    {attribution.category}
                  </Badge>
                  <Badge tone="slate">coverage {(attribution.coverage * 100).toFixed(0)}%</Badge>
                  {attribution.analysis_id && <Badge tone="violet">analysis #{attribution.analysis_id}</Badge>}
                </div>
                <div className="h-44">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={attribution.contributions} layout="vertical" margin={{ left: 40 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                      <XAxis type="number" domain={[0, 1]} stroke="#94a3b8" fontSize={10} />
                      <YAxis type="category" dataKey="feature" width={90} stroke="#94a3b8" fontSize={10} />
                      <Tooltip />
                      <Bar dataKey="contribution" fill="#22d3ee" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <p className="text-sm text-slate-300">{attribution.explanation}</p>
                <p className="rounded border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-amber-200">
                  {attribution.hypothesis}
                </p>
                {attribution.missing_evidence.length > 0 && (
                  <p className="text-xs text-slate-500">
                    Missing evidence: {attribution.missing_evidence.join(", ")}
                  </p>
                )}
                <ul className="list-disc space-y-1 pl-5 text-xs text-slate-500">
                  {attribution.limitations.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </Card>

          {attribution && (
            <Card title="Feature detail" className="lg:col-span-2">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 text-left text-xs uppercase text-slate-400">
                      <th className="py-2">Feature</th>
                      <th className="py-2">Similarity</th>
                      <th className="py-2">Weight</th>
                      <th className="py-2">Contribution</th>
                      <th className="py-2">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attribution.contributions.map((item) => (
                      <tr key={item.feature} className="border-b border-slate-800/60">
                        <td className="py-2 text-slate-200">{item.label}</td>
                        <td className="py-2 text-slate-300">{item.value.toFixed(3)}</td>
                        <td className="py-2 text-slate-400">{item.weight.toFixed(2)}</td>
                        <td className="py-2 text-cyan-300">{item.contribution.toFixed(3)}</td>
                        <td className="py-2 text-xs text-slate-500">
                          {JSON.stringify(item.detail ?? {}).slice(0, 220)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>
      )}

      {tab === "style" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <Card title="Writing samples" subtitle="At least 20 words per sample is recommended.">
            <div className="space-y-3">
              <Field label="Sample A">
                <textarea
                  className={inputClass}
                  rows={7}
                  value={styleA}
                  onChange={(event) => setStyleA(event.target.value)}
                />
              </Field>
              <Field label="Sample B">
                <textarea
                  className={inputClass}
                  rows={7}
                  value={styleB}
                  onChange={(event) => setStyleB(event.target.value)}
                />
              </Field>
              <Button onClick={runStyle} disabled={busy !== null || !styleA || !styleB}>
                <Play className="h-4 w-4" /> {busy === "style" ? "Comparing…" : "Compare style"}
              </Button>
            </div>
          </Card>

          <Card title="Stylometric result">
            {!style ? (
              <EmptyState title="No comparison yet" />
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <span className="text-3xl font-bold text-cyan-300">{style.score.toFixed(3)}</span>
                  <Badge tone={style.sufficient ? "green" : "amber"}>
                    {style.sufficient ? "sufficient sample" : "short sample"}
                  </Badge>
                </div>
                {style.explanation && <p className="text-sm text-slate-300">{style.explanation}</p>}

                {Array.isArray((style.details as any).feature_comparison) && (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-800 text-left text-xs uppercase text-slate-400">
                        <th className="py-2">Feature</th>
                        <th className="py-2">A</th>
                        <th className="py-2">B</th>
                        <th className="py-2">Closeness</th>
                      </tr>
                    </thead>
                    <tbody>
                      {((style.details as any).feature_comparison as Record<string, any>[]).map((row) => (
                        <tr key={row.feature} className="border-b border-slate-800/60">
                          <td className="py-2 capitalize text-slate-300">{String(row.feature).replace(/_/g, " ")}</td>
                          <td className="py-2 text-slate-400">{Number(row.a).toFixed(2)}</td>
                          <td className="py-2 text-slate-400">{Number(row.b).toFixed(2)}</td>
                          <td className="py-2 text-cyan-300">{Number(row.closeness).toFixed(2)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}

                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge tone="cyan">tf-idf {Number((style.details as any).tfidf_cosine ?? 0).toFixed(2)}</Badge>
                  <Badge tone="slate">lexical {Number((style.details as any).lexical_similarity ?? 0).toFixed(2)}</Badge>
                  <Badge tone="slate">
                    punctuation {Number((style.details as any).punctuation_similarity ?? 0).toFixed(2)}
                  </Badge>
                </div>

                {style.warnings.length > 0 && (
                  <ul className="space-y-1 rounded border border-amber-500/30 bg-amber-500/5 p-2 text-xs text-amber-200">
                    {style.warnings.map((warning) => (
                      <li key={warning}>{warning}</li>
                    ))}
                  </ul>
                )}
                <p className="text-xs text-slate-500">{style.disclaimer}</p>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "behaviour" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <Card title="Hourly activity comparison" subtitle="Cosine similarity of 24-bin activity distributions.">
            <Button onClick={runBehaviour} disabled={busy !== null}>
              <Play className="h-4 w-4" /> {busy === "behaviour" ? "Comparing…" : "Compare actors"}
            </Button>
          </Card>
          <Card title="Result">
            {!behaviour ? (
              <EmptyState title="No behavioural comparison yet" />
            ) : (
              <div className="space-y-3">
                <div className="text-3xl font-bold text-cyan-300">{behaviour.score.toFixed(3)}</div>
                <p className="text-sm text-slate-300">
                  {behaviour.actor_a.handle || behaviour.actor_a.internal_id} vs{" "}
                  {behaviour.actor_b.handle || behaviour.actor_b.internal_id}
                </p>
                <div className="flex flex-wrap gap-2 text-xs">
                  {(behaviour.details as any).cosine !== undefined && (
                    <Badge tone="cyan">cosine {Number((behaviour.details as any).cosine).toFixed(3)}</Badge>
                  )}
                  {(behaviour.details as any).activity_count_a !== undefined && (
                    <Badge tone="slate">
                      events {String((behaviour.details as any).activity_count_a)} /{" "}
                      {String((behaviour.details as any).activity_count_b)}
                    </Badge>
                  )}
                  <Badge tone={(behaviour.details as any).sufficient ? "green" : "amber"}>
                    {(behaviour.details as any).sufficient ? "sufficient" : "insufficient data"}
                  </Badge>
                </div>
                <p className="text-sm text-slate-400">
                  {String((behaviour.details as any).explanation ?? (behaviour.details as any).note ?? "")}
                </p>
                <p className="text-xs text-slate-500">{behaviour.disclaimer}</p>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "clustering" && (
        <div className="space-y-5">
          <Card title="Clustering" subtitle="Groups are exploratory structure, not identity conclusions.">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
              <Field label="Method">
                <select
                  className={inputClass}
                  value={method}
                  onChange={(event) => setMethod(event.target.value as "kmeans" | "dbscan")}
                >
                  <option value="kmeans">K-Means (structural)</option>
                  <option value="dbscan">DBSCAN (hourly activity)</option>
                </select>
              </Field>
              {method === "kmeans" ? (
                <Field label="Clusters (k)">
                  <input
                    type="number"
                    min={2}
                    max={20}
                    className={inputClass}
                    value={k}
                    onChange={(event) => setK(Number(event.target.value))}
                  />
                </Field>
              ) : (
                <>
                  <Field label="eps">
                    <input
                      type="number"
                      step={0.05}
                      min={0.05}
                      max={2}
                      className={inputClass}
                      value={eps}
                      onChange={(event) => setEps(Number(event.target.value))}
                    />
                  </Field>
                  <Field label="min samples">
                    <input
                      type="number"
                      min={1}
                      max={50}
                      className={inputClass}
                      value={minSamples}
                      onChange={(event) => setMinSamples(Number(event.target.value))}
                    />
                  </Field>
                </>
              )}
              <div className="flex items-end">
                <Button onClick={runCluster} disabled={busy !== null} className="w-full justify-center">
                  <Play className="h-4 w-4" /> {busy === "cluster" ? "Running…" : "Run"}
                </Button>
              </div>
            </div>
          </Card>

          {cluster && (
            <Card title="Cluster result">
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={cluster.status === "ok" ? "green" : "amber"}>{cluster.status}</Badge>
                  <Badge tone="cyan">{cluster.clusters} clusters</Badge>
                  {cluster.silhouette !== undefined && cluster.silhouette !== null && (
                    <Badge tone="violet">silhouette {cluster.silhouette}</Badge>
                  )}
                  {cluster.noise_count !== undefined && <Badge tone="slate">{cluster.noise_count} noise</Badge>}
                </div>
                <p className="text-sm text-slate-300">{cluster.explanation}</p>
                {cluster.feature_note && <p className="text-xs text-slate-500">{cluster.feature_note}</p>}

                {cluster.summaries && cluster.summaries.length > 0 && (
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                    {cluster.summaries.map((group) => (
                      <div key={group.cluster} className="rounded-lg border border-slate-800 p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium text-slate-200">{group.label}</span>
                          <Badge tone={group.cluster === -1 ? "amber" : "cyan"}>{group.size}</Badge>
                        </div>
                        <ul className="mt-2 space-y-0.5 text-xs text-slate-400">
                          {group.members.map((member) => (
                            <li key={member.actor_id}>{member.handle || member.internal_id}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}

                {cluster.limitations.length > 0 && (
                  <ul className="list-disc space-y-1 pl-5 text-xs text-slate-500">
                    {cluster.limitations.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                )}
              </div>
            </Card>
          )}
        </div>
      )}

      {tab === "models" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <Card title="Persisted style-inference model" subtitle="Trained TF-IDF centroid model for single and batch inference.">
            {!modelStatus ? (
              <LoadingState />
            ) : (
              <div className="space-y-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={modelStatus.trained ? "green" : "amber"}>
                    {modelStatus.trained ? "trained" : "not trained"}
                  </Badge>
                  {modelStatus.actor_count !== undefined && (
                    <Badge tone="slate">{modelStatus.actor_count} actors</Badge>
                  )}
                  {modelStatus.sample_count !== undefined && (
                    <Badge tone="slate">{modelStatus.sample_count} samples</Badge>
                  )}
                  {modelStatus.trained_at && <Badge tone="slate">{formatDateTime(modelStatus.trained_at)}</Badge>}
                </div>
                <p className="text-xs text-slate-500">
                  Training uses stored text-sample evidence. The model predicts the closest actor centroid;
                  that is an investigative lead, not an identification.
                </p>
                <div className="flex flex-wrap gap-2">
                  <Button variant="secondary" onClick={train} disabled={busy !== null}>
                    <Play className="h-4 w-4" /> {busy === "train" ? "Training…" : "Train model"}
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => {
                      api.analysis
                        .modelStatus()
                        .then(setModelStatus)
                        .catch((err) => add("error", err instanceof Error ? err.message : "Status failed"));
                    }}
                  >
                    Refresh status
                  </Button>
                </div>
              </div>
            )}
          </Card>

          <Card title="Single inference">
            <div className="space-y-3">
              <Field label="Text sample">
                <textarea
                  className={inputClass}
                  rows={5}
                  value={inferText}
                  onChange={(event) => setInferText(event.target.value)}
                />
              </Field>
              <Button variant="secondary" onClick={infer} disabled={busy !== null || !inferText.trim()}>
                <Play className="h-4 w-4" /> {busy === "infer" ? "Running…" : "Infer"}
              </Button>
              {inferResult && (
                <div className="rounded-lg border border-slate-800 p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={(inferResult as any).error ? "red" : "green"}>
                      {(inferResult as any).error
                        ? String((inferResult as any).status)
                        : inferResult.predicted_handle || "no match"}
                    </Badge>
                    <span className="text-xs text-slate-400">
                      score {Number(inferResult.score ?? 0).toFixed(3)}
                      {inferResult.margin !== null && inferResult.margin !== undefined
                        ? ` · margin ${Number(inferResult.margin).toFixed(3)}`
                        : ""}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-slate-500">
                    {String((inferResult as any).note ?? (inferResult as any).error ?? "")}
                  </p>
                  {inferResult.candidates?.length > 0 && (
                    <ul className="mt-2 space-y-0.5 text-xs text-slate-400">
                      {inferResult.candidates.slice(0, 5).map((candidate: { actor_id: number; handle: string | null; internal_id: string | null; score: number }) => (
                        <li key={candidate.actor_id}>
                          {candidate.handle || candidate.internal_id} — {Number(candidate.score).toFixed(3)}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          </Card>

          <Card title="Batch inference" className="lg:col-span-2">
            <Field label="Samples (one per line)">
              <textarea
                className={inputClass}
                rows={5}
                value={batchText}
                onChange={(event) => setBatchText(event.target.value)}
              />
            </Field>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button variant="secondary" onClick={batch} disabled={busy !== null}>
                <Play className="h-4 w-4" /> {busy === "batch" ? "Processing…" : "Run batch"}
              </Button>
            </div>
            {batchResult && (
              <div className="mt-3 space-y-2">
                <div className="flex flex-wrap gap-2 text-xs">
                  <Badge tone="green">{Number(batchResult.succeeded ?? 0)} succeeded</Badge>
                  <Badge tone="red">{Number(batchResult.failed ?? 0)} failed</Badge>
                  <Badge tone="slate">{Number(batchResult.processed ?? 0)} processed</Badge>
                </div>
                <div className="max-h-56 overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-left uppercase text-slate-500">
                        <th className="py-1">#</th>
                        <th className="py-1">Prediction</th>
                        <th className="py-1">Score</th>
                        <th className="py-1">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {batchResult.results?.map((row: Record<string, any>, index: number) => (
                        <tr key={index} className="border-t border-slate-800/60">
                          <td className="py-1 text-slate-400">{index + 1}</td>
                          <td className="py-1 text-slate-200">
                            {row.predicted_handle || row.error || "no match"}
                          </td>
                          <td className="py-1 text-slate-400">{Number(row.score ?? 0).toFixed(3)}</td>
                          <td className="py-1 text-slate-500">{row.status ?? (row.error ? "error" : "ok")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "history" && (
        <Card title="Analysis history" subtitle="Persisted attribution and similarity results.">
          {history.length === 0 ? (
            <EmptyState title="No analyses recorded" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[680px] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-left text-xs uppercase text-slate-400">
                    <th className="py-2">Actors</th>
                    <th className="py-2">Type</th>
                    <th className="py-2">Score</th>
                    <th className="py-2">Category</th>
                    <th className="py-2">Recorded</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((row) => (
                    <tr key={row.id} className="border-b border-slate-800/60">
                      <td className="py-2 text-slate-200">
                        {row.actor_a_handle || actorName(row.actor_a)} →{" "}
                        {row.actor_b_handle || (row.actor_b ? actorName(row.actor_b) : "—")}
                      </td>
                      <td className="py-2 text-slate-400">{row.type}</td>
                      <td className="py-2 text-slate-300">{Number(row.score ?? 0).toFixed(3)}</td>
                      <td className="py-2">
                        {row.category ? (
                          <Badge tone={statusTone(row.category.startsWith("Strong") ? "approved" : "pending")}>
                            {row.category}
                          </Badge>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="py-2 text-xs text-slate-500">{formatDateTime(row.created)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
