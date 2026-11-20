import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { GitBranch, Maximize2, RefreshCw, Search, ZoomIn, ZoomOut } from "lucide-react";
import { api } from "../services/api";
import type { Actor, GraphEdgeData, GraphPayload } from "../services/api";
import { useToast } from "../components/Toast";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  formatDateTime,
  inputClass,
  statusTone,
} from "../components/ui";

const REL_TYPES = [
  "SHARED_IDENTIFIER",
  "POTENTIALLY_SAME_PERSONA",
  "HAS_IDENTIFIER",
  "ASSOCIATED_WITH_INFRASTRUCTURE",
];

const LAYOUTS = ["cose", "circle", "concentric", "grid", "breadthfirst"];

const STYLE = [
  {
    selector: "node",
    style: {
      "background-color": "#0ea5e9",
      label: "data(label)",
      color: "#cbd5e1",
      "font-size": 9,
      "text-margin-y": 4,
      "text-valign": "bottom",
      "text-halign": "center",
      width: 26,
      height: 26,
      "border-width": 1,
      "border-color": "#0f172a",
      "text-wrap": "ellipsis",
      "text-max-width": "110px",
    },
  },
  {
    selector: 'node[type = "identifier"]',
    style: { "background-color": "#a855f7", shape: "round-rectangle", width: 18, height: 18 },
  },
  {
    selector: 'node[type = "indicator"]',
    style: { "background-color": "#f97316", shape: "diamond", width: 18, height: 18 },
  },
  {
    selector: 'node[type = "malware"]',
    style: { "background-color": "#ef4444", shape: "hexagon", width: 18, height: 18 },
  },
  {
    selector: "edge",
    style: {
      width: 1.4,
      "line-color": "#475569",
      "target-arrow-color": "#475569",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      label: "data(label)",
      "font-size": 7,
      color: "#94a3b8",
      "text-rotation": "autorotate",
      "text-background-color": "#020617",
      "text-background-opacity": 0.7,
      "text-background-padding": "1px",
    },
  },
  {
    selector: 'edge[direct = true]',
    style: { "line-color": "#22d3ee", "target-arrow-color": "#22d3ee", width: 2 },
  },
  {
    selector: 'edge[label = "POTENTIALLY_SAME_PERSONA"]',
    style: { "line-style": "dashed", "line-color": "#a855f7", "target-arrow-color": "#a855f7" },
  },
  {
    selector: ".faded",
    style: { opacity: 0.2 },
  },
  {
    selector: ":selected",
    style: { "border-width": 3, "border-color": "#facc15" },
  },
] as unknown as cytoscape.StylesheetStyle[];

type Selection =
  | { kind: "node"; data: Record<string, any> }
  | { kind: "edge"; data: GraphEdgeData }
  | null;

export default function Graph() {
  const [params, setParams] = useSearchParams();
  const [actors, setActors] = useState<Actor[]>([]);
  const [focus, setFocus] = useState(params.get("actor") || "");
  const [depth, setDepth] = useState(1);
  const [minScore, setMinScore] = useState(0);
  const [includeIdentifiers, setIncludeIdentifiers] = useState(true);
  const [relType, setRelType] = useState("");
  const [search, setSearch] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");
  const [layout, setLayout] = useState("cose");
  const [data, setData] = useState<GraphPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selection, setSelection] = useState<Selection>(null);
  const [relationship, setRelationship] = useState<Awaited<ReturnType<typeof api.graph.relationship>> | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const { add } = useToast();

  useEffect(() => {
    api.actors
      .list({ page_size: 100, sort: "handle" })
      .then((result) => setActors(result.items))
      .catch(() => setActors([]));
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const payload = await api.graph.data({
        actor_id: focus ? Number(focus) : undefined,
        depth,
        include_identifiers: includeIdentifiers,
        min_score: minScore,
        rel_types: relType || undefined,
        q: appliedSearch || undefined,
      });
      setData(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load graph");
    } finally {
      setLoading(false);
    }
  }, [focus, depth, includeIdentifiers, minScore, relType, appliedSearch]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!containerRef.current || !data) return;
    const elements: ElementDefinition[] = [
      ...data.nodes.map((node) => ({ data: node.data })),
      ...data.edges.map((edge) => ({ data: edge.data })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: STYLE,
      layout: { name: layout, animate: false, padding: 40, fit: true } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.2,
    });

    cy.on("tap", "node", (event) => {
      setSelection({ kind: "node", data: event.target.data() });
      setRelationship(null);
    });
    cy.on("tap", "edge", (event) => {
      const edgeData = event.target.data() as GraphEdgeData;
      setSelection({ kind: "edge", data: edgeData });
      setRelationship(null);
      if (edgeData.relationship_id && !edgeData.synthetic_edge) {
        api.graph
          .relationship(edgeData.relationship_id)
          .then(setRelationship)
          .catch((err) => add("error", err instanceof Error ? err.message : "Failed to load relationship"));
      }
    });
    cy.on("tap", (event) => {
      if (event.target === cy) {
        setSelection(null);
        setRelationship(null);
      }
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [data, layout, add]);

  const runBuild = async () => {
    setBusy("build");
    try {
      const result = await api.graph.build();
      add("success", `Build complete — ${result.direct_created ?? 0} new direct link(s), ${result.skipped ?? 0} existing`);
      await load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Build failed");
    } finally {
      setBusy(null);
    }
  };

  const runInfer = async () => {
    setBusy("infer");
    try {
      const result = await api.graph.infer();
      add(
        "success",
        `Inference complete — ${result.inferred ?? 0} new hypothesis link(s) above threshold ${result.threshold}`,
      );
      await load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Inference failed");
    } finally {
      setBusy(null);
    }
  };

  const updateFocus = (value: string) => {
    setFocus(value);
    if (value) params.set("actor", value);
    else params.delete("actor");
    setParams(params, { replace: true });
  };

  return (
    <div className="space-y-4">
      <PageHeader
        title="Relationship Explorer"
        subtitle="Nodes and edges are read from the database. Direct links come from identical identifiers; dashed purple links are analytical hypotheses."
        actions={
          <>
            <Button variant="secondary" onClick={runBuild} disabled={busy !== null}>
              <GitBranch className="h-4 w-4" /> {busy === "build" ? "Building…" : "Build direct links"}
            </Button>
            <Button variant="secondary" onClick={runInfer} disabled={busy !== null}>
              <GitBranch className="h-4 w-4" /> {busy === "infer" ? "Inferring…" : "Infer hypotheses"}
            </Button>
            <Button onClick={load} variant="ghost">
              <RefreshCw className="h-4 w-4" /> Refresh
            </Button>
          </>
        }
      />

      <Card>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-6">
          <Field label="Focus actor">
            <select className={inputClass} value={focus} onChange={(event) => updateFocus(event.target.value)}>
              <option value="">Whole graph</option>
              {actors.map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.primary_handle || actor.internal_id}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Neighbourhood depth">
            <select className={inputClass} value={depth} onChange={(event) => setDepth(Number(event.target.value))}>
              <option value={0}>0 (focus only)</option>
              <option value={1}>1 hop</option>
              <option value={2}>2 hops</option>
              <option value={3}>3 hops</option>
            </select>
          </Field>
          <Field label="Relationship type">
            <select className={inputClass} value={relType} onChange={(event) => setRelType(event.target.value)}>
              <option value="">All types</option>
              {REL_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </Field>
          <Field label={`Minimum score (${minScore.toFixed(2)})`}>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={minScore}
              onChange={(event) => setMinScore(Number(event.target.value))}
              className="w-full accent-cyan-500"
            />
          </Field>
          <Field label="Search labels">
            <div className="flex gap-1">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  className={`${inputClass} pl-8`}
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") setAppliedSearch(search.trim());
                  }}
                />
              </div>
              <Button variant="secondary" className="px-2" onClick={() => setAppliedSearch(search.trim())}>
                <Search className="h-4 w-4" />
              </Button>
            </div>
          </Field>
          <Field label="Layout">
            <div className="flex gap-1">
              <select className={inputClass} value={layout} onChange={(event) => setLayout(event.target.value)}>
                {LAYOUTS.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </div>
          </Field>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-400">
          <label className="flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={includeIdentifiers}
              onChange={(event) => setIncludeIdentifiers(event.target.checked)}
              className="accent-cyan-500"
            />
            Include identifier nodes
          </label>
          <div className="ml-auto flex flex-wrap items-center gap-1">
            <Button
              variant="ghost"
              className="px-2 py-1"
              onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.25)}
              aria-label="Zoom in"
            >
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              className="px-2 py-1"
              onClick={() => cyRef.current?.zoom(cyRef.current.zoom() / 1.25)}
              aria-label="Zoom out"
            >
              <ZoomOut className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              className="px-2 py-1"
              onClick={() => cyRef.current?.fit(undefined, 40)}
              aria-label="Fit to screen"
            >
              <Maximize2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </Card>

      {data && (
        <div className="flex flex-wrap gap-2 text-xs">
          <Badge tone="cyan">{data.stats.actor_nodes} actors</Badge>
          <Badge tone="violet">{data.stats.identifier_nodes} identifiers</Badge>
          <Badge tone="amber">{data.stats.indicator_nodes} indicators</Badge>
          <Badge tone="green">{data.stats.edges} edges</Badge>
          <Badge tone="slate">{data.stats.direct_edges} direct</Badge>
          <Badge tone="violet">{data.stats.inferred_edges} inferred</Badge>
          {data.stats.truncated && (
            <Badge tone="amber">showing first {data.stats.edge_limit ?? 0} edges</Badge>
          )}
        </div>
      )}

      {data?.stats.truncated && (
        <p className="text-xs text-amber-400">
          The database holds more evidence-backed relationships than can be drawn at once. Focus on an
          actor or filter by relationship type to inspect the rest.
        </p>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Card className="lg:col-span-3" title="Graph">
          {loading ? (
            <LoadingState label="Loading graph…" />
          ) : error ? (
            <ErrorState message={error} onRetry={load} />
          ) : !data || data.nodes.length === 0 ? (
            <EmptyState
              title="No graph data"
              message="The current filters return no nodes. Clear the focus actor or build relationships from shared identifiers."
            />
          ) : (
            <div
              ref={containerRef}
              className="h-[560px] w-full rounded-lg border border-slate-800 bg-slate-950"
              role="img"
              aria-label="Relationship graph"
            />
          )}
        </Card>

        <div className="space-y-4">
          <Card title="Selection">
            {!selection ? (
              <p className="text-sm text-slate-500">
                Select a node or edge to inspect its stored attributes and evidence.
              </p>
            ) : selection.kind === "node" ? (
              <dl className="space-y-2 text-sm">
                <div>
                  <dt className="text-xs uppercase text-slate-500">Label</dt>
                  <dd className="break-words text-slate-200">{String(selection.data.label ?? "—")}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase text-slate-500">Type</dt>
                  <dd className="text-slate-300">{String(selection.data.type ?? "—")}</dd>
                </div>
                {selection.data.internal_id && (
                  <div>
                    <dt className="text-xs uppercase text-slate-500">Internal ID</dt>
                    <dd className="font-mono text-xs text-slate-300">{selection.data.internal_id}</dd>
                  </div>
                )}
                {selection.data.category && (
                  <div>
                    <dt className="text-xs uppercase text-slate-500">Category</dt>
                    <dd className="text-slate-300">{selection.data.category}</dd>
                  </div>
                )}
                {selection.data.origin && (
                  <div>
                    <dt className="text-xs uppercase text-slate-500">Origin</dt>
                    <dd>
                      <Badge tone={selection.data.origin === "synthetic" ? "amber" : "slate"}>
                        {selection.data.origin}
                      </Badge>
                    </dd>
                  </div>
                )}
                {Array.isArray(selection.data.owners) && selection.data.owners.length > 1 && (
                  <div>
                    <dt className="text-xs uppercase text-slate-500">Shared by</dt>
                    <dd className="space-y-1">
                      {selection.data.owners.map((owner: Record<string, any>) => (
                        <div key={owner.actor_id} className="text-xs text-slate-300">
                          {owner.handle || `actor ${owner.actor_id}`}
                        </div>
                      ))}
                    </dd>
                  </div>
                )}
              </dl>
            ) : (
              <div className="space-y-2 text-sm">
                <div className="flex flex-wrap gap-2">
                  <Badge tone={selection.data.direct ? "green" : "violet"}>
                    {selection.data.direct ? "direct" : "inferred"}
                  </Badge>
                  <Badge tone="slate">{selection.data.label}</Badge>
                  {selection.data.score !== undefined && selection.data.score !== null && (
                    <Badge tone="cyan">score {Number(selection.data.score).toFixed(2)}</Badge>
                  )}
                </div>
                {selection.data.evidence && (
                  <p className="text-xs text-slate-300">{selection.data.evidence}</p>
                )}
                <dl className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <dt className="text-slate-500">Classification</dt>
                    <dd className="text-slate-300">{selection.data.relationship_classification || "—"}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Confidence</dt>
                    <dd className="text-slate-300">{selection.data.confidence_level || "—"}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Created</dt>
                    <dd className="text-slate-300">{formatDateTime(selection.data.created_at)}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Relationship ID</dt>
                    <dd className="text-slate-300">{selection.data.relationship_id ?? "synthetic edge"}</dd>
                  </div>
                </dl>
                {relationship && (
                  <div className="rounded border border-slate-800 p-2 text-xs">
                    <div className="text-slate-300">
                      {relationship.source?.label || "?"} → {relationship.target?.label || "?"}
                    </div>
                    <p className="mt-1 text-slate-500">{relationship.interpretation}</p>
                    {relationship.reviews.length > 0 && (
                      <ul className="mt-1 space-y-0.5">
                        {relationship.reviews.map((review) => (
                          <li key={review.id} className="text-slate-400">
                            <Badge tone={statusTone(review.decision)}>{review.decision}</Badge>{" "}
                            {review.analyst}
                            {review.notes ? ` — ${review.notes}` : ""}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            )}
          </Card>

          <Card title="Legend">
            <ul className="space-y-2 text-xs text-slate-400">
              <li className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-sky-500" /> Actor
              </li>
              <li className="flex items-center gap-2">
                <span className="h-3 w-3 rounded bg-violet-500" /> Identifier
              </li>
              <li className="flex items-center gap-2">
                <span className="h-3 w-3 rotate-45 bg-orange-500" /> Infrastructure indicator
              </li>
              <li className="flex items-center gap-2">
                <span className="h-0.5 w-5 bg-cyan-400" /> Direct relationship
              </li>
              <li className="flex items-center gap-2">
                <span className="h-0.5 w-5 border-t border-dashed border-violet-400" /> Inferred hypothesis
              </li>
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
