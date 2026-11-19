import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowRight, Plus, Trash2 } from "lucide-react";
import { api } from "../services/api";
import type { ActorProfile as Profile } from "../services/api";
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
  formatDate,
  formatDateTime,
  inputClass,
  statusTone,
} from "../components/ui";

const TABS = ["overview", "identifiers", "evidence", "timeline", "relationships"] as const;
type Tab = (typeof TABS)[number];

const ID_TYPES: [string, string][] = [
  ["pgp", "PGP fingerprint"],
  ["wallet", "Crypto wallet"],
  ["email", "Email"],
  ["domain", "Domain"],
  ["ip", "IP address"],
  ["username", "Username"],
  ["cert", "Certificate"],
  ["url", "URL"],
  ["infra", "Infrastructure value"],
];

export default function ActorProfile() {
  const { actorId } = useParams();
  const id = Number(actorId);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [edit, setEdit] = useState({ primary_handle: "", threat_category: "", investigation_status: "open", notes: "" });
  const [identifier, setIdentifier] = useState({ id_type: "pgp", value: "", source: "", reliability: 0.8 });
  const [evidence, setEvidence] = useState({
    evidence_type: "osint_report",
    content: "",
    reference: "",
    source: "",
    reliability: 0.6,
  });
  const [event, setEvent] = useState({ event_type: "activity", description: "", event_date: "", source: "" });
  const [handle, setHandle] = useState({ handle: "", marketplace: "" });
  const { add } = useToast();

  const load = useCallback(async () => {
    if (!Number.isFinite(id)) {
      setError("Invalid actor id");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await api.actors.profile(id);
      setProfile(data);
      setEdit({
        primary_handle: data.primary_handle ?? "",
        threat_category: data.threat_category ?? "",
        investigation_status: data.investigation_status,
        notes: data.notes ?? "",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load actor");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action: () => Promise<unknown>, message: string) => {
    setSaving(true);
    try {
      await action();
      add("success", message);
      await load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Operation failed");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <LoadingState label="Loading actor profile…" />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!profile) return <ErrorState message="Actor not found" onRetry={load} />;

  return (
    <div className="space-y-5">
      <PageHeader
        title={profile.primary_handle || profile.internal_id}
        subtitle={`Internal ID ${profile.internal_id} · ${profile.related.length} recorded relationships`}
        actions={
          <>
            <Link to={`/graph?actor=${profile.id}`}>
              <Button variant="secondary">
                View in graph <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
            <Link to="/actors">
              <Button variant="ghost">Back to actors</Button>
            </Link>
          </>
        }
      />

      <div className="flex flex-wrap gap-2">
        <Badge tone={profile.origin === "synthetic" ? "amber" : profile.origin === "external" ? "cyan" : "slate"}>
          origin: {profile.origin}
        </Badge>
        <Badge tone={statusTone(profile.investigation_status)}>{profile.investigation_status}</Badge>
        {profile.threat_category && <Badge tone="violet">{profile.threat_category}</Badge>}
        <Badge tone="slate">last observed {formatDate(profile.last_observed)}</Badge>
      </div>

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
            {item}
            {item === "identifiers" && ` (${profile.identifiers.length})`}
            {item === "evidence" && ` (${profile.evidence.length})`}
            {item === "timeline" && ` (${profile.timeline.length})`}
            {item === "relationships" && ` (${profile.related.length})`}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <Card title="Actor details">
            <form
              className="space-y-3"
              onSubmit={(submitEvent) => {
                submitEvent.preventDefault();
                run(
                  () =>
                    api.actors.update(profile.id, {
                      primary_handle: edit.primary_handle || null,
                      threat_category: edit.threat_category || null,
                      investigation_status: edit.investigation_status,
                      notes: edit.notes || null,
                    }),
                  "Actor updated",
                );
              }}
            >
              <Field label="Primary handle">
                <input
                  className={inputClass}
                  value={edit.primary_handle}
                  onChange={(change) => setEdit({ ...edit, primary_handle: change.target.value })}
                />
              </Field>
              <Field label="Threat category">
                <input
                  className={inputClass}
                  value={edit.threat_category}
                  onChange={(change) => setEdit({ ...edit, threat_category: change.target.value })}
                />
              </Field>
              <Field label="Investigation status">
                <select
                  className={inputClass}
                  value={edit.investigation_status}
                  onChange={(change) => setEdit({ ...edit, investigation_status: change.target.value })}
                >
                  <option value="open">open</option>
                  <option value="review">review</option>
                  <option value="closed">closed</option>
                </select>
              </Field>
              <Field label="Analyst notes">
                <textarea
                  className={inputClass}
                  rows={4}
                  value={edit.notes}
                  onChange={(change) => setEdit({ ...edit, notes: change.target.value })}
                />
              </Field>
              <Button type="submit" disabled={saving}>
                {saving ? "Saving…" : "Save changes"}
              </Button>
            </form>
          </Card>

          <Card title="Handles" subtitle="Pseudonyms observed on marketplaces and forums">
            {profile.handles.length === 0 ? (
              <p className="text-sm text-slate-500">No handles recorded.</p>
            ) : (
              <ul className="divide-y divide-slate-800">
                {profile.handles.map((item) => (
                  <li key={item.id} className="flex items-center justify-between py-2 text-sm">
                    <span className="text-slate-200">{item.handle}</span>
                    <span className="text-xs text-slate-500">
                      {item.marketplace || "unknown marketplace"} · {formatDate(item.last_seen)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <form
              className="mt-4 flex flex-col gap-2 sm:flex-row"
              onSubmit={(submitEvent) => {
                submitEvent.preventDefault();
                if (!handle.handle.trim()) {
                  add("error", "Handle is required");
                  return;
                }
                run(
                  () =>
                    api.actors.handles.add(profile.id, {
                      handle: handle.handle.trim(),
                      marketplace: handle.marketplace || null,
                    }),
                  "Handle added",
                ).then(() => setHandle({ handle: "", marketplace: "" }));
              }}
            >
              <input
                className={inputClass}
                placeholder="Handle"
                value={handle.handle}
                onChange={(change) => setHandle({ ...handle, handle: change.target.value })}
              />
              <input
                className={inputClass}
                placeholder="Marketplace"
                value={handle.marketplace}
                onChange={(change) => setHandle({ ...handle, marketplace: change.target.value })}
              />
              <Button type="submit" disabled={saving}>
                <Plus className="h-4 w-4" /> Add
              </Button>
            </form>
          </Card>
        </div>
      )}

      {tab === "identifiers" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          <Card title="Add identifier" subtitle="Values are normalised and validated per type.">
            <form
              className="space-y-3"
              onSubmit={(submitEvent) => {
                submitEvent.preventDefault();
                if (!identifier.value.trim()) {
                  add("error", "Identifier value is required");
                  return;
                }
                run(
                  () =>
                    api.actors.identifiers.add(profile.id, {
                      id_type: identifier.id_type,
                      value: identifier.value.trim(),
                      source: identifier.source || null,
                      reliability: Number(identifier.reliability),
                    }),
                  "Identifier added",
                ).then(() => setIdentifier({ ...identifier, value: "" }));
              }}
            >
              <Field label="Type">
                <select
                  className={inputClass}
                  value={identifier.id_type}
                  onChange={(change) => setIdentifier({ ...identifier, id_type: change.target.value })}
                >
                  {ID_TYPES.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Value">
                <input
                  className={inputClass}
                  value={identifier.value}
                  onChange={(change) => setIdentifier({ ...identifier, value: change.target.value })}
                />
              </Field>
              <Field label="Source">
                <input
                  className={inputClass}
                  value={identifier.source}
                  onChange={(change) => setIdentifier({ ...identifier, source: change.target.value })}
                />
              </Field>
              <Field label="Reliability" hint={`${Math.round(identifier.reliability * 100)}%`}>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={identifier.reliability}
                  onChange={(change) =>
                    setIdentifier({ ...identifier, reliability: Number(change.target.value) })
                  }
                  className="w-full accent-cyan-500"
                />
              </Field>
              <Button type="submit" disabled={saving}>
                <Plus className="h-4 w-4" /> Add identifier
              </Button>
            </form>
          </Card>

          <Card title="Identifiers" className="lg:col-span-2">
            {profile.identifiers.length === 0 ? (
              <EmptyState title="No identifiers" message="Shared identifiers drive direct relationship generation." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-slate-800 text-left text-xs uppercase text-slate-400">
                      <th className="py-2">Type</th>
                      <th className="py-2">Value</th>
                      <th className="py-2">Source</th>
                      <th className="py-2">Reliability</th>
                      <th className="py-2 text-right">Remove</th>
                    </tr>
                  </thead>
                  <tbody>
                    {profile.identifiers.map((item) => (
                      <tr key={item.id} className="border-b border-slate-800/60">
                        <td className="py-2 text-slate-300">{item.type_label || item.id_type}</td>
                        <td className="max-w-[260px] truncate py-2 font-mono text-xs text-slate-200">
                          {item.value}
                        </td>
                        <td className="py-2 text-xs text-slate-500">{item.source || "—"}</td>
                        <td className="py-2 text-xs text-slate-400">{item.reliability.toFixed(2)}</td>
                        <td className="py-2 text-right">
                          <button
                            className="text-red-400 hover:text-red-300"
                            onClick={() => {
                              if (!window.confirm("Remove this identifier?")) return;
                              run(
                                () => api.actors.identifiers.remove(profile.id, item.id),
                                "Identifier removed",
                              );
                            }}
                            aria-label="Remove identifier"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "evidence" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          <Card title="Add evidence">
            <form
              className="space-y-3"
              onSubmit={(submitEvent) => {
                submitEvent.preventDefault();
                if (!evidence.content.trim()) {
                  add("error", "Evidence content is required");
                  return;
                }
                run(
                  () =>
                    api.actors.evidence.add(profile.id, {
                      evidence_type: evidence.evidence_type,
                      content: evidence.content.trim(),
                      reference: evidence.reference || null,
                      source: evidence.source || null,
                      reliability: Number(evidence.reliability),
                    }),
                  "Evidence recorded",
                ).then(() => setEvidence({ ...evidence, content: "", reference: "" }));
              }}
            >
              <Field label="Evidence type">
                <select
                  className={inputClass}
                  value={evidence.evidence_type}
                  onChange={(change) => setEvidence({ ...evidence, evidence_type: change.target.value })}
                >
                  {["osint_report", "text_sample", "forum_post", "marketplace_listing", "infrastructure_observation", "other"].map(
                    (type) => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ),
                  )}
                </select>
              </Field>
              <Field label="Content">
                <textarea
                  className={inputClass}
                  rows={5}
                  value={evidence.content}
                  onChange={(change) => setEvidence({ ...evidence, content: change.target.value })}
                />
              </Field>
              <Field label="Reference">
                <input
                  className={inputClass}
                  value={evidence.reference}
                  onChange={(change) => setEvidence({ ...evidence, reference: change.target.value })}
                />
              </Field>
              <Field label="Source">
                <input
                  className={inputClass}
                  value={evidence.source}
                  onChange={(change) => setEvidence({ ...evidence, source: change.target.value })}
                />
              </Field>
              <Field label="Reliability" hint={`${Math.round(evidence.reliability * 100)}%`}>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={evidence.reliability}
                  onChange={(change) => setEvidence({ ...evidence, reliability: Number(change.target.value) })}
                  className="w-full accent-cyan-500"
                />
              </Field>
              <Button type="submit" disabled={saving}>
                <Plus className="h-4 w-4" /> Record evidence
              </Button>
            </form>
          </Card>

          <Card title="Evidence" className="lg:col-span-2">
            {profile.evidence.length === 0 ? (
              <EmptyState title="No evidence linked" message="Evidence keeps observations traceable to their source." />
            ) : (
              <ul className="space-y-3">
                {profile.evidence.map((item) => (
                  <li key={item.id} className="rounded-lg border border-slate-800 p-3">
                    <div className="mb-1 flex flex-wrap items-center gap-2">
                      <Badge tone="cyan">{item.evidence_type}</Badge>
                      {item.is_synthetic && <Badge tone="amber">synthetic</Badge>}
                      <span className="text-xs text-slate-500">
                        {item.source || "unknown source"} · reliability {item.reliability.toFixed(2)} ·{" "}
                        {formatDate(item.collected_at)}
                      </span>
                    </div>
                    <p className="whitespace-pre-wrap text-sm text-slate-300">{item.content}</p>
                    {item.reference && (
                      <p className="mt-1 break-all text-xs text-slate-500">ref: {item.reference}</p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}

      {tab === "timeline" && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          <Card title="Add timeline event">
            <form
              className="space-y-3"
              onSubmit={(submitEvent) => {
                submitEvent.preventDefault();
                if (!event.description.trim()) {
                  add("error", "Description is required");
                  return;
                }
                run(
                  () =>
                    api.actors.timeline.add(profile.id, {
                      event_type: event.event_type,
                      description: event.description.trim(),
                      event_date: event.event_date || null,
                      source: event.source || null,
                    }),
                  "Timeline event added",
                ).then(() => setEvent({ ...event, description: "" }));
              }}
            >
              <Field label="Event type">
                <select
                  className={inputClass}
                  value={event.event_type}
                  onChange={(change) => setEvent({ ...event, event_type: change.target.value })}
                >
                  {["activity", "registration", "post", "transaction", "infrastructure_change", "law_enforcement", "other"].map(
                    (type) => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ),
                  )}
                </select>
              </Field>
              <Field label="Description">
                <textarea
                  className={inputClass}
                  rows={3}
                  value={event.description}
                  onChange={(change) => setEvent({ ...event, description: change.target.value })}
                />
              </Field>
              <Field label="Event date">
                <input
                  type="datetime-local"
                  className={inputClass}
                  value={event.event_date}
                  onChange={(change) => setEvent({ ...event, event_date: change.target.value })}
                />
              </Field>
              <Field label="Source">
                <input
                  className={inputClass}
                  value={event.source}
                  onChange={(change) => setEvent({ ...event, source: change.target.value })}
                />
              </Field>
              <Button type="submit" disabled={saving}>
                <Plus className="h-4 w-4" /> Add event
              </Button>
            </form>
          </Card>

          <Card title="Timeline" className="lg:col-span-2">
            {profile.timeline.length === 0 ? (
              <EmptyState title="No timeline events" />
            ) : (
              <ol className="relative space-y-4 border-l border-slate-800 pl-5">
                {profile.timeline.map((item) => (
                  <li key={item.id} className="relative">
                    <span className="absolute -left-[26px] top-1.5 h-2.5 w-2.5 rounded-full bg-cyan-400" />
                    <div className="text-xs text-slate-500">
                      {formatDateTime(item.event_date)} · {item.event_type}
                      {item.source ? ` · ${item.source}` : ""}
                    </div>
                    <p className="text-sm text-slate-200">{item.description}</p>
                  </li>
                ))}
              </ol>
            )}
          </Card>
        </div>
      )}

      {tab === "relationships" && (
        <Card title="Recorded relationships" subtitle="Direct observations and analytical hypotheses are labelled separately.">
          {profile.related.length === 0 ? (
            <EmptyState
              title="No relationships"
              message="Build relationships from shared identifiers in the Relationship Explorer."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-left text-xs uppercase text-slate-400">
                    <th className="py-2">Type</th>
                    <th className="py-2">Other party</th>
                    <th className="py-2">Score</th>
                    <th className="py-2">Basis</th>
                    <th className="py-2">Classification</th>
                    <th className="py-2">Review</th>
                  </tr>
                </thead>
                <tbody>
                  {profile.related.map((item) => (
                    <tr key={item.relationship_id} className="border-b border-slate-800/60">
                      <td className="py-2 text-slate-300">{item.rel_type}</td>
                      <td className="py-2">
                        {item.other_type === "actor" && item.other_id ? (
                          <Link to={`/actors/${item.other_id}`} className="text-cyan-300 hover:underline">
                            {item.other_name || item.other_id}
                          </Link>
                        ) : (
                          <span className="text-slate-400">
                            {item.other_type} {item.other_name || item.other_id}
                          </span>
                        )}
                      </td>
                      <td className="py-2 text-slate-300">{Number(item.score ?? 0).toFixed(2)}</td>
                      <td className="py-2">
                        <Badge tone={item.direct ? "green" : "violet"}>
                          {item.direct ? "direct" : "inferred"}
                        </Badge>
                      </td>
                      <td className="py-2 text-xs text-slate-400">
                        {item.relationship_classification || "unresolved"} / {item.confidence_level || "unverified"}
                      </td>
                      <td className="py-2">
                        <Badge tone={statusTone(item.review_decision || "pending")}>
                          {item.review_decision || "unreviewed"}
                        </Badge>
                      </td>
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
