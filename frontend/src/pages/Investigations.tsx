import { useCallback, useEffect, useState } from "react";
import { Download, Plus, Trash2 } from "lucide-react";
import { api, saveBlob } from "../services/api";
import type { Actor, InvestigationDetail, InvestigationSummary } from "../services/api";
import { useToast } from "../components/Toast";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  Modal,
  PageHeader,
  formatDate,
  formatDateTime,
  inputClass,
  statusTone,
} from "../components/ui";

export default function Investigations() {
  const [items, setItems] = useState<InvestigationSummary[]>([]);
  const [actors, setActors] = useState<Actor[]>([]);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ title: "", notes: "", actor_ids: [] as number[] });
  const [addActor, setAddActor] = useState("");
  const [reviewTarget, setReviewTarget] = useState<{ id: number; label: string } | null>(null);
  const [review, setReview] = useState({ decision: "approved", notes: "" });
  const [busy, setBusy] = useState(false);
  const { add } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await api.investigations.list());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load investigations");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    api.actors
      .list({ page_size: 100 })
      .then((data) => setActors(data.items))
      .catch(() => setActors([]));
  }, [load]);

  const openDetail = async (id: number) => {
    try {
      setDetail(await api.investigations.get(id));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Failed to load investigation");
    }
  };

  const refreshDetail = async () => {
    if (detail) await openDetail(detail.id);
  };

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form.title.trim()) {
      add("error", "A title is required");
      return;
    }
    setBusy(true);
    try {
      const created = await api.investigations.create({
        title: form.title.trim(),
        notes: form.notes || null,
        actor_ids: form.actor_ids,
      });
      add("success", `Investigation ${created.id} created`);
      setCreateOpen(false);
      setForm({ title: "", notes: "", actor_ids: [] });
      await load();
      await openDetail(created.id);
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  const submitReview = async () => {
    if (!detail || !reviewTarget) return;
    setBusy(true);
    try {
      await api.investigations.review(detail.id, {
        relationship_id: reviewTarget.id,
        decision: review.decision,
        notes: review.notes || null,
      });
      add("success", "Review decision recorded");
      setReviewTarget(null);
      setReview({ decision: "approved", notes: "" });
      await refreshDetail();
      await load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Review failed");
    } finally {
      setBusy(false);
    }
  };

  const downloadPdf = async () => {
    if (!detail) return;
    try {
      const { blob, filename } = await api.reports.investigationPdf(detail.id);
      saveBlob(blob, filename);
      add("success", "Investigation report downloaded");
    } catch (err) {
      add("error", err instanceof Error ? err.message : "PDF export failed");
    }
  };

  const availableActors = actors.filter(
    (actor) => !detail?.entities.some((entity) => entity.id === actor.id),
  );

  return (
    <div className="space-y-5">
      <PageHeader
        title="Investigations"
        subtitle="Case files group actors and their relationships. Every analyst decision is recorded with reviewer, timestamp and notes."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4" /> New investigation
          </Button>
        }
      />

      <Card title="Case files">
        {loading ? (
          <LoadingState />
        ) : error ? (
          <ErrorState message={error} onRetry={load} />
        ) : items.length === 0 ? (
          <EmptyState title="No investigations yet" message="Create a case file to start a review workflow." />
        ) : (
          <div className="-mx-5 overflow-x-auto">
            <table className="w-full min-w-[760px] text-sm">
              <thead>
                <tr className="border-y border-slate-800 bg-slate-800/40 text-left text-xs uppercase text-slate-400">
                  <th className="px-4 py-2.5">Title</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">Entities</th>
                  <th className="px-4 py-2.5">Decisions</th>
                  <th className="px-4 py-2.5">Created</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                    <td className="px-4 py-2.5 text-slate-200">{item.title}</td>
                    <td className="px-4 py-2.5">
                      <Badge tone={statusTone(item.status)}>{item.status}</Badge>
                    </td>
                    <td className="px-4 py-2.5 text-slate-300">{item.entity_count}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">
                      {item.reviews.approved} approved · {item.reviews.rejected} rejected ·{" "}
                      {item.reviews.pending} pending
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-500">{formatDate(item.created_at)}</td>
                    <td className="px-4 py-2.5 text-right">
                      <button className="text-xs text-cyan-400 hover:underline" onClick={() => openDetail(item.id)}>
                        Open case
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="New investigation"
        subtitle="Select the actors that belong to this case."
        wide
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={create} disabled={busy}>
              Create investigation
            </Button>
          </>
        }
      >
        <form className="space-y-3" onSubmit={create}>
          <Field label="Title">
            <input
              className={inputClass}
              value={form.title}
              onChange={(event) => setForm({ ...form, title: event.target.value })}
              required
            />
          </Field>
          <Field label="Case notes">
            <textarea
              className={inputClass}
              rows={3}
              value={form.notes}
              onChange={(event) => setForm({ ...form, notes: event.target.value })}
            />
          </Field>
          <Field label={`Actors (${form.actor_ids.length} selected)`}>
            <div className="max-h-56 space-y-1 overflow-y-auto rounded-lg border border-slate-800 p-2">
              {actors.map((actor) => {
                const checked = form.actor_ids.includes(actor.id);
                return (
                  <label
                    key={actor.id}
                    className="flex cursor-pointer items-center gap-2 rounded px-2 py-1 text-sm hover:bg-slate-800"
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() =>
                        setForm({
                          ...form,
                          actor_ids: checked
                            ? form.actor_ids.filter((value) => value !== actor.id)
                            : [...form.actor_ids, actor.id],
                        })
                      }
                      className="accent-cyan-500"
                    />
                    <span className="text-slate-200">{actor.primary_handle || actor.internal_id}</span>
                    <span className="text-xs text-slate-500">{actor.origin}</span>
                  </label>
                );
              })}
            </div>
          </Field>
        </form>
      </Modal>

      <Modal
        open={detail !== null}
        onClose={() => setDetail(null)}
        title={detail?.title || "Investigation"}
        subtitle={detail ? `Case ${detail.id} · created ${formatDate(detail.created_at)}` : undefined}
        wide
      >
        {!detail ? (
          <LoadingState />
        ) : (
          <div className="space-y-5 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone={statusTone(detail.status)}>{detail.status}</Badge>
              <Badge tone="cyan">{detail.entities.length} entities</Badge>
              <Badge tone="violet">{detail.relationships.length} relationships</Badge>
              <Badge tone="slate">{detail.evidence_count} evidence</Badge>
              <Badge tone="slate">{detail.analysis_count} analyses</Badge>
              <div className="ml-auto flex flex-wrap gap-2">
                <select
                  className={`${inputClass} w-auto`}
                  value={detail.status}
                  onChange={async (event) => {
                    try {
                      await api.investigations.update(detail.id, { status: event.target.value });
                      add("success", "Status updated");
                      await refreshDetail();
                      await load();
                    } catch (err) {
                      add("error", err instanceof Error ? err.message : "Update failed");
                    }
                  }}
                >
                  <option value="open">open</option>
                  <option value="review">review</option>
                  <option value="closed">closed</option>
                </select>
                <Button variant="secondary" onClick={downloadPdf}>
                  <Download className="h-4 w-4" /> PDF
                </Button>
              </div>
            </div>

            {detail.notes && <p className="rounded bg-slate-800/60 p-3 text-slate-300">{detail.notes}</p>}

            <section>
              <h3 className="mb-2 text-xs uppercase tracking-wide text-slate-500">Entities</h3>
              {detail.entities.length === 0 ? (
                <p className="text-xs text-slate-500">No actors linked.</p>
              ) : (
                <ul className="divide-y divide-slate-800">
                  {detail.entities.map((entity) => (
                    <li key={entity.id} className="flex items-center justify-between gap-3 py-2">
                      <div>
                        <span className="text-slate-200">{entity.handle || entity.internal_id}</span>
                        <span className="ml-2 text-xs text-slate-500">
                          {entity.category || "uncategorised"} · {entity.origin}
                        </span>
                      </div>
                      <button
                        className="text-red-400 hover:text-red-300"
                        onClick={async () => {
                          if (!window.confirm("Remove this actor from the investigation?")) return;
                          try {
                            await api.investigations.removeEntity(detail.id, entity.id);
                            add("success", "Entity removed");
                            await refreshDetail();
                            await load();
                          } catch (err) {
                            add("error", err instanceof Error ? err.message : "Remove failed");
                          }
                        }}
                        aria-label="Remove entity"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              {availableActors.length > 0 && (
                <div className="mt-3 flex gap-2">
                  <select
                    className={inputClass}
                    value={addActor}
                    onChange={(event) => setAddActor(event.target.value)}
                  >
                    <option value="">Add actor…</option>
                    {availableActors.map((actor) => (
                      <option key={actor.id} value={actor.id}>
                        {actor.primary_handle || actor.internal_id}
                      </option>
                    ))}
                  </select>
                  <Button
                    variant="secondary"
                    disabled={!addActor}
                    onClick={async () => {
                      try {
                        await api.investigations.addEntity(detail.id, Number(addActor));
                        add("success", "Entity added");
                        setAddActor("");
                        await refreshDetail();
                        await load();
                      } catch (err) {
                        add("error", err instanceof Error ? err.message : "Add failed");
                      }
                    }}
                  >
                    <Plus className="h-4 w-4" /> Add
                  </Button>
                </div>
              )}
            </section>

            <section>
              <h3 className="mb-2 text-xs uppercase tracking-wide text-slate-500">
                Relationships and review
              </h3>
              {detail.relationships.length === 0 ? (
                <p className="text-xs text-slate-500">No relationships involve these actors yet.</p>
              ) : (
                <div className="space-y-2">
                  {detail.relationships.map((rel) => {
                    const latest = detail.reviews.find((item) => item.relationship_id === rel.id);
                    return (
                      <div key={rel.id} className="rounded-lg border border-slate-800 p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge tone={rel.direct ? "green" : "violet"}>
                            {rel.direct ? "direct" : "inferred"}
                          </Badge>
                          <span className="text-slate-200">{rel.rel_type}</span>
                          <span className="text-xs text-slate-500">
                            {rel.source_actor.handle || rel.source_actor.internal_id} →{" "}
                            {rel.target_actor.handle || rel.target_actor.internal_id}
                          </span>
                          <span className="text-xs text-slate-400">score {Number(rel.score).toFixed(2)}</span>
                          <Badge tone={statusTone(latest?.decision || "pending")}>
                            {latest?.decision || "unreviewed"}
                          </Badge>
                          <Button
                            variant="ghost"
                            className="ml-auto px-2 py-1 text-xs"
                            onClick={() =>
                              setReviewTarget({
                                id: rel.id,
                                label: `${rel.source_actor.handle || rel.source_actor.internal_id} → ${
                                  rel.target_actor.handle || rel.target_actor.internal_id
                                }`,
                              })
                            }
                          >
                            Record decision
                          </Button>
                        </div>
                        {rel.evidence && <p className="mt-1 text-xs text-slate-400">{rel.evidence}</p>}
                        {latest && (
                          <p className="mt-1 text-xs text-slate-500">
                            Latest: {latest.analyst} · {latest.decision} · {formatDateTime(latest.reviewed_at)}
                            {latest.notes ? ` — ${latest.notes}` : ""}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <section>
              <h3 className="mb-2 text-xs uppercase tracking-wide text-slate-500">Decision history</h3>
              {detail.reviews.length === 0 ? (
                <p className="text-xs text-slate-500">No analyst decisions recorded.</p>
              ) : (
                <ul className="space-y-1">
                  {detail.reviews.map((item) => (
                    <li key={item.id} className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <Badge tone={statusTone(item.decision)}>{item.decision}</Badge>
                      <span>{item.analyst}</span>
                      <span>{formatDateTime(item.reviewed_at)}</span>
                      {item.relationship_id !== null && <span>rel #{item.relationship_id}</span>}
                      {item.notes && <span className="text-slate-500">— {item.notes}</span>}
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </Modal>

      <Modal
        open={reviewTarget !== null}
        onClose={() => setReviewTarget(null)}
        title="Record analyst decision"
        subtitle={reviewTarget?.label}
        footer={
          <>
            <Button variant="secondary" onClick={() => setReviewTarget(null)}>
              Cancel
            </Button>
            <Button onClick={submitReview} disabled={busy}>
              Save decision
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <Field label="Decision">
            <select
              className={inputClass}
              value={review.decision}
              onChange={(event) => setReview({ ...review, decision: event.target.value })}
            >
              <option value="approved">approved — link supported by evidence</option>
              <option value="rejected">rejected — link not supported</option>
              <option value="pending">pending — needs more intelligence</option>
            </select>
          </Field>
          <Field label="Reviewer notes">
            <textarea
              className={inputClass}
              rows={4}
              value={review.notes}
              onChange={(event) => setReview({ ...review, notes: event.target.value })}
            />
          </Field>
          <p className="text-xs text-slate-500">
            Decisions are analytical judgements and do not confirm real-world identity.
          </p>
        </div>
      </Modal>
    </div>
  );
}
