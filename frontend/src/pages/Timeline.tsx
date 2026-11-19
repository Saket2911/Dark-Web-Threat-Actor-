import { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Plus } from "lucide-react";
import { api } from "../services/api";
import type { Actor, TimelineRecord } from "../services/api";
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
  formatDateTime,
  inputClass,
} from "../components/ui";

export default function Timeline() {
  const [events, setEvents] = useState<TimelineRecord[]>([]);
  const [summary, setSummary] = useState<Awaited<ReturnType<typeof api.timeline.summary>> | null>(null);
  const [actors, setActors] = useState<Actor[]>([]);
  const [actorId, setActorId] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [eventType, setEventType] = useState("");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ actor_id: "", event_type: "activity", description: "", event_date: "", source: "" });
  const [busy, setBusy] = useState(false);
  const { add } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rows, aggregate] = await Promise.all([
        api.timeline.list({
          actor_id: actorId ? Number(actorId) : undefined,
          start: start || undefined,
          end: end || undefined,
          event_type: eventType || undefined,
          order,
        }),
        api.timeline.summary(actorId ? Number(actorId) : undefined),
      ]);
      setEvents(rows);
      setSummary(aggregate);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load timeline");
    } finally {
      setLoading(false);
    }
  }, [actorId, start, end, eventType, order]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    api.actors
      .list({ page_size: 100, sort: "handle" })
      .then((data) => setActors(data.items))
      .catch(() => setActors([]));
  }, []);

  const create = async (submitEvent: React.FormEvent) => {
    submitEvent.preventDefault();
    if (!form.actor_id) {
      add("error", "Select an actor");
      return;
    }
    if (!form.description.trim()) {
      add("error", "Description is required");
      return;
    }
    setBusy(true);
    try {
      await api.actors.timeline.add(Number(form.actor_id), {
        event_type: form.event_type,
        description: form.description.trim(),
        event_date: form.event_date || null,
        source: form.source || null,
      });
      add("success", "Timeline event recorded");
      setOpen(false);
      setForm({ ...form, description: "" });
      load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Investigation Timeline"
        subtitle="Chronology of recorded activity, filtered by actor, date range and event type."
        actions={
          <Button onClick={() => setOpen(true)}>
            <Plus className="h-4 w-4" /> Add event
          </Button>
        }
      />

      {summary && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Card title="Events over time" className="lg:col-span-2">
            <div className="h-56">
              {summary.by_day.length === 0 ? (
                <p className="flex h-full items-center justify-center text-sm text-slate-500">
                  No dated events for this selection.
                </p>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={summary.by_day}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                    <XAxis dataKey="date" stroke="#94a3b8" fontSize={10} />
                    <YAxis stroke="#94a3b8" fontSize={10} allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>
          <Card title="Event types">
            {summary.by_type.length === 0 ? (
              <p className="text-sm text-slate-500">No events.</p>
            ) : (
              <ul className="space-y-2">
                {summary.by_type.map((item) => (
                  <li key={item.type} className="flex items-center justify-between text-sm">
                    <span className="text-slate-300">{item.type}</span>
                    <Badge tone="cyan">{item.count}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}

      <Card>
        <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-6">
          <select className={inputClass} value={actorId} onChange={(event) => setActorId(event.target.value)}>
            <option value="">All actors</option>
            {actors.map((actor) => (
              <option key={actor.id} value={actor.id}>
                {actor.primary_handle || actor.internal_id}
              </option>
            ))}
          </select>
          <input
            type="date"
            className={inputClass}
            value={start}
            onChange={(event) => setStart(event.target.value)}
            aria-label="Start date"
          />
          <input
            type="date"
            className={inputClass}
            value={end}
            onChange={(event) => setEnd(event.target.value)}
            aria-label="End date"
          />
          <select className={inputClass} value={eventType} onChange={(event) => setEventType(event.target.value)}>
            <option value="">All event types</option>
            {["activity", "registration", "post", "transaction", "infrastructure_change", "law_enforcement", "other"].map(
              (type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ),
            )}
          </select>
          <select
            className={inputClass}
            value={order}
            onChange={(event) => setOrder(event.target.value as "asc" | "desc")}
          >
            <option value="desc">Newest first</option>
            <option value="asc">Oldest first</option>
          </select>
          <div className="flex items-center justify-end text-xs text-slate-500">
            {events.length} event{events.length === 1 ? "" : "s"}
          </div>
        </div>

        {loading ? (
          <LoadingState />
        ) : error ? (
          <ErrorState message={error} onRetry={load} />
        ) : events.length === 0 ? (
          <EmptyState title="No events match these filters" message="Adjust the date range or actor filter." />
        ) : (
          <ol className="relative space-y-4 border-l border-slate-800 pl-5">
            {events.map((item) => (
              <li key={item.id} className="relative">
                <span className="absolute -left-[26px] top-1.5 h-2.5 w-2.5 rounded-full bg-cyan-400" />
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                  <span>{formatDateTime(item.event_date)}</span>
                  <Badge tone="slate">{item.event_type}</Badge>
                  <span>{item.actor_handle || `actor ${item.actor_id}`}</span>
                  {item.source && <span>· {item.source}</span>}
                </div>
                <p className="text-sm text-slate-200">{item.description}</p>
              </li>
            ))}
          </ol>
        )}
      </Card>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add timeline event"
        footer={
          <>
            <Button variant="secondary" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button onClick={create} disabled={busy}>
              Add event
            </Button>
          </>
        }
      >
        <form className="space-y-3" onSubmit={create}>
          <Field label="Actor">
            <select
              className={inputClass}
              value={form.actor_id}
              onChange={(event) => setForm({ ...form, actor_id: event.target.value })}
              required
            >
              <option value="">Select an actor…</option>
              {actors.map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.primary_handle || actor.internal_id}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Event type">
            <select
              className={inputClass}
              value={form.event_type}
              onChange={(event) => setForm({ ...form, event_type: event.target.value })}
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
              value={form.description}
              onChange={(event) => setForm({ ...form, description: event.target.value })}
              required
            />
          </Field>
          <Field label="Event date">
            <input
              type="datetime-local"
              className={inputClass}
              value={form.event_date}
              onChange={(event) => setForm({ ...form, event_date: event.target.value })}
            />
          </Field>
          <Field label="Source">
            <input
              className={inputClass}
              value={form.source}
              onChange={(event) => setForm({ ...form, source: event.target.value })}
            />
          </Field>
        </form>
      </Modal>
    </div>
  );
}
