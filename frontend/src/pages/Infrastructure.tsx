import { useCallback, useEffect, useState } from "react";
import { Plus, Search } from "lucide-react";
import { api } from "../services/api";
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

type Indicator = {
  id: number;
  type: string;
  value: string;
  metadata: Record<string, unknown>;
  source: string | null;
  reliability: number;
  origin: string | null;
  last_observed: string | null;
};

const INFRA_TYPES = ["domain", "ip", "url", "cert", "hash", "infra"];

export default function Infrastructure() {
  const [items, setItems] = useState<Indicator[]>([]);
  const [types, setTypes] = useState<{ type: string; count: number }[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [type, setType] = useState("");
  const [origin, setOrigin] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<Awaited<ReturnType<typeof api.infra.get>> | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({
    indicator_type: "domain",
    value: "",
    source: "",
    reliability: 0.6,
    metadata: "",
  });
  const [busy, setBusy] = useState(false);
  const { add } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.infra.list({
        q: query || undefined,
        type: type || undefined,
        origin: origin || undefined,
      });
      setItems(data.items);
      setTypes(data.types);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load infrastructure");
    } finally {
      setLoading(false);
    }
  }, [query, type, origin]);

  useEffect(() => {
    load();
  }, [load]);

  const openDetail = async (indicator: Indicator) => {
    setDetailLoading(true);
    try {
      setDetail(await api.infra.get(indicator.id));
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Failed to load indicator");
    } finally {
      setDetailLoading(false);
    }
  };

  const create = async (submitEvent: React.FormEvent) => {
    submitEvent.preventDefault();
    let metadata: Record<string, unknown> = {};
    if (form.metadata.trim()) {
      try {
        metadata = JSON.parse(form.metadata);
      } catch {
        add("error", "Metadata must be valid JSON");
        return;
      }
    }
    setBusy(true);
    try {
      await api.infra.create({
        indicator_type: form.indicator_type,
        value: form.value.trim(),
        source: form.source || "analyst",
        reliability: Number(form.reliability),
        metadata,
      });
      add("success", "Indicator created");
      setCreateOpen(false);
      setForm({ ...form, value: "", metadata: "" });
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
        title="Infrastructure Intelligence"
        subtitle="Passive indicators only. Associations are derived from recorded identifier matches and stored relationships — no active probing is performed."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4" /> Add indicator
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
          <div className="text-xs uppercase text-slate-500">Total</div>
          <div className="text-xl font-bold text-cyan-300">{total}</div>
        </div>
        {types.map((item) => (
          <div key={item.type} className="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div className="text-xs uppercase text-slate-500">{item.type}</div>
            <div className="text-xl font-bold text-slate-200">{item.count}</div>
          </div>
        ))}
      </div>

      <Card>
        <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-4">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              className={`${inputClass} pl-9`}
              placeholder="Search value or source"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <select className={inputClass} value={type} onChange={(event) => setType(event.target.value)}>
            <option value="">All types</option>
            {INFRA_TYPES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
          <select className={inputClass} value={origin} onChange={(event) => setOrigin(event.target.value)}>
            <option value="">All origins</option>
            <option value="synthetic">Synthetic</option>
            <option value="external">External</option>
            <option value="manual">Manual</option>
          </select>
        </div>

        {loading ? (
          <LoadingState />
        ) : error ? (
          <ErrorState message={error} onRetry={load} />
        ) : items.length === 0 ? (
          <EmptyState
            title="No infrastructure indicators"
            message="Import a feed (URLhaus, ThreatFox) or add an indicator manually."
          />
        ) : (
          <div className="-mx-5 overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-y border-slate-800 bg-slate-800/40 text-left text-xs uppercase text-slate-400">
                  <th className="px-4 py-2.5">Type</th>
                  <th className="px-4 py-2.5">Value</th>
                  <th className="px-4 py-2.5">Source</th>
                  <th className="px-4 py-2.5">Reliability</th>
                  <th className="px-4 py-2.5">Origin</th>
                  <th className="px-4 py-2.5">Last observed</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id} className="border-b border-slate-800/60 hover:bg-slate-800/30">
                    <td className="px-4 py-2.5">
                      <Badge tone="violet">{item.type}</Badge>
                    </td>
                    <td className="max-w-[320px] truncate px-4 py-2.5 font-mono text-xs text-slate-200">
                      {item.value}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">{item.source || "—"}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400">{Number(item.reliability).toFixed(2)}</td>
                    <td className="px-4 py-2.5">
                      <Badge tone={item.origin === "synthetic" ? "amber" : item.origin === "external" ? "cyan" : "slate"}>
                        {item.origin || "manual"}
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-500">{formatDateTime(item.last_observed)}</td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        className="text-xs text-cyan-400 hover:underline"
                        onClick={() => openDetail(item)}
                      >
                        Details
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
        title="Add infrastructure indicator"
        subtitle="Indicators are manual observations unless imported from a feed."
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={create} disabled={busy || !form.value.trim()}>
              Create
            </Button>
          </>
        }
      >
        <form className="space-y-3" onSubmit={create}>
          <Field label="Type">
            <select
              className={inputClass}
              value={form.indicator_type}
              onChange={(event) => setForm({ ...form, indicator_type: event.target.value })}
            >
              {INFRA_TYPES.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Value">
            <input
              className={inputClass}
              value={form.value}
              onChange={(event) => setForm({ ...form, value: event.target.value })}
              required
            />
          </Field>
          <Field label="Source">
            <input
              className={inputClass}
              value={form.source}
              onChange={(event) => setForm({ ...form, source: event.target.value })}
              placeholder="analyst"
            />
          </Field>
          <Field label="Reliability" hint={`${Math.round(form.reliability * 100)}%`}>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={form.reliability}
              onChange={(event) => setForm({ ...form, reliability: Number(event.target.value) })}
              className="w-full accent-cyan-500"
            />
          </Field>
          <Field label="Metadata (JSON)">
            <textarea
              className={inputClass}
              rows={3}
              value={form.metadata}
              onChange={(event) => setForm({ ...form, metadata: event.target.value })}
              placeholder='{"first_seen": "2024-01-01", "registrar": "..."}'
            />
          </Field>
        </form>
      </Modal>

      <Modal
        open={detail !== null || detailLoading}
        onClose={() => setDetail(null)}
        title="Indicator detail"
        wide
      >
        {detailLoading || !detail ? (
          <LoadingState />
        ) : (
          <div className="space-y-4 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="violet">{String(detail.indicator.type)}</Badge>
              <span className="break-all font-mono text-xs text-slate-200">
                {String(detail.indicator.value)}
              </span>
              <Badge tone={detail.indicator.origin === "synthetic" ? "amber" : "slate"}>
                {String(detail.indicator.origin || "manual")}
              </Badge>
              <span className="text-xs text-slate-500">
                reliability {Number(detail.indicator.reliability).toFixed(2)} ·{" "}
                {formatDateTime(detail.indicator.last_observed as string)}
              </span>
            </div>

            {Object.keys(detail.indicator.metadata || {}).length > 0 && (
              <div>
                <h3 className="mb-1 text-xs uppercase text-slate-500">Metadata</h3>
                <pre className="overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
                  {JSON.stringify(detail.indicator.metadata, null, 2)}
                </pre>
              </div>
            )}

            <div>
              <h3 className="mb-1 text-xs uppercase text-slate-500">Associated actors</h3>
              {detail.associated_actors.length === 0 ? (
                <p className="text-xs text-slate-500">No actor association recorded.</p>
              ) : (
                <ul className="space-y-1">
                  {detail.associated_actors.map((actor) => (
                    <li key={actor.actor_id} className="text-slate-300">
                      {actor.handle || actor.internal_id}{" "}
                      <span className="text-xs text-slate-500">— {actor.basis}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <h3 className="mb-1 text-xs uppercase text-slate-500">Evidence</h3>
              {detail.evidence.length === 0 ? (
                <p className="text-xs text-slate-500">No evidence linked to this indicator.</p>
              ) : (
                <ul className="space-y-2">
                  {detail.evidence.map((item) => (
                    <li key={item.id} className="rounded border border-slate-800 p-2">
                      <div className="text-xs text-slate-500">
                        {item.evidence_type} · {item.source || "unknown"} ·{" "}
                        {formatDateTime(item.collected_at)}
                      </div>
                      <div className="text-slate-300">{item.content}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <p className="text-xs text-slate-500">{detail.note}</p>
          </div>
        )}
      </Modal>
    </div>
  );
}
