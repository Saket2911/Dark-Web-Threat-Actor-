import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronLeft, ChevronRight, Plus, Search, Trash2, Upload } from "lucide-react";
import { api, getRole } from "../services/api";
import type { Actor, IngestionSummary } from "../services/api";
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
  inputClass,
  statusTone,
} from "../components/ui";

const EMPTY_IMPORT: IngestionSummary | null = null;

export default function Actors() {
  const [actors, setActors] = useState<Actor[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [status, setStatus] = useState("");
  const [origin, setOrigin] = useState("");
  const [categories, setCategories] = useState<{ category: string; count: number }[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [form, setForm] = useState({ primary_handle: "", threat_category: "", notes: "" });
  const [uploadKind, setUploadKind] = useState<"csv" | "json" | "stix">("csv");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [summary, setSummary] = useState<IngestionSummary | null>(EMPTY_IMPORT);
  const [busy, setBusy] = useState(false);
  const [record, setRecord] = useState({
    handle: "",
    source: "",
    pgp: "",
    wallet: "",
    email: "",
    domain: "",
    threat_category: "",
    text_sample: "",
    is_synthetic: true,
  });
  const { add } = useToast();
  const isAdmin = getRole() === "admin";

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.actors.list({
        q: query || undefined,
        category: category || undefined,
        status: status || undefined,
        origin: origin || undefined,
        page,
        page_size: 20,
      });
      setActors(data.items);
      setTotal(data.total);
      setPages(data.pages);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load actors");
    } finally {
      setLoading(false);
    }
  }, [query, category, status, origin, page]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    api.actors
      .categories()
      .then(setCategories)
      .catch(() => setCategories([]));
  }, []);

  const createActor = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form.primary_handle.trim()) {
      add("error", "A primary handle is required");
      return;
    }
    setBusy(true);
    try {
      const created = await api.actors.create({
        primary_handle: form.primary_handle.trim(),
        threat_category: form.threat_category || null,
        notes: form.notes || null,
      });
      add("success", `Actor ${created.primary_handle} created`);
      setCreateOpen(false);
      setForm({ primary_handle: "", threat_category: "", notes: "" });
      load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  const deleteActor = async (actor: Actor) => {
    if (!window.confirm(`Delete actor ${actor.primary_handle || actor.internal_id}? This removes its relationships.`)) {
      return;
    }
    try {
      await api.actors.remove(actor.id);
      add("success", "Actor deleted");
      load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Delete failed");
    }
  };

  const runUpload = async () => {
    if (!uploadFile) {
      add("error", "Choose a file first");
      return;
    }
    setBusy(true);
    setSummary(null);
    try {
      const result =
        uploadKind === "csv"
          ? await api.ingestion.csv(uploadFile)
          : uploadKind === "json"
            ? await api.ingestion.json(uploadFile)
            : await api.ingestion.stix(uploadFile);
      setSummary(result);
      add(
        result.rejected > 0 ? "info" : "success",
        `Processed ${result.processed ?? 0}: ${result.imported ?? result.records_imported ?? 0} imported, ${result.rejected ?? 0} rejected`,
      );
      load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setBusy(false);
    }
  };

  const submitRecord = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!record.handle.trim() || !record.source.trim()) {
      add("error", "Handle and source are required");
      return;
    }
    setBusy(true);
    try {
      const payload: Record<string, unknown> = {
        handle: record.handle.trim(),
        source: record.source.trim(),
        is_synthetic: record.is_synthetic,
      };
      for (const key of ["pgp", "wallet", "email", "domain", "threat_category", "text_sample"] as const) {
        if (record[key].trim()) payload[key] = record[key].trim();
      }
      const result = (await api.ingestion.record(payload)) as unknown as IngestionSummary;
      setSummary(result);
      add(
        result.duplicates ? "info" : "success",
        result.duplicates ? "Record already present (duplicate)" : "Record imported",
      );
      setRecord((current) => ({
        ...current,
        handle: "",
        pgp: "",
        wallet: "",
        email: "",
        domain: "",
        text_sample: "",
      }));
      load();
    } catch (err) {
      add("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Actor Intelligence"
        subtitle="Search, filter and enrich pseudonymous actors. Identifiers are normalised and validated before they can drive relationships."
        actions={
          <>
            <Button variant="secondary" onClick={() => setImportOpen(true)}>
              <Upload className="h-4 w-4" /> Import intelligence
            </Button>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" /> Add actor
            </Button>
          </>
        }
      />

      <Card>
        <div className="mb-4 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-5">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              className={`${inputClass} pl-9`}
              placeholder="Search handle, internal or external ID"
              value={query}
              onChange={(event) => {
                setPage(1);
                setQuery(event.target.value);
              }}
            />
          </div>
          <select
            className={inputClass}
            value={category}
            onChange={(event) => {
              setPage(1);
              setCategory(event.target.value);
            }}
          >
            <option value="">All categories</option>
            {categories.map((item) => (
              <option key={item.category} value={item.category}>
                {item.category} ({item.count})
              </option>
            ))}
          </select>
          <select
            className={inputClass}
            value={status}
            onChange={(event) => {
              setPage(1);
              setStatus(event.target.value);
            }}
          >
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="review">Review</option>
            <option value="closed">Closed</option>
          </select>
          <select
            className={inputClass}
            value={origin}
            onChange={(event) => {
              setPage(1);
              setOrigin(event.target.value);
            }}
          >
            <option value="">All origins</option>
            <option value="synthetic">Synthetic</option>
            <option value="external">External</option>
            <option value="manual">Manual</option>
          </select>
          <div className="flex items-center justify-end text-xs text-slate-500">
            {total} actor{total === 1 ? "" : "s"}
          </div>
        </div>

        {loading ? (
          <LoadingState />
        ) : error ? (
          <ErrorState message={error} onRetry={load} />
        ) : actors.length === 0 ? (
          <EmptyState
            title="No actors match these filters"
            message="Import intelligence or create an actor to get started."
            action={
              <Button variant="secondary" onClick={() => setCreateOpen(true)}>
                <Plus className="h-4 w-4" /> Add actor
              </Button>
            }
          />
        ) : (
          <>
            <div className="-mx-5 overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead>
                  <tr className="border-y border-slate-800 bg-slate-800/40 text-left text-xs uppercase tracking-wide text-slate-400">
                    <th className="px-4 py-2.5">Handle</th>
                    <th className="px-4 py-2.5">Internal ID</th>
                    <th className="px-4 py-2.5">Category</th>
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-4 py-2.5">Origin</th>
                    <th className="px-4 py-2.5">Signals</th>
                    <th className="px-4 py-2.5">Last observed</th>
                    <th className="px-4 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {actors.map((actor) => (
                    <tr
                      key={actor.id}
                      className="border-b border-slate-800/70 hover:bg-slate-800/30"
                    >
                      <td className="px-4 py-2.5">
                        <Link
                          to={`/actors/${actor.id}`}
                          className="font-medium text-cyan-300 hover:underline"
                        >
                          {actor.primary_handle || "(no handle)"}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-slate-400">
                        {actor.internal_id}
                      </td>
                      <td className="px-4 py-2.5 text-slate-300">{actor.threat_category || "—"}</td>
                      <td className="px-4 py-2.5">
                        <Badge tone={statusTone(actor.investigation_status)}>
                          {actor.investigation_status}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge tone={actor.origin === "synthetic" ? "amber" : actor.origin === "external" ? "cyan" : "slate"}>
                          {actor.origin}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-slate-400">
                        {actor.identifier_count ?? 0} ids · {actor.handle_count ?? 0} handles ·{" "}
                        {actor.timeline_count ?? 0} events
                      </td>
                      <td className="px-4 py-2.5 text-xs text-slate-400">
                        {formatDate(actor.last_observed)}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <div className="flex justify-end gap-2">
                          <Link
                            to={`/actors/${actor.id}`}
                            className="text-xs text-cyan-400 hover:underline"
                          >
                            Open
                          </Link>
                          {isAdmin && (
                            <button
                              onClick={() => deleteActor(actor)}
                              className="text-xs text-red-400 hover:text-red-300"
                              title="Delete actor (admin)"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
              <span>
                Page {page} of {pages} · {total} total
              </span>
              <div className="flex gap-1">
                <Button
                  variant="secondary"
                  className="px-2 py-1"
                  disabled={page <= 1}
                  onClick={() => setPage((current) => Math.max(1, current - 1))}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="secondary"
                  className="px-2 py-1"
                  disabled={page >= pages}
                  onClick={() => setPage((current) => Math.min(pages, current + 1))}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Add threat actor"
        subtitle="Manual records are marked origin=manual and are never treated as external intelligence."
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={createActor} disabled={busy}>
              Create actor
            </Button>
          </>
        }
      >
        <form onSubmit={createActor} className="space-y-3">
          <Field label="Primary handle">
            <input
              className={inputClass}
              value={form.primary_handle}
              onChange={(event) => setForm({ ...form, primary_handle: event.target.value })}
              placeholder="e.g. ghostsec"
              required
            />
          </Field>
          <Field label="Threat category">
            <input
              className={inputClass}
              value={form.threat_category}
              onChange={(event) => setForm({ ...form, threat_category: event.target.value })}
              placeholder="APT, FinCrime, DataTheft…"
            />
          </Field>
          <Field label="Analyst notes">
            <textarea
              className={inputClass}
              rows={3}
              value={form.notes}
              onChange={(event) => setForm({ ...form, notes: event.target.value })}
            />
          </Field>
        </form>
      </Modal>

      <Modal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        title="Import intelligence"
        subtitle="Every import creates a collection job and reports imported, duplicate and rejected records."
        wide
      >
        <div className="space-y-6">
          <div className="rounded-lg border border-slate-800 p-4">
            <h3 className="mb-2 text-sm font-semibold text-slate-200">Upload file</h3>
            <div className="flex flex-col gap-2 sm:flex-row">
              <select
                className={`${inputClass} sm:max-w-[180px]`}
                value={uploadKind}
                onChange={(event) => setUploadKind(event.target.value as "csv" | "json" | "stix")}
              >
                <option value="csv">CSV records</option>
                <option value="json">JSON records</option>
                <option value="stix">STIX 2.1 bundle</option>
              </select>
              <input
                type="file"
                accept={uploadKind === "csv" ? ".csv,text/csv" : ".json,application/json"}
                onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-slate-700 file:px-2 file:py-1 file:text-xs file:text-slate-100"
              />
              <Button onClick={runUpload} disabled={busy || !uploadFile}>
                <Upload className="h-4 w-4" /> Import
              </Button>
            </div>
            <p className="mt-2 text-xs text-slate-500">
              CSV/JSON rows require a <code>handle</code> and <code>source</code>. STIX bundles are
              validated, deduplicated and stored as external intelligence.
            </p>
          </div>

          <div className="rounded-lg border border-slate-800 p-4">
            <h3 className="mb-2 text-sm font-semibold text-slate-200">Single record</h3>
            <form onSubmit={submitRecord} className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {(
                [
                  ["handle", "Handle *", "ghostsec"],
                  ["source", "Source *", "Forum scrape 2024-05"],
                  ["pgp", "PGP fingerprint", "ABCD1234…"],
                  ["wallet", "Crypto wallet", "1A1zP1eP…"],
                  ["email", "Email", "ops@example.com"],
                  ["domain", "Domain", "example-market.com"],
                  ["threat_category", "Category", "APT"],
                ] as const
              ).map(([key, label, placeholder]) => (
                <Field key={key} label={label}>
                  <input
                    className={inputClass}
                    value={record[key]}
                    onChange={(event) => setRecord({ ...record, [key]: event.target.value })}
                    placeholder={placeholder}
                  />
                </Field>
              ))}
              <Field label="Synthetic demonstration data">
                <select
                  className={inputClass}
                  value={record.is_synthetic ? "yes" : "no"}
                  onChange={(event) =>
                    setRecord({ ...record, is_synthetic: event.target.value === "yes" })
                  }
                >
                  <option value="yes">Yes — mark as synthetic</option>
                  <option value="no">No — real intelligence</option>
                </select>
              </Field>
              <div className="sm:col-span-2">
                <Field label="Writing sample" hint="Stored as text_sample evidence for stylometric comparison.">
                  <textarea
                    className={inputClass}
                    rows={3}
                    value={record.text_sample}
                    onChange={(event) => setRecord({ ...record, text_sample: event.target.value })}
                  />
                </Field>
              </div>
              <div className="sm:col-span-2">
                <Button type="submit" disabled={busy}>
                  Import record
                </Button>
              </div>
            </form>
          </div>

          {summary && (
            <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-4 text-sm">
              <div className="mb-2 flex flex-wrap gap-2">
                <Badge tone="green">{summary.imported ?? summary.records_imported ?? 0} imported</Badge>
                <Badge tone="amber">{summary.duplicates ?? 0} duplicates</Badge>
                <Badge tone="red">{summary.rejected ?? 0} rejected</Badge>
                <Badge tone="slate">{summary.processed ?? 0} processed</Badge>
                {summary.identifiers_added !== undefined && (
                  <Badge tone="cyan">{summary.identifiers_added} identifiers</Badge>
                )}
              </div>
              {summary.errors?.length > 0 && (
                <ul className="max-h-32 space-y-1 overflow-y-auto text-xs text-red-300">
                  {summary.errors.map((message, index) => (
                    <li key={index}>{message}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
}
