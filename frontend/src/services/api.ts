/**
 * Typed API client for the threat-intelligence backend.
 *
 * Every call funnels through `request`, which:
 *  - attaches the bearer token,
 *  - parses FastAPI error payloads into a readable message,
 *  - clears the session and redirects to /login on 401.
 */

const API_BASE: string = import.meta.env.VITE_API_BASE || "http://localhost:8000/api";
const TOKEN_KEY = "token";
const ROLE_KEY = "role";
const USER_KEY = "username";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getRole(): string | null {
  return localStorage.getItem(ROLE_KEY);
}

export function getUsername(): string | null {
  return localStorage.getItem(USER_KEY);
}

export function storeSession(token: string, username?: string, role?: string) {
  localStorage.setItem(TOKEN_KEY, token);
  if (username) localStorage.setItem(USER_KEY, username);
  if (role) localStorage.setItem(ROLE_KEY, role);
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
  localStorage.removeItem(USER_KEY);
}

function extractDetail(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== "object") return fallback;
  const detail = (payload as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const record = item as { msg?: string; loc?: unknown[] };
          const where = Array.isArray(record.loc) ? record.loc.slice(1).join(".") : "";
          return where ? `${where}: ${record.msg ?? "invalid value"}` : record.msg ?? "invalid value";
        }
        return String(item);
      })
      .join("; ");
  }
  return fallback;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch (error) {
    throw new ApiError(0, `Cannot reach the API at ${API_BASE}. Is the backend running?`);
  }

  if (response.status === 401 && !path.startsWith("/auth/login")) {
    clearSession();
    if (window.location.pathname !== "/login") window.location.href = "/login";
    throw new ApiError(401, "Session expired. Please sign in again.");
  }

  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    throw new ApiError(response.status, extractDetail(payload, `Request failed (${response.status})`));
  }

  if (response.status === 204) return {} as T;
  const text = await response.text();
  if (!text) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    return {} as T;
  }
}

function download(path: string): Promise<{ blob: Blob; filename: string }> {
  const token = getToken();
  return fetch(`${API_BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  }).then(async (response) => {
    if (response.status === 401) {
      clearSession();
      window.location.href = "/login";
      throw new ApiError(401, "Session expired");
    }
    if (!response.ok) {
      let message = `Export failed (${response.status})`;
      try {
        message = extractDetail(await response.json(), message);
      } catch {
        /* keep default message */
      }
      throw new ApiError(response.status, message);
    }
    const disposition = response.headers.get("content-disposition") || "";
    const match = /filename="?([^";]+)"?/.exec(disposition);
    return { blob: await response.blob(), filename: match ? match[1] : "export" };
  });
}

export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* ------------------------------------------------------------------ types */
export interface Actor {
  id: number;
  internal_id: string;
  primary_handle: string | null;
  threat_category: string | null;
  investigation_status: string;
  origin: string;
  external_id?: string | null;
  source_url?: string | null;
  aliases?: string[] | null;
  notes?: string | null;
  last_observed?: string | null;
  created_at?: string | null;
  identifier_count?: number;
  handle_count?: number;
  timeline_count?: number;
}

export interface IdentifierRecord {
  id: number;
  id_type: string;
  type_label?: string;
  value: string;
  source?: string | null;
  reliability: number;
  origin?: string | null;
}

export interface EvidenceRecord {
  id: number;
  evidence_type: string;
  content: string | null;
  reference?: string | null;
  source?: string | null;
  is_synthetic?: boolean | null;
  reliability: number;
  source_confidence?: string | null;
  collected_at?: string | null;
  source_url?: string | null;
}

export interface TimelineRecord {
  id: number;
  actor_id: number;
  actor_handle?: string | null;
  event_type: string;
  description: string;
  event_date: string | null;
  source?: string | null;
}

export interface RelationshipSummary {
  relationship_id: number;
  rel_type: string;
  score: number;
  direct: boolean;
  other_type: string;
  other_id: number | null;
  other_name: string | null;
  other_handle: string | null;
  other_internal_id: string | null;
  evidence: string | null;
  relationship_classification: string | null;
  confidence_level: string | null;
  source_confidence?: string | null;
  created_at?: string | null;
  review_decision?: string | null;
}

export interface ActorProfile extends Actor {
  handles: { id: number; handle: string; marketplace: string | null; first_seen?: string | null; last_seen?: string | null }[];
  identifiers: IdentifierRecord[];
  timeline: TimelineRecord[];
  evidence: EvidenceRecord[];
  related: RelationshipSummary[];
}

export interface Paged<T> {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  items: T[];
}

export interface InvestigationSummary {
  id: number;
  title: string;
  status: string;
  created_at: string;
  notes: string | null;
  entity_count: number;
  reviews: { pending: number; approved: number; rejected: number; total: number };
}

export interface InvestigationDetail {
  id: number;
  title: string;
  status: string;
  created_at: string;
  notes: string | null;
  entities: {
    id: number;
    internal_id: string;
    handle: string | null;
    category: string | null;
    status: string;
    origin: string;
  }[];
  relationships: {
    id: number;
    rel_type: string;
    score: number;
    direct: boolean;
    evidence: string | null;
    relationship_classification: string | null;
    confidence_level: string | null;
    source_actor: { id: number; handle: string | null; internal_id: string | null };
    target_actor: { id: number; handle: string | null; internal_id: string | null };
  }[];
  reviews: {
    id: number;
    relationship_id: number | null;
    analyst: string;
    decision: string;
    notes: string | null;
    reviewed_at: string;
  }[];
  review_counts: { pending: number; approved: number; rejected: number; total: number };
  evidence_count: number;
  analysis_count: number;
}

export interface GraphEdgeData {
  id: string;
  relationship_id?: number;
  source: string;
  target: string;
  label: string;
  score?: number | null;
  direct?: boolean;
  evidence?: string;
  relationship_classification?: string | null;
  confidence_level?: string | null;
  source_confidence?: string | null;
  created_at?: string | null;
  synthetic_edge?: boolean;
}

export interface GraphPayload {
  nodes: { data: Record<string, unknown> }[];
  edges: { data: GraphEdgeData }[];
  stats: {
    actor_nodes: number;
    identifier_nodes: number;
    indicator_nodes: number;
    edges: number;
    direct_edges: number;
    inferred_edges: number;
    focus_actor_id: number | null;
    edge_limit?: number;
    truncated?: boolean;
  };
}

export interface AttributionResult {
  final: number;
  category: string;
  hypothesis: string;
  components: Record<string, number>;
  weights: Record<string, number>;
  contributions: {
    feature: string;
    label: string;
    value: number;
    weight: number;
    contribution: number;
    detail?: Record<string, unknown>;
  }[];
  coverage: number;
  available: Record<string, boolean>;
  missing_evidence: string[];
  explanation: string;
  limitations: string[];
  analysis_id?: number;
  actor_a?: { id: number; handle: string | null; internal_id: string };
  actor_b?: { id: number; handle: string | null; internal_id: string };
}

export interface ClusterResult {
  method: string;
  clusters: number;
  assignments: { actor_id: number; handle?: string | null; cluster: number }[];
  summaries?: {
    cluster: number;
    size: number;
    label: string;
    members: { actor_id: number; handle: string | null; internal_id: string; category: string | null }[];
    dominant_categories: { category: string; count: number }[];
  }[];
  silhouette?: number | null;
  noise_count?: number;
  status: string;
  explanation: string;
  limitations: string[];
  feature_note?: string;
}

/* ---------------------------------------------------------------- endpoints */
export const api = {
  auth: {
    login: (username: string, password: string) =>
      request<{ access_token: string; token_type: string; expires_in: number }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }),
    logout: () => request<{ ok: boolean }>("/auth/logout", { method: "POST" }),
    me: () => request<{ id: number; username: string; role: string }>("/auth/me"),
  },
  dashboard: {
    stats: () => request<Record<string, number | string | null>>("/dashboard/stats"),
    category: () => request<{ name: string; value: number }[]>("/dashboard/charts/category"),
    // The backend supports a bounded day window; 3650 exposes the full
    // demonstration timeline without pretending events are recent.
    activity: (days = 3650) =>
      request<{ date: string; count: number }[]>(`/dashboard/charts/activity?days=${days}`),
    sources: () => request<{ name: string; value: number }[]>("/dashboard/charts/sources"),
    identifiers: () => request<{ name: string; value: number }[]>("/dashboard/charts/identifiers"),
    relationships: () => request<{ name: string; value: number }[]>("/dashboard/charts/relationships"),
    origin: () => request<{ name: string; value: number }[]>("/dashboard/charts/origin"),
    recent: () =>
      request<{ id: number; source: string; status: string; records: number; started: string; finished: string | null }[]>(
        "/dashboard/recent",
      ),
    activityLog: () =>
      request<{ id: number; user: string; action: string; details: string; created_at: string }[]>(
        "/dashboard/activity-log",
      ),
  },
  actors: {
    list: (params: {
      q?: string;
      category?: string;
      status?: string;
      origin?: string;
      page?: number;
      page_size?: number;
      sort?: string;
    }) => {
      const query = new URLSearchParams();
      if (params.q) query.set("q", params.q);
      if (params.category) query.set("category", params.category);
      if (params.status) query.set("status", params.status);
      if (params.origin) query.set("origin", params.origin);
      query.set("page", String(params.page ?? 1));
      query.set("page_size", String(params.page_size ?? 20));
      if (params.sort) query.set("sort", params.sort);
      return request<Paged<Actor>>(`/actors?${query.toString()}`);
    },
    categories: () => request<{ category: string; count: number }[]>("/actors/categories"),
    get: (id: number) => request<Actor>(`/actors/${id}`),
    profile: (id: number) => request<ActorProfile>(`/actors/${id}/profile`),
    create: (body: Record<string, unknown>) =>
      request<Actor>("/actors", { method: "POST", body: JSON.stringify(body) }),
    update: (id: number, body: Record<string, unknown>) =>
      request<Actor>(`/actors/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    remove: (id: number) => request<{ ok: boolean }>(`/actors/${id}`, { method: "DELETE" }),
    identifiers: {
      list: (id: number) => request<IdentifierRecord[]>(`/actors/${id}/identifiers`),
      add: (id: number, body: Record<string, unknown>) =>
        request<IdentifierRecord>(`/actors/${id}/identifiers`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
      remove: (actorId: number, identifierId: number) =>
        request<{ ok: boolean }>(`/actors/${actorId}/identifiers/${identifierId}`, {
          method: "DELETE",
        }),
    },
    handles: {
      add: (id: number, body: Record<string, unknown>) =>
        request<Record<string, unknown>>(`/actors/${id}/handles`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
    },
    evidence: {
      add: (id: number, body: Record<string, unknown>) =>
        request<Record<string, unknown>>(`/actors/${id}/evidence`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
    },
    timeline: {
      add: (id: number, body: Record<string, unknown>) =>
        request<TimelineRecord>(`/actors/${id}/timeline`, {
          method: "POST",
          body: JSON.stringify(body),
        }),
    },
  },
  ingestion: {
    record: (body: Record<string, unknown>) =>
      request<Record<string, unknown>>("/ingestion/record", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    csv: (file: File) => {
      const form = new FormData();
      form.append("file", file);
      return request<IngestionSummary>("/ingestion/csv", { method: "POST", body: form });
    },
    json: (file: File) => {
      const form = new FormData();
      form.append("file", file);
      return request<IngestionSummary>("/ingestion/json", { method: "POST", body: form });
    },
    stix: (file: File) => {
      const form = new FormData();
      form.append("file", file);
      return request<IngestionSummary>("/ingestion/stix?source_name=stix_upload", {
        method: "POST",
        body: form,
      });
    },
    jobs: () =>
      request<{ id: number; source: string; status: string; records: number; started: string; finished: string | null }[]>(
        "/ingestion/jobs",
      ),
    feeds: () =>
      request<
        {
          key: string;
          name: string;
          description: string;
          requires_key: boolean;
          configured: boolean;
          status: string;
          reason: string;
          docs?: string;
          produces?: string;
        }[]
      >("/ingestion/feeds"),
    ingestFeed: (key: string, limit = 100) =>
      request<Record<string, unknown>>(`/ingestion/feeds/${key}`, {
        method: "POST",
        body: JSON.stringify({ limit }),
      }),
    mitre: () => request<Record<string, unknown>>("/ingestion/mitre-attack", { method: "POST" }),
  },
  graph: {
    data: (params: {
      actor_id?: number;
      depth?: number;
      include_identifiers?: boolean;
      min_score?: number;
      rel_types?: string;
      q?: string;
    } = {}) => {
      const query = new URLSearchParams();
      if (params.actor_id) query.set("actor_id", String(params.actor_id));
      if (params.depth !== undefined) query.set("depth", String(params.depth));
      if (params.include_identifiers !== undefined)
        query.set("include_identifiers", String(params.include_identifiers));
      if (params.min_score !== undefined) query.set("min_score", String(params.min_score));
      if (params.rel_types) query.set("rel_types", params.rel_types);
      if (params.q) query.set("q", params.q);
      return request<GraphPayload>(`/graph/data?${query.toString()}`);
    },
    stats: () => request<Record<string, unknown>>("/graph/stats"),
    build: () =>
      request<{ direct_created: number; created: number; skipped: number; failed: number; message: string }>(
        "/graph/build",
        { method: "POST" },
      ),
    infer: () =>
      request<{ inferred: number; created: number; skipped: number; threshold: number; message: string }>(
        "/graph/infer",
        { method: "POST" },
      ),
    relationship: (id: number) =>
      request<{
        id: number;
        rel_type: string;
        score: number;
        direct: boolean;
        evidence: string | null;
        relationship_classification: string | null;
        confidence_level: string | null;
        created_at: string | null;
        source: { label?: string; type?: string } | null;
        target: { label?: string; type?: string } | null;
        reviews: { id: number; analyst: string; decision: string; notes: string | null; reviewed_at: string }[];
        interpretation: string;
      }>(`/graph/relationships/${id}`),
    components: () => request<{ component_count: number; components: string[][] }>("/graph/components"),
    clusters: () => request<{ cluster_count: number; clusters: string[][]; note?: string }>("/graph/clusters"),
  },
  analysis: {
    stylometry: (textA: string, textB: string) =>
      request<{
        score: number;
        details: Record<string, unknown>;
        features_a: Record<string, unknown> | null;
        features_b: Record<string, unknown> | null;
        sufficient: boolean;
        warnings: string[];
        explanation: string | null;
        disclaimer: string;
      }>("/analysis/stylometry", {
        method: "POST",
        body: JSON.stringify({ text_a: textA, text_b: textB }),
      }),
    behavioural: (actorA: number, actorB: number) =>
      request<{
        actor_a: { id: number; handle: string | null; internal_id: string };
        actor_b: { id: number; handle: string | null; internal_id: string };
        score: number;
        details: Record<string, unknown>;
        disclaimer: string;
      }>("/analysis/behavioural", {
        method: "POST",
        body: JSON.stringify({ actor_a_id: actorA, actor_b_id: actorB }),
      }),
    score: (actorA: number, actorB: number, weights?: Record<string, number>) =>
      request<AttributionResult>("/analysis/score", {
        method: "POST",
        body: JSON.stringify({ actor_a_id: actorA, actor_b_id: actorB, weights }),
      }),
    cluster: (method: "kmeans" | "dbscan", options?: { k?: number; eps?: number; min_samples?: number }) =>
      request<ClusterResult>("/analysis/cluster", {
        method: "POST",
        body: JSON.stringify({ method, ...options }),
      }),
    history: () =>
      request<
        {
          id: number;
          actor_a: number;
          actor_b: number | null;
          actor_a_handle: string | null;
          actor_b_handle: string | null;
          type: string;
          score: number;
          created: string;
          category?: string | null;
        }[]
      >("/analysis/history"),
    models: () => request<{ models: Record<string, unknown>[] }>("/analysis/models"),
    modelStatus: () => request<Record<string, unknown>>("/analysis/models/status"),
    train: () => request<Record<string, unknown>>("/analysis/models/train", { method: "POST" }),
    infer: (text: string) =>
      request<{
        predicted_actor_id: number | null;
        predicted_handle: string | null;
        score: number;
        margin: number | null;
        model: Record<string, unknown>;
        candidates: { actor_id: number; handle: string | null; internal_id: string | null; score: number }[];
        note: string;
        analysis_id?: number | null;
        status?: string;
        error?: string;
      }>("/analysis/models/infer", { method: "POST", body: JSON.stringify({ text }) }),
    batch: (texts: string[]) =>
      request<{
        processed: number;
        succeeded: number;
        failed: number;
        results: Record<string, unknown>[];
        model: Record<string, unknown>;
      }>("/analysis/models/batch", { method: "POST", body: JSON.stringify({ texts }) }),
  },
  infra: {
    list: (params: { q?: string; type?: string; origin?: string; page?: number; page_size?: number } = {}) => {
      const query = new URLSearchParams();
      if (params.q) query.set("q", params.q);
      if (params.type) query.set("type", params.type);
      if (params.origin) query.set("origin", params.origin);
      query.set("page", String(params.page ?? 1));
      query.set("page_size", String(params.page_size ?? 50));
      return request<{
        total: number;
        page: number;
        page_size: number;
        types: { type: string; count: number }[];
        items: {
          id: number;
          type: string;
          value: string;
          metadata: Record<string, unknown>;
          source: string | null;
          reliability: number;
          origin: string | null;
          last_observed: string | null;
        }[];
      }>(`/infrastructure?${query.toString()}`);
    },
    get: (id: number) =>
      request<{
        indicator: Record<string, unknown>;
        associated_actors: {
          actor_id: number;
          handle: string | null;
          internal_id: string;
          basis: string;
          identifier_source: string | null;
        }[];
        evidence: EvidenceRecord[];
        malware_links: { relationship_id: number; malware_id: number; rel_type: string; evidence: string | null }[];
        note: string;
      }>(`/infrastructure/${id}`),
    create: (body: Record<string, unknown>) =>
      request<Record<string, unknown>>("/infrastructure", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  },
  timeline: {
    list: (params: { actor_id?: number; start?: string; end?: string; order?: "asc" | "desc"; event_type?: string } = {}) => {
      const query = new URLSearchParams();
      if (params.actor_id) query.set("actor_id", String(params.actor_id));
      if (params.start) query.set("start", params.start);
      if (params.end) query.set("end", params.end);
      if (params.order) query.set("order", params.order);
      if (params.event_type) query.set("event_type", params.event_type);
      return request<TimelineRecord[]>(`/timeline?${query.toString()}`);
    },
    summary: (actorId?: number) =>
      request<{
        total: number;
        by_day: { date: string; count: number }[];
        by_type: { type: string; count: number }[];
        actors: { actor_id: number; handle: string | null; count: number }[];
      }>(`/timeline/summary${actorId ? `?actor_id=${actorId}` : ""}`),
  },
  investigations: {
    list: () => request<InvestigationSummary[]>("/investigations"),
    create: (body: Record<string, unknown>) =>
      request<{ id: number; title: string; entities: number[] }>("/investigations", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    get: (id: number) => request<InvestigationDetail>(`/investigations/${id}`),
    update: (id: number, body: Record<string, unknown>) =>
      request<Record<string, unknown>>(`/investigations/${id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    addEntity: (id: number, actorId: number) =>
      request<{ id: number; actor_id: number }>(`/investigations/${id}/entities`, {
        method: "POST",
        body: JSON.stringify({ actor_id: actorId }),
      }),
    removeEntity: (id: number, actorId: number) =>
      request<{ ok: boolean }>(`/investigations/${id}/entities/${actorId}`, { method: "DELETE" }),
    review: (id: number, body: Record<string, unknown>) =>
      request<Record<string, unknown>>(`/investigations/${id}/review`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
  },
  reports: {
    csv: (kind: string) => download(`/reports/export/csv?kind=${encodeURIComponent(kind)}`),
    json: (kind: string) => download(`/reports/export/json?kind=${encodeURIComponent(kind)}`),
    pdf: (actorId: number) => download(`/reports/pdf/${actorId}`),
    investigationPdf: (id: number) => download(`/reports/pdf/investigation/${id}`),
  },
  settings: {
    sources: () =>
      request<
        {
          id: number;
          name: string;
          type: string;
          reliability: number;
          is_synthetic: boolean;
          origin: string;
          url: string | null;
          collected_at: string;
        }[]
      >("/settings/sources"),
    weights: () => request<Record<string, number>>("/settings/weights/default"),
    thresholds: () => request<Record<string, number>>("/settings/thresholds"),
    models: () => request<Record<string, unknown>>("/settings/models"),
    feeds: () => request<Record<string, unknown>[]>("/settings/feeds"),
    system: () => request<Record<string, any>>("/settings/system"),
    health: () => request<Record<string, unknown>>("/settings/health"),
  },
};

export interface IngestionSummary {
  job_id?: number;
  processed: number;
  imported: number;
  duplicates: number;
  rejected: number;
  skipped: number;
  identifiers_added?: number;
  handles_added?: number;
  evidence_added?: number;
  events_added?: number;
  records_imported?: number;
  errors: string[];
  source?: string;
}
