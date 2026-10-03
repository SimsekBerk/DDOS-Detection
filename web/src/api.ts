// Typed client for the ddosd REST API (/api/v1).

export interface TotalPoint {
  t: number;
  in_bps: number;
  in_pps: number;
  in_fps: number;
  out_bps: number;
  out_pps: number;
  other_bps: number;
  tcp_bps: number;
  udp_bps: number;
  icmp_bps: number;
  other_proto_bps: number;
}

export interface ObjectStatus {
  id: number;
  name: string;
  prefixes: string[];
  profile: string;
  link_capacity_bps: number;
  carpet_prefix_v4: number;
  carpet_prefix_v6: number;
  notes?: string;
  rates: TotalPoint;
  active_incidents: number;
  utilization: number;
}

export interface EngineSnapshot {
  time: number;
  window_seconds: number;
  global: TotalPoint;
  objects: ObjectStatus[];
  series: number;
  active_incidents: number;
  total_incidents: number;
  pending_signals: number;
  records_per_sec: number;
  records_total: number;
  dropped_records: number;
  eval_millis: number;
  flowstore_len: number;
  flowstore_cap: number;
  oldest_flow: number;
  rules: number;
  rules_active: number;
  series_overflow: number;
  max_series: number;
}

export interface AnalystStatus {
  enabled: boolean;
  provider: string;
  model: string;
  configured_provider: string;
  note?: string;
  auto_run: boolean;
  interval_seconds: number;
  running: boolean;
  current?: string;
  last_run: number;
  last_error?: string;
  findings: number;
  pending_signals: number;
  language: string;
}

export interface Overview {
  version: string;
  uptime: number;
  engine: EngineSnapshot;
  mitigation: { pending: number; active: number; mode: string; driver: string };
  analyst: AnalystStatus;
  exporters_total?: number;
  exporters_up?: number;
  listening?: string[];
  demo: boolean;
  restart_pending: string[];
}

export interface Vector {
  rule_id: string;
  rule_name: string;
  category: string;
  severity: string;
  reason: string;
  trigger_kind: string;
  started_at: number;
  ended_at?: number;
  active: boolean;
  cur_pps: number;
  cur_bps: number;
  cur_fps: number;
  peak_pps: number;
  peak_bps: number;
  unique_sources: number;
  avg_packet_size: number;
  threshold_pps?: number;
  threshold_bps?: number;
  threshold_fps?: number;
  baseline_pps?: number;
  baseline_bps?: number;
  mitigation_action: string;
}

export interface Row {
  key: string;
  bps: number;
  pps: number;
  fps: number;
  share: number;
  records: number;
}

export interface Breakdown {
  seconds: number;
  records: number;
  total_bps: number;
  total_pps: number;
  total_fps: number;
  avg_packet_size: number;
  unique_src: number;
  unique_dst: number;
  fragment_share: number;
  sampling_rates: number[];
  protocols: Row[];
  packet_sizes: Row[];
  tcp_flags: Row[];
  top_sources: Row[];
  top_destinations: Row[];
  top_src_ports: Row[];
  top_dst_ports: Row[];
  top_src_nets: Row[];
  exporters: Row[];
}

export interface SampleFlow {
  time: number;
  exporter: string;
  source: string;
  sampling_rate: number;
  direction: string;
  src: string;
  dst: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  tcp_flags?: string;
  icmp?: string;
  fragment?: boolean;
  packets: number;
  bytes: number;
  avg_packet_size: number;
  duration_ms: number;
  in_if: number;
  out_if: number;
}

export interface Incident {
  id: string;
  target: string;
  scope: string;
  direction: string;
  object_id: number;
  object_name: string;
  profile: string;
  link_capacity_bps: number;
  status: string;
  severity: string;
  started_at: number;
  updated_at: number;
  ended_at?: number;
  cur_pps: number;
  cur_bps: number;
  peak_pps: number;
  peak_bps: number;
  vectors: Vector[];
  series?: { t: number; bps: number; pps: number }[];
  evidence?: { computed_at: number; breakdown: Breakdown; samples: SampleFlow[] };
  mitigations: string[];
  findings: string[];
  reopened?: number;
}

export interface FlowSpec {
  destination?: string;
  source?: string;
  protocols?: string[];
  src_ports?: string[];
  dst_ports?: string[];
  packet_length?: string;
  fragment?: boolean;
  tcp_flags_set?: string[];
  tcp_flags_not_set?: string[];
  icmp_types?: number[];
  action: string;
  rate_bps?: number;
}

export interface Mitigation {
  id: string;
  incident_id?: string;
  rule_id?: string;
  finding_id?: string;
  target: string;
  kind: string;
  status: string;
  source: string;
  flowspec?: FlowSpec;
  rtbh?: { prefix: string; next_hop: string; community: string };
  reason: string;
  note?: string;
  guardrails: string[] | null;
  rendered?: Record<string, string>;
  driver: string;
  created_at: number;
  activated_at?: number;
  expires_at?: number;
  withdraw_at?: number;
  ended_at?: number;
  error?: string;
  history: { t: number; status: string; actor: string; msg?: string }[];
}

export interface Signal {
  id: string;
  kind: string;
  rule_id: string;
  rule_name: string;
  category: string;
  scope: string;
  direction: string;
  target: string;
  object_id: number;
  object_name: string;
  first_seen: number;
  last_seen: number;
  seconds: number;
  peak_ratio: number;
  peak_z: number;
  peak_pps: number;
  peak_bps: number;
  cur_pps: number;
  cur_bps: number;
  baseline_pps: number;
  baseline_bps: number;
  threshold_pps?: number;
  threshold_bps?: number;
  detail: string;
  condition?: string;
  related_incident?: string;
  analyzed: boolean;
  finding_id?: string;
  escalated_incident?: string;
}

export interface Recommendation {
  type: string;
  title: string;
  detail: string;
  rule_id?: string;
  flowspec?: {
    target: string;
    direction?: string;
    protocol?: string;
    src_ports?: number[];
    dst_ports?: number[];
    min_packet_length?: number;
    action?: string;
    rate_bps?: number;
  };
  threshold?: { rule_id: string; profile?: string; pps?: number; bps?: number };
  applied?: string;
}

export interface Finding {
  id: string;
  created_at: number;
  duration_ms: number;
  mode: string;
  provider: string;
  model: string;
  status: string;
  error?: string;
  question?: string;
  incident_id?: string;
  signal_ids?: string[];
  title: string;
  summary: string;
  classification: string;
  severity: string;
  confidence: number;
  targets?: string[];
  hypothesis?: string;
  missed_reason?: string;
  evidence: { claim: string; source: string }[];
  recommendations: Recommendation[];
  trace?: { turn: number; tool: string; input: string; output_preview: string; is_error?: boolean; duration_ms: number }[];
  usage: { turns: number; input_tokens: number; output_tokens: number; cache_read_tokens?: number };
}

export interface Thresholds {
  pps: number;
  bps: number;
  fps: number;
}

export interface RuleView {
  id: string;
  name: string;
  description: string;
  category: string;
  direction: string;
  scope: string;
  severity: string;
  match: Record<string, unknown>;
  /** thresholds as written in the rule file */
  thresholds: Thresholds;
  baseline: { enabled: boolean; factor: number; min_pps: number; min_bps: number };
  conditions: {
    min_unique_sources?: number;
    min_unique_destinations?: number;
    min_avg_packet_size?: number;
    max_avg_packet_size?: number;
    min_samples?: number;
  };
  mitigation: { action: string; rate?: number; packet_length?: boolean; rtbh_escalation?: number; note?: string };
  rationale?: string;
  false_positives?: string;
  references?: string[];
  active: boolean;
  match_summary: string;
  sustain_seconds: number;
  hold_down_seconds: number;
  /** thresholds in force: file values with local overrides applied (before profile scaling) */
  base_thresholds: Thresholds;
  override?: { enabled?: boolean; pps?: number; bps?: number; fps?: number };
  effective: Record<string, { enabled: boolean; profile: string; pps: number; bps: number; fps: number }>;
}

export interface Profile {
  name: string;
  description: string;
  scale: number;
  disable?: string[];
  overrides?: Record<string, { scale?: number; pps?: number; bps?: number; fps?: number }>;
}

export interface Exporter {
  address: string;
  name: string;
  protocols: Record<string, number>;
  datagrams: number;
  records: number;
  errors: number;
  missing_template: number;
  lost_estimate: number;
  first_seen: number;
  last_seen: number;
  sampling_reported: number;
  sampling_override: number;
  sampling_learned: number;
  templates: number;
  records_per_sec: number;
  last_error?: string;
  listener: string;
}

export interface TargetRuleState {
  rule_id: string;
  rule_name: string;
  scope: string;
  target: string;
  direction: string;
  object_name: string;
  enabled: boolean;
  active: boolean;
  incident?: string;
  pps: number;
  bps: number;
  fps: number;
  avg_packet_size: number;
  samples: number;
  ratio: number;
  threshold_pps: number;
  threshold_bps: number;
  threshold_fps: number;
  baseline_ready: boolean;
  baseline_pps: number;
  baseline_bps: number;
  baseline_factor?: number;
  sustain_seconds: number;
  consecutive_over: number;
  min_unique_sources?: number;
  conditions: string;
  history_minutes?: { t: number; bps: number; pps: number }[];
  recent_seconds?: { t: number; bps: number; pps: number }[];
}

export interface TopResult {
  dimension: string;
  metric: string;
  seconds: number;
  total_bps: number;
  total_pps: number;
  records: number;
  rows: Row[];
}

export interface FlowFilter {
  seconds?: number;
  direction?: string;
  src?: string;
  dst?: string;
  protocol?: string;
  src_port?: number;
  dst_port?: number;
  fragment?: boolean;
  tcp_flags?: string;
}

export interface Scenario {
  id: string;
  name: string;
  category: string;
  description: string;
  target_kind: string;
  default_pps: number;
  sources: number;
  expected_rules: string[];
  relative_rule?: string;
}

export interface SimRun {
  id: string;
  scenario: string;
  name: string;
  target: string;
  pps: number;
  sources: number;
  started_at: number;
  ends_at: number;
}

export interface SimStatus {
  enabled: boolean;
  status?: {
    encoder: string;
    sampling_rate: number;
    collector: string;
    baseline: boolean;
    baseline_bps: number;
    datagrams_sent: number;
    specs_generated: number;
    runs: SimRun[] | null;
  };
  scenarios?: Scenario[];
}

// ---------------------------------------------------------------- admin

export interface Me {
  username: string;
  role: "viewer" | "operator" | "admin";
  objects: string[];
  can_operate: boolean;
  can_admin: boolean;
  demo: boolean;
  last_login?: number;
}

export interface UserRecord {
  username: string;
  role: string;
  objects: string[];
  disabled: boolean;
  created_at: number;
  last_login?: number;
  tokens: { id: string; name: string; prefix: string; created_at: number; last_used?: number }[];
}

export interface AuditEntry {
  t: number;
  user: string;
  role: string;
  client: string;
  action: string;
  target?: string;
  detail?: string;
  ok: boolean;
  error?: string;
}

export interface HistoryEntry {
  id: string;
  time: number;
  actor: string;
  comment: string;
  restart_required?: string[];
}

export interface ChannelStatus {
  name: string;
  type: string;
  enabled: boolean;
  sent: number;
  failed: number;
  last_sent?: number;
  last_error?: string;
}

export interface ChannelConfig {
  name: string;
  type: string;
  enabled: boolean;
  min_severity: string;
  events: string[] | null;
  url?: string;
  secret?: string;
  bot_token?: string;
  chat_id?: string;
  address?: string;
  protocol?: string;
  smtp_host?: string;
  smtp_port?: number;
  username?: string;
  password?: string;
  from?: string;
  to?: string[];
}

export interface ObjectConfig {
  name: string;
  prefixes: string[];
  profile: string;
  link_capacity: number | string;
  carpet_prefix_v4: number;
  carpet_prefix_v6: number;
  notes: string;
}

export interface ConfigDoc {
  collector: {
    listen: string[];
    read_buffer_bytes: number;
    queue_size: number;
    default_sampling_rate: number;
    workers: number;
    allow: string[] | null;
    forward: string[] | null;
  };
  api: { listen: string; tls_cert: string; tls_key: string; session_ttl: string; base_url: string; username: string; password: string };
  engine: {
    window: string;
    max_flow_spread: string;
    recent_flows: number;
    baseline_tau: string;
    baseline_learn: string;
    near_miss_ratio: number;
    signal_min_z: number;
    signal_min_pps: number | string;
    signal_min_bps: number | string;
    signal_min_seconds: number;
    incident_reopen: string;
    evidence_every: string;
    max_series: number;
  };
  exporters: { address: string; name: string; sampling_rate: number }[] | null;
  protected_objects: ObjectConfig[];
  rules_dir: string;
  data_dir: string;
  mitigation: {
    mode: string;
    driver: string;
    default_ttl: string;
    withdraw_after: string;
    max_active: number;
    min_prefix_v4: number;
    min_prefix_v6: number;
    allow_rtbh: boolean;
    never_mitigate: string[] | null;
    exabgp: { command_file: string; rtbh_next_hop: string; rtbh_community: string };
    webhook: { url: string; secret: string };
  };
  notifications: { channels: ChannelConfig[] | null };
  analyst: {
    enabled: boolean;
    provider: string;
    model: string;
    effort: string;
    interval: string;
    language: string;
    max_turns: number;
    max_tokens: number;
    auto_run: boolean;
    openai_compat: { base_url: string; model: string; api_key_env: string };
  };
  demo: { enabled: boolean; encoder: string; sampling_rate: number; target: string; baseline: boolean; baseline_bps: number | string };
}

export interface ConfigResponse {
  config: ConfigDoc;
  restart_pending: string[];
  profiles: string[];
  config_path: string;
  /** false when the configuration file cannot be written (read-only mount) */
  writable: boolean;
  notification_events: string[];
}

// ---------------------------------------------------------------- transport

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-Requested-With"] = "ddosd";
  const res = await fetch("/api/v1" + path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) window.dispatchEvent(new Event("ddosd:unauthorized"));
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    if (!res.ok) throw new ApiError(res.status, text || res.statusText);
    return text as unknown as T;
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error ?? res.statusText;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

export const api = {
  get: <T,>(path: string) => req<T>("GET", path),
  post: <T,>(path: string, body: unknown = {}) => req<T>("POST", path, body),
  put: <T,>(path: string, body: unknown) => req<T>("PUT", path, body),
  patch: <T,>(path: string, body: unknown) => req<T>("PATCH", path, body),
  del: <T,>(path: string) => req<T>("DELETE", path),
};
