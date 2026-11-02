import {
  CollectorStatus,
  NetworkInterface,
  MetricsSummary,
  TimelineDataPoint,
  ProtocolStat,
  TopTalkersData,
  NetworkEvent,
  SecurityAlert,
  HostInfo,
  ModelMetadata,
  ResponseAction,
  ThreatMapData,
  IpIntelligence,
  CopilotExplanation,
  IPSMetrics,
  IPSSettings,
  IPSActionRecord,
  IPSAllowlistEntry,
  IPSPreventionMode,
} from '../types';

const API_BASE = '/api';
const DEFAULT_ADMIN_KEY = 'wearewinning';

export function getAdminKey(): string {
  const stored = localStorage.getItem('sentinel_admin_key');
  if (stored !== null && stored !== undefined && stored.trim() !== '') return stored.trim();
  const envKey = (import.meta as any).env?.VITE_SENTINEL_ADMIN_KEY;
  if (envKey) return envKey.trim();
  return DEFAULT_ADMIN_KEY;
}

export function setAdminKey(key: string): void {
  if (key && key.trim()) {
    localStorage.setItem('sentinel_admin_key', key.trim());
  } else {
    localStorage.removeItem('sentinel_admin_key');
  }
}

export function getAdminHeaders(customHeaders: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...customHeaders,
  };
  const key = getAdminKey();
  if (key) {
    headers['X-Sentinel-Admin-Key'] = key;
  }
  return headers;
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorText = await res.text();
    let message = `API request failed with status ${res.status}`;
    try {
      const errJson = JSON.parse(errorText);
      message = errJson.detail || errJson.message || message;
    } catch {
      if (errorText) message = errorText;
    }
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

export function normalizeAlert(raw: any): SecurityAlert {
  if (!raw) return {} as SecurityAlert;
  const alertId = raw.alert_id || raw.incident_id || raw.id || `ALERT-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
  const title = raw.title || raw.category || raw.rule_name || 'Suspicious Activity';
  const srcIp = raw.src_ip || raw.source_ip || raw.source || '0.0.0.0';
  const dstIp = raw.dst_ip || raw.destination_ip || raw.destination || 'Internal Subnet';
  const severity = raw.severity || 'Medium';
  const status = raw.status || 'New';
  const timestamp = raw.timestamp || raw.first_seen || raw.created_at || new Date().toISOString();
  const detectionMethod = raw.detection_method || 'Rule-based';
  const explanation = raw.explanation || raw.evidence || raw.summary || 'Security event detected by SentinelAI engine.';

  return {
    ...raw,
    alert_id: alertId,
    title,
    src_ip: srcIp,
    dst_ip: dstIp,
    severity,
    status,
    timestamp,
    detection_method: detectionMethod,
    explanation,
  };
}

export const api = {
  // Collector
  async getCollectorStatus(): Promise<CollectorStatus> {
    const res = await fetch(`${API_BASE}/collector/status`);
    return handleResponse<CollectorStatus>(res);
  },

  async getCollectorInterfaces(): Promise<NetworkInterface[]> {
    const res = await fetch(`${API_BASE}/collector/interfaces`);
    const data = await handleResponse<{ interfaces: NetworkInterface[] }>(res);
    return data.interfaces || [];
  },

  async startCollector(interfaceName?: string, mode?: string, force: boolean = true): Promise<{ status: string; message: string }> {
    const res = await fetch(`${API_BASE}/collector/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: interfaceName, mode, force }),
    });
    return handleResponse(res);
  },

  async stopCollector(): Promise<{ status: string; message: string }> {
    const res = await fetch(`${API_BASE}/collector/stop`, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  // Metrics
  async getMetricsSummary(): Promise<MetricsSummary> {
    const res = await fetch(`${API_BASE}/metrics/summary`);
    return handleResponse<MetricsSummary>(res);
  },

  async getTimeline(range: string = '24h'): Promise<TimelineDataPoint[]> {
    const res = await fetch(`${API_BASE}/metrics/timeline?range=${range}`);
    const data = await handleResponse<{ timeline: TimelineDataPoint[] }>(res);
    return data.timeline || [];
  },

  async getProtocols(): Promise<ProtocolStat[]> {
    const res = await fetch(`${API_BASE}/metrics/protocols`);
    const data = await handleResponse<{ protocols: ProtocolStat[] }>(res);
    return data.protocols || [];
  },

  async getTopTalkers(): Promise<TopTalkersData> {
    const res = await fetch(`${API_BASE}/metrics/top-talkers`);
    return handleResponse<TopTalkersData>(res);
  },

  // Events
  async getEvents(params: {
    limit?: number;
    offset?: number;
    protocol?: string;
    suspicious_only?: boolean;
    search?: string;
  } = {}): Promise<{ total: number; limit: number; offset: number; events: NetworkEvent[] }> {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', params.limit.toString());
    if (params.offset) query.set('offset', params.offset.toString());
    if (params.protocol) query.set('protocol', params.protocol);
    if (params.suspicious_only !== undefined) query.set('suspicious_only', params.suspicious_only.toString());
    if (params.search) query.set('search', params.search);

    const res = await fetch(`${API_BASE}/events?${query.toString()}`);
    return handleResponse(res);
  },

  // Alerts
  async getAlerts(params: {
    limit?: number;
    offset?: number;
    severity?: string;
    status?: string;
    search?: string;
  } = {}): Promise<{ total: number; limit: number; offset: number; alerts: SecurityAlert[]; items?: SecurityAlert[] }> {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', params.limit.toString());
    if (params.offset) query.set('offset', params.offset.toString());
    if (params.severity && params.severity !== 'All') query.set('severity', params.severity);
    if (params.status && params.status !== 'All') query.set('status', params.status);
    if (params.search) query.set('search', params.search);

    const res = await fetch(`${API_BASE}/alerts?${query.toString()}`);
    const data = await handleResponse<any>(res);
    const rawList = data.items || data.alerts || (Array.isArray(data) ? data : []);
    const list: SecurityAlert[] = rawList.map(normalizeAlert);
    return {
      total: data.total ?? list.length,
      limit: data.limit ?? data.page_size ?? 25,
      offset: data.offset ?? 0,
      alerts: list,
      items: list,
    };
  },

  async getAlert(alertId: string): Promise<SecurityAlert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`);
    const data = await handleResponse<any>(res);
    return normalizeAlert(data);
  },

  async patchAlertVerdict(alertId: string, verdict: string, notes?: string): Promise<{ success: boolean; status: string; verdict: string }> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict, notes }),
    });
    return handleResponse(res);
  },

  // Hosts
  async getHosts(): Promise<HostInfo[]> {
    const res = await fetch(`${API_BASE}/hosts`);
    const data = await handleResponse<{ hosts: HostInfo[] }>(res);
    return data.hosts || [];
  },

  async getHost(ip: string): Promise<HostInfo & { flows_history?: NetworkEvent[]; alerts_history?: SecurityAlert[] }> {
    const res = await fetch(`${API_BASE}/hosts/${ip}`);
    return handleResponse(res);
  },

  // Models
  async getModelMetrics(): Promise<ModelMetadata> {
    const res = await fetch(`${API_BASE}/models/metrics`);
    return handleResponse<ModelMetadata>(res);
  },

  // Safe Response
  async getResponseRecommendations(alertId: string): Promise<{ actions: ResponseAction[] }> {
    const res = await fetch(`${API_BASE}/response/recommendations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId }),
    });
    return handleResponse(res);
  },

  async executeResponse(actionId: string, simulate: boolean = true, notes?: string): Promise<{ success: boolean; result: string; executed_at: string }> {
    const res = await fetch(`${API_BASE}/response/execute`, {
      method: 'POST',
      headers: getAdminHeaders(),
      body: JSON.stringify({ action_id: actionId, simulate, notes }),
    });
    return handleResponse(res);
  },

  // Threat Intelligence & GeoIP
  async getThreatMap(params?: { severity?: string; category?: string; country?: string; timeRange?: string }): Promise<ThreatMapData> {
    const query = new URLSearchParams();
    if (params?.severity && params.severity !== 'All') query.append('severity', params.severity);
    if (params?.category && params.category !== 'All') query.append('category', params.category);
    if (params?.country && params.country !== 'All') query.append('country', params.country);
    if (params?.timeRange) query.append('time_range', params.timeRange);
    const qs = query.toString() ? `?${query.toString()}` : '';
    const res = await fetch(`${API_BASE}/threat-map${qs}`);
    return handleResponse<ThreatMapData>(res);
  },

  async lookupIp(ip: string): Promise<{ status: string; ip: string; intelligence: IpIntelligence; recent_flows_count: number; related_incidents_count: number; recent_flows: any[]; incidents: any[] }> {
    const res = await fetch(`${API_BASE}/threat-map/ip-lookup?ip=${encodeURIComponent(ip)}`);
    return handleResponse(res);
  },

  async simulateAttack(payload: {
    source_ip: string;
    target_ip?: string;
    target_port?: number;
    protocol?: string;
    attack_type?: string;
    severity?: string;
    event_count?: number;
  }): Promise<{ status: string; message: string; event: any }> {
    const res = await fetch(`${API_BASE}/threat-map/simulate-attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return handleResponse(res);
  },

  // Gemini Security Copilot
  async getCopilotExplanation(incidentId: string): Promise<{ status: string; explanation: CopilotExplanation; incident: any; safe_recommendations?: any }> {
    const res = await fetch(`${API_BASE}/copilot/explain/${encodeURIComponent(incidentId)}`);
    return handleResponse(res);
  },

  async getCopilotSummary(): Promise<{ status: string; gemini_active: boolean; provider: string; summary: string; total_incidents: number }> {
    const res = await fetch(`${API_BASE}/copilot/summary`);
    return handleResponse(res);
  },

  // ---------------------------------------------------------------------------
  // IPS (Intrusion Prevention System) API Methods
  // ---------------------------------------------------------------------------
  async getIPSStatus(): Promise<{
    status: string;
    metrics: IPSMetrics;
    prevention_mode: IPSPreventionMode;
    confidence_threshold: number;
    is_elevated: boolean;
    is_windows_firewall: boolean;
    active_blocks_count: number;
    settings: IPSSettings;
    timestamp: string;
  }> {
    const res = await fetch(`${API_BASE}/ips/status`);
    return handleResponse(res);
  },

  async getIPSActions(params: {
    page?: number;
    page_size?: number;
    status?: string;
    search?: string;
  } = {}): Promise<{
    status: string;
    items: IPSActionRecord[];
    total: number;
    page: number;
    page_size: number;
    total_pages: number;
  }> {
    const query = new URLSearchParams();
    if (params.page) query.set('page', params.page.toString());
    if (params.page_size) query.set('page_size', params.page_size.toString());
    if (params.status && params.status !== 'All') query.set('status', params.status);
    if (params.search) query.set('search', params.search);
    const res = await fetch(`${API_BASE}/ips/actions?${query.toString()}`);
    return handleResponse(res);
  },

  async setIPSMode(mode: IPSPreventionMode, operator: string = 'SOC Administrator', adminKey?: string): Promise<{ status: string; message: string; settings: IPSSettings }> {
    const headers = getAdminHeaders();
    if (adminKey && adminKey.trim()) {
      headers['X-Sentinel-Admin-Key'] = adminKey.trim();
    }
    const res = await fetch(`${API_BASE}/ips/mode`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ mode, operator }),
    });
    return handleResponse(res);
  },

  async unblockIPS(target: string, operator: string = 'SOC Administrator', adminKey?: string): Promise<{ status: string; result: any }> {
    const headers = getAdminHeaders();
    if (adminKey && adminKey.trim()) {
      headers['X-Sentinel-Admin-Key'] = adminKey.trim();
    }
    const res = await fetch(`${API_BASE}/ips/unblock`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ target, operator }),
    });
    return handleResponse(res);
  },

  async getIPSAllowlist(): Promise<{ status: string; allowlist: IPSAllowlistEntry[] }> {
    const res = await fetch(`${API_BASE}/ips/allowlist`);
    return handleResponse(res);
  },

  async addIPSAllowlist(ip_or_cidr: string, description: string = ''): Promise<{ status: string; entry: IPSAllowlistEntry }> {
    const res = await fetch(`${API_BASE}/ips/allowlist`, {
      method: 'POST',
      headers: getAdminHeaders(),
      body: JSON.stringify({ ip_or_cidr, description }),
    });
    return handleResponse(res);
  },

  async deleteIPSAllowlist(entryId: string): Promise<{ status: string; entry_id: string }> {
    const res = await fetch(`${API_BASE}/ips/allowlist/${encodeURIComponent(entryId)}`, {
      method: 'DELETE',
      headers: getAdminHeaders(),
    });
    return handleResponse(res);
  },

  async toggleIPSAllowlist(entryId: string, enabled: boolean): Promise<{ status: string; entry_id: string; enabled: boolean }> {
    const res = await fetch(`${API_BASE}/ips/allowlist/${encodeURIComponent(entryId)}/toggle?enabled=${enabled}`, {
      method: 'PATCH',
      headers: getAdminHeaders(),
    });
    return handleResponse(res);
  },

  async getIPSSettings(): Promise<{ status: string; settings: IPSSettings; is_elevated: boolean }> {
    const res = await fetch(`${API_BASE}/ips/settings`);
    return handleResponse(res);
  },

  async updateIPSSettings(settings: Partial<IPSSettings>): Promise<{ status: string; settings: IPSSettings }> {
    const res = await fetch(`${API_BASE}/ips/settings`, {
      method: 'POST',
      headers: getAdminHeaders(),
      body: JSON.stringify(settings),
    });
    return handleResponse(res);
  },

  async getIPSActionExplanation(actionId: string): Promise<{ status: string; action_id: string; action: IPSActionRecord; explanation: any }> {
    const res = await fetch(`${API_BASE}/ips/actions/${encodeURIComponent(actionId)}/explain`);
    return handleResponse(res);
  },
};

