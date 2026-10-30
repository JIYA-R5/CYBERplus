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
} from '../types';

const API_BASE = '/api';

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
  } = {}): Promise<{ total: number; limit: number; offset: number; alerts: SecurityAlert[] }> {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', params.limit.toString());
    if (params.offset) query.set('offset', params.offset.toString());
    if (params.severity && params.severity !== 'All') query.set('severity', params.severity);
    if (params.status && params.status !== 'All') query.set('status', params.status);
    if (params.search) query.set('search', params.search);

    const res = await fetch(`${API_BASE}/alerts?${query.toString()}`);
    return handleResponse(res);
  },

  async getAlert(alertId: string): Promise<SecurityAlert> {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`);
    return handleResponse<SecurityAlert>(res);
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
      headers: { 'Content-Type': 'application/json' },
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

  // Gemini Security Copilot
  async getCopilotExplanation(incidentId: string): Promise<{ status: string; explanation: CopilotExplanation; incident: any; safe_recommendations?: any }> {
    const res = await fetch(`${API_BASE}/copilot/explain/${encodeURIComponent(incidentId)}`);
    return handleResponse(res);
  },

  async getCopilotSummary(): Promise<{ status: string; gemini_active: boolean; provider: string; summary: string; total_incidents: number }> {
    const res = await fetch(`${API_BASE}/copilot/summary`);
    return handleResponse(res);
  },
};

