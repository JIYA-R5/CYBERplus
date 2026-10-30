export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type AlertStatus = 'New' | 'Investigating' | 'Resolved' | 'Dismissed';
export type CollectorStatusType = 'running' | 'stopped' | 'connecting' | 'error';
export type DataSource = 'LIVE' | 'PCAP REPLAY' | 'SIMULATION';
export type TimeRange = '1h' | '6h' | '24h' | '7d';

export interface CollectorStatus {
  status: CollectorStatusType;
  capture_interface: string;
  uptime_seconds: number;
  packet_count: number;
  event_count: number;
  parsing_errors: number;
  last_event_received: string | null;
  active_session: boolean;
  mode: string;
}

export interface NetworkInterface {
  name: string;
  description: string;
  addresses: string[];
  id?: string;
  alias?: string;
  ip?: string | null;
  is_active?: boolean;
}

export interface MetricsSummary {
  packets_observed: number;
  current_pps: number;
  incoming_bandwidth_kbps: number;
  outgoing_bandwidth_kbps: number;
  active_connections: number;
  suspicious_events: number;
  open_security_alerts: number;
  collector_health: string;
  data_source: DataSource;
  trend?: {
    packets_change_pct: number;
    alerts_change_pct: number;
    pps_change_pct: number;
  };
}

export interface TimelineDataPoint {
  timestamp: string;
  pps: number;
  incoming_bps: number;
  outgoing_bps: number;
  bandwidth_kbps: number;
  suspicious_count: number;
  rule_detections: number;
  ml_detections: number;
}

export interface ProtocolStat {
  protocol: string;
  count: number;
  percentage: number;
}

export interface TopTalker {
  ip: string;
  packets: number;
  bytes: number;
  flows: number;
}

export interface TopTalkersData {
  top_sources: TopTalker[];
  top_destinations: TopTalker[];
}

export interface NetworkEvent {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packet_size: number;
  flags?: string;
  flow_id?: string;
  is_suspicious: boolean;
  detection_status: string;
  data_source?: 'LIVE' | 'SIMULATION' | string;
}

export interface SecurityAlert {
  alert_id: string;
  title: string;
  severity: Severity;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  detection_method: 'Rule-based' | 'Supervised ML' | 'Anomaly Detection';
  status: AlertStatus;
  assigned_analyst?: string;
  anomaly_score?: number;
  confidence?: number;
  explanation: string;
  recommended_action: string;
  evidence?: Record<string, any>;
  related_events?: NetworkEvent[];
  review_history?: Array<{
    timestamp: string;
    analyst: string;
    verdict: string;
    notes?: string;
  }>;
  suggested_steps?: string[];
  mitre_tactic?: string;
}

export interface HostInfo {
  ip: string;
  first_seen: string;
  last_seen: string;
  packets?: number;
  total_packets?: number;
  bytes?: number;
  total_bytes?: number;
  flows?: number;
  flow_count?: number;
  contacted_ports?: number[];
  frequent_ports?: number[];
  protocols?: Record<string, number>;
  alerts_count?: number;
  alert_count?: number;
  recent_activity?: string;
  role?: string;
}

export interface ModelMetadata {
  web_log_model?: {
    name: string;
    version: string;
    type: string;
    trained_at?: string;
    precision?: number;
    recall?: number;
    f1_score?: number;
    false_positive_rate?: number;
    confusion_matrix?: number[][];
    feature_importance?: Record<string, number>;
    threshold?: number;
    limitations: string;
    data_provenance?: string;
  };
  network_anomaly_model?: {
    name: string;
    version: string;
    type: string;
    trained_at?: string;
    threshold?: number;
    anomaly_score_definition: string;
    features: string[];
    limitations: string;
    data_provenance?: string;
  };
}

export interface ResponseAction {
  action_id: string;
  title: string;
  target: string;
  action_type: 'simulate' | 'block_ip' | 'rate_limit' | 'isolate_host' | 'log_only';
  risk_level: 'Low' | 'Medium' | 'High';
  recommended: boolean;
  explanation: string;
  expected_effect: string;
  dry_run_supported: boolean;
}

export interface ThreatMarker {
  latitude: number;
  longitude: number;
  country: string;
  country_code?: string;
  city: string;
  asn?: string;
  org?: string;
  source_ips: string[];
  incident_ids?: string[];
  categories: string[];
  severity: string;
  max_severity?: string;
  total_packets?: number;
  first_seen?: string;
  last_seen?: string;
  accuracy_km?: number;
}

export interface CountryIncidentSummary {
  incident_id: string;
  category: string;
  severity: string;
  source_ip: string;
  timestamp?: string;
  packets?: number;
}

export interface CountryAggregate {
  country: string;
  country_code?: string;
  iso3?: string;
  intensity_score: number;
  incident_count: number;
  unique_ips: number;
  source_ips?: string[];
  max_severity?: string;
  top_category?: string;
  severities?: Record<string, number>;
  categories?: Record<string, number>;
  recent_incidents?: CountryIncidentSummary[];
}

export interface ThreatActivityPoint {
  time_bucket: string;
  label: string;
  total_events: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface LocalNetworkHost {
  ip: string;
  rfc_type?: string;
  packet_count?: number;
  categories: string[];
  incidents: string[];
  severity?: string;
  status?: string;
}

export interface ThreatMapStatistics {
  total_geolocated_sources: number;
  countries_detected: number;
  total_suspicious_events: number;
  unlocated_source_ips: number;
  high_critical_events: number;
}

export interface ThreatMapData {
  status: string;
  markers: ThreatMarker[];
  country_aggregates: CountryAggregate[];
  local_network: LocalNetworkHost[];
  activity_timeline?: ThreatActivityPoint[];
  disclaimer: string;
  total_public_markers: number;
  total_local_hosts: number;
  total_incidents_analyzed: number;
  statistics: ThreatMapStatistics;
}

export interface IpIntelligence {
  ip: string;
  is_public: boolean;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  accuracy_km?: number;
  accuracy_radius?: number;
  asn?: string;
  org?: string;
  status: string;
  rfc_designation?: string;
}

export interface CopilotExplanation {
  provider: string;
  summary: string;
  mechanism: string;
  threat_hypotheses: string;
  recommended_actions: string;
  confidence_score: number;
  ai_disclaimer: string;
  timeline?: { timestamp: string; event: string }[];
}

