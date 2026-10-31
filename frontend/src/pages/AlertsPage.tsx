import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Bell,
  ShieldAlert,
  Network,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  ArrowUpDown,
  UserCheck,
  Eye,
  RefreshCw,
  Server,
  X,
  AlertTriangle,
  Info,
  Sliders,
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityAlert, HostInfo, NetworkEvent } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

type TabType = 'alerts' | 'threats' | 'hosts';

interface AlertsPageProps {
  defaultTab?: TabType;
  initialHostIp?: string | null;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({
  defaultTab = 'alerts',
  initialHostIp,
}) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlTab = searchParams.get('tab') as TabType | null;

  // Active sub-tab state
  const [activeTab, setActiveTab] = useState<TabType>(urlTab || defaultTab);

  // Sync tab state with query params or props
  useEffect(() => {
    if (urlTab && (urlTab === 'alerts' || urlTab === 'threats' || urlTab === 'hosts')) {
      setActiveTab(urlTab);
    } else if (defaultTab) {
      setActiveTab(defaultTab);
    }
  }, [urlTab, defaultTab]);

  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab);
    setSearchParams({ tab });
  };

  // ---------------------------------------------------------------------------
  // SHARED / DRAWER STATE
  // ---------------------------------------------------------------------------
  const [selectedDrawerAlert, setSelectedDrawerAlert] = useState<SecurityAlert | null>(null);

  // ---------------------------------------------------------------------------
  // 1. SECURITY ALERTS STATE
  // ---------------------------------------------------------------------------
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [totalAlerts, setTotalAlerts] = useState<number>(0);
  const [alertsLoading, setAlertsLoading] = useState<boolean>(true);
  const [alertsSeverityFilter, setAlertsSeverityFilter] = useState<string>('All');
  const [alertsStatusFilter, setAlertsStatusFilter] = useState<string>('All');
  const [alertsSearchQuery, setAlertsSearchQuery] = useState<string>('');
  const [alertsPage, setAlertsPage] = useState<number>(0);
  const pageSize = 12;

  const loadAlerts = async () => {
    try {
      setAlertsLoading(true);
      const res = await api.getAlerts({
        limit: 100,
        severity: alertsSeverityFilter,
        status: alertsStatusFilter,
        search: alertsSearchQuery,
      });
      setAlerts(res.alerts || []);
      setTotalAlerts(res.total || res.alerts?.length || 0);
    } catch (err) {
      console.error('Failed to load alerts', err);
    } finally {
      setAlertsLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [alertsSeverityFilter, alertsStatusFilter, alertsSearchQuery]);

  const paginatedAlerts = alerts.slice(alertsPage * pageSize, (alertsPage + 1) * pageSize);
  const totalAlertPages = Math.ceil(alerts.length / pageSize) || 1;

  // ---------------------------------------------------------------------------
  // 2. THREAT DETECTION STATE
  // ---------------------------------------------------------------------------
  const [threatMethodFilter, setThreatMethodFilter] = useState<string>('All');
  const [threatSeverityFilter, setThreatSeverityFilter] = useState<string>('All');
  const [threatSearchQuery, setThreatSearchQuery] = useState<string>('');

  const filteredThreats = alerts.filter((a) => {
    if (threatMethodFilter !== 'All' && a.detection_method !== threatMethodFilter) return false;
    if (threatSeverityFilter !== 'All' && a.severity !== threatSeverityFilter) return false;
    if (threatSearchQuery) {
      const q = threatSearchQuery.toLowerCase();
      const matchTitle = a.title.toLowerCase().includes(q);
      const matchHost = a.src_ip.toLowerCase().includes(q) || a.dst_ip.toLowerCase().includes(q);
      if (!matchTitle && !matchHost) return false;
    }
    return true;
  });

  // ---------------------------------------------------------------------------
  // 3. HOSTS AND CONNECTIONS STATE
  // ---------------------------------------------------------------------------
  const [hosts, setHosts] = useState<HostInfo[]>([]);
  const [selectedHost, setSelectedHost] = useState<HostInfo | null>(null);
  const [hostsLoading, setHostsLoading] = useState<boolean>(true);
  const [hostsSearchQuery, setHostsSearchQuery] = useState<string>('');

  const fetchHosts = async () => {
    try {
      setHostsLoading(true);
      const data = await api.getHosts();
      setHosts(data || []);

      const targetIp = initialHostIp || searchParams.get('ip');
      if (targetIp) {
        const match = (data || []).find((h) => h.ip === targetIp);
        if (match) {
          handleSelectHost(match);
        }
      }
    } catch (err) {
      console.error('Failed to load hosts', err);
    } finally {
      setHostsLoading(false);
    }
  };

  useEffect(() => {
    fetchHosts();
  }, [initialHostIp]);

  const handleSelectHost = async (host: HostInfo) => {
    setSelectedHost(host);
  };

  const filteredHosts = hosts.filter((h) => {
    if (!hostsSearchQuery) return true;
    const q = hostsSearchQuery.toLowerCase();
    const ports = h.contacted_ports || h.frequent_ports || [];
    return (
      h.ip.toLowerCase().includes(q) ||
      (h.recent_activity && h.recent_activity.toLowerCase().includes(q)) ||
      (h.role && h.role.toLowerCase().includes(q)) ||
      ports.some((p) => p.toString().includes(q))
    );
  });

  const getHostPorts = (h: HostInfo) => h.contacted_ports || h.frequent_ports || [];
  const getHostPackets = (h: HostInfo) => h.packets ?? h.total_packets ?? 0;
  const getHostBytes = (h: HostInfo) => h.bytes ?? h.total_bytes ?? 0;
  const getHostFlows = (h: HostInfo) => h.flows ?? h.flow_count ?? 0;
  const getHostAlerts = (h: HostInfo) => h.alerts_count ?? h.alert_count ?? 0;
  const getHostActivity = (h: HostInfo) => h.recent_activity || h.role || 'Active';

  return (
    <div className="space-y-6">
      {/* =======================================================================
          TOP PAGE HEADER & UNIFIED TAB NAVIGATION
      ======================================================================= */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
        <div>
          <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            <Bell className="w-5 h-5 text-cyan-400" />
            Alerts & Threat Operations
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Centralized hub for security incidents, hybrid threat detection heuristics, and host connection inventories.
          </p>
        </div>

        {/* Cohesive Sub-Tabs Navigation */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-950/80 border border-slate-800/80 rounded-lg shrink-0">
          <button
            onClick={() => handleTabChange('alerts')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'alerts'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                : 'text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent'
            }`}
          >
            <Bell className="w-3.5 h-3.5" />
            <span>Security Alerts</span>
            {alerts.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-cyan-500/30 text-cyan-300 font-mono">
                {alerts.length}
              </span>
            )}
          </button>

          <button
            onClick={() => handleTabChange('threats')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'threats'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                : 'text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Threat Detection</span>
          </button>

          <button
            onClick={() => handleTabChange('hosts')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
              activeTab === 'hosts'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                : 'text-slate-400 hover:text-white hover:bg-slate-900/60 border border-transparent'
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Hosts & Connections</span>
            {hosts.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-400 font-mono">
                {hosts.length}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* =======================================================================
          TAB 1: SECURITY ALERTS VIEW
      ======================================================================= */}
      {activeTab === 'alerts' && (
        <div className="space-y-6">
          {/* Filter and Search Bar */}
          <div className="soc-card p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search alerts by title, source IP, or destination IP..."
                value={alertsSearchQuery}
                onChange={(e) => {
                  setAlertsSearchQuery(e.target.value);
                  setAlertsPage(0);
                }}
                className="w-full pl-9 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Severity:</span>
                <select
                  value={alertsSeverityFilter}
                  onChange={(e) => {
                    setAlertsSeverityFilter(e.target.value);
                    setAlertsPage(0);
                  }}
                  className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none"
                >
                  <option value="All">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-slate-400">Status:</span>
                <select
                  value={alertsStatusFilter}
                  onChange={(e) => {
                    setAlertsStatusFilter(e.target.value);
                    setAlertsPage(0);
                  }}
                  className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none"
                >
                  <option value="All">All Statuses</option>
                  <option value="New">New</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Resolved">Resolved</option>
                  <option value="Dismissed">Dismissed</option>
                </select>
              </div>

              <button
                onClick={loadAlerts}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:text-white"
                title="Reload Alerts"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Refresh</span>
              </button>
            </div>
          </div>

          {/* Alerts Table */}
          <div className="soc-card p-5 space-y-4">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-400 border-b border-slate-800 font-mono">
                  <tr>
                    <th className="pb-3">Severity</th>
                    <th className="pb-3">Alert Title</th>
                    <th className="pb-3">Source Host</th>
                    <th className="pb-3">Destination Host</th>
                    <th className="pb-3">Method</th>
                    <th className="pb-3">Timestamp</th>
                    <th className="pb-3">Status</th>
                    <th className="pb-3 text-right">Triage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-slate-300">
                  {alertsLoading ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                        Loading security alerts...
                      </td>
                    </tr>
                  ) : paginatedAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                        No security alerts found matching selected filters.
                      </td>
                    </tr>
                  ) : (
                    paginatedAlerts.map((alert) => (
                      <tr
                        key={alert.alert_id}
                        onClick={() => setSelectedDrawerAlert(alert)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-3">
                          <SeverityBadge severity={alert.severity} size="sm" />
                        </td>
                        <td className="py-3 font-semibold text-white">
                          <div className="flex flex-col">
                            <span>{alert.title}</span>
                            <span className="text-[11px] text-slate-500 font-mono line-clamp-1 font-normal">
                              {alert.explanation}
                            </span>
                          </div>
                        </td>
                        <td className="py-3 font-mono text-cyan-400">{alert.src_ip}</td>
                        <td className="py-3 font-mono text-cyan-300">{alert.dst_ip}</td>
                        <td className="py-3">
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-400">
                            {alert.detection_method}
                          </span>
                        </td>
                        <td className="py-3 font-mono text-slate-400">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-3">
                          <StatusBadge status={alert.status} size="sm" />
                        </td>
                        <td className="py-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedDrawerAlert(alert);
                            }}
                            className="px-2.5 py-1 rounded text-[11px] bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 border border-cyan-500/30 font-medium"
                          >
                            Review
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Bar */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-xs font-mono text-slate-400">
              <span>
                Showing {paginatedAlerts.length} of {alerts.length} alerts
              </span>

              <div className="flex items-center gap-2">
                <button
                  disabled={alertsPage === 0}
                  onClick={() => setAlertsPage(alertsPage - 1)}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:text-white"
                >
                  Previous
                </button>
                <button
                  disabled={alertsPage >= totalAlertPages - 1}
                  onClick={() => setAlertsPage(alertsPage + 1)}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:text-white"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =======================================================================
          TAB 2: THREAT DETECTION VIEW
      ======================================================================= */}
      {activeTab === 'threats' && (
        <div className="space-y-6">
          {/* Detection Engine Status Banner */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div className="soc-card p-4 space-y-1 border-l-2 border-cyan-500">
              <span className="text-slate-400 uppercase text-[10px]">Methodology 1</span>
              <p className="font-semibold text-white">Rule Heuristics & Signatures</p>
              <p className="text-slate-500 text-[11px]">Deterministic pattern matching for known TTPs</p>
            </div>
            <div className="soc-card p-4 space-y-1 border-l-2 border-blue-500">
              <span className="text-slate-400 uppercase text-[10px]">Methodology 2</span>
              <p className="font-semibold text-white">Flow Isolation Forest</p>
              <p className="text-slate-500 text-[11px]">Statistical distance from benign baselines</p>
            </div>
            <div className="soc-card p-4 space-y-1 border-l-2 border-purple-500">
              <span className="text-slate-400 uppercase text-[10px]">Methodology 3</span>
              <p className="font-semibold text-white">Rate Velocity Monitors</p>
              <p className="text-slate-500 text-[11px]">Threshold anomaly spikes per unit window</p>
            </div>
          </div>

          {/* Filter and Search Bar */}
          <div className="soc-card p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3 flex-1 min-w-[240px]">
              <div className="relative w-full max-w-sm">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search threat name or host IP..."
                  value={threatSearchQuery}
                  onChange={(e) => setThreatSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Method:</span>
                <select
                  value={threatMethodFilter}
                  onChange={(e) => setThreatMethodFilter(e.target.value)}
                  className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none"
                >
                  <option value="All">All Methods</option>
                  <option value="Rule-based">Rule-based</option>
                  <option value="Anomaly Detection">Anomaly Detection</option>
                  <option value="Supervised ML">Supervised ML</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-slate-400">Severity:</span>
                <select
                  value={threatSeverityFilter}
                  onChange={(e) => setThreatSeverityFilter(e.target.value)}
                  className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none"
                >
                  <option value="All">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono">
                {filteredThreats.length} Detections
              </div>
            </div>
          </div>

          {/* Detections List Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {alertsLoading ? (
              <div className="col-span-2 p-12 text-center text-slate-400 font-mono text-xs soc-card">
                Loading detections from SentinelAI engine...
              </div>
            ) : filteredThreats.length === 0 ? (
              <div className="col-span-2 p-12 text-center text-slate-500 font-mono text-xs soc-card">
                No detections match the current filter criteria.
              </div>
            ) : (
              filteredThreats.map((item) => (
                <div
                  key={item.alert_id}
                  onClick={() => setSelectedDrawerAlert(item)}
                  className="soc-card p-5 hover:border-cyan-500/50 cursor-pointer space-y-4 group transition-all"
                >
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={item.severity} size="sm" />
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {item.detection_method}
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {item.title}
                      </h3>
                    </div>

                    <div className="text-right font-mono">
                      <span className="text-xs text-slate-400">
                        {item.anomaly_score !== undefined
                          ? `Score: ${(item.anomaly_score * 100).toFixed(0)}%`
                          : item.confidence !== undefined
                          ? `Conf: ${(item.confidence * 100).toFixed(0)}%`
                          : 'Rule Match'}
                      </span>
                    </div>
                  </div>

                  {/* Communication Line */}
                  <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 flex items-center justify-between text-xs font-mono">
                    <div>
                      <span className="text-slate-500 text-[10px] block">Source</span>
                      <span className="text-cyan-400 font-semibold">{item.src_ip}</span>
                    </div>
                    <span className="text-slate-600">→</span>
                    <div className="text-right">
                      <span className="text-slate-500 text-[10px] block">Destination</span>
                      <span className="text-cyan-300 font-semibold">{item.dst_ip}</span>
                    </div>
                  </div>

                  {/* Plain English Summary */}
                  <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">{item.explanation}</p>

                  {/* Bottom Metadata */}
                  <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                    <span>{new Date(item.timestamp).toLocaleString()}</span>
                    <span className="text-cyan-400 group-hover:underline flex items-center gap-1">
                      <Eye className="w-3.5 h-3.5" />
                      Inspect Evidence
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* =======================================================================
          TAB 3: HOSTS AND CONNECTIONS VIEW
      ======================================================================= */}
      {activeTab === 'hosts' && (
        <div className="space-y-6">
          {/* Search Bar */}
          <div className="soc-card p-4 flex items-center justify-between">
            <div className="relative w-full max-w-md">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search host by IP or contacted port..."
                value={hostsSearchQuery}
                onChange={(e) => setHostsSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div className="text-xs font-mono text-cyan-400 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              {filteredHosts.length} Observed Endpoints
            </div>
          </div>

          {/* Main Grid: Hosts List & Host Detail Drawer/Modal */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Host Cards / Table (2 Cols) */}
            <div className="lg:col-span-2 space-y-3">
              {hostsLoading ? (
                <div className="p-8 text-center text-slate-400 font-mono text-xs soc-card">
                  Loading network host directory...
                </div>
              ) : filteredHosts.length === 0 ? (
                <div className="p-8 text-center text-slate-500 font-mono text-xs soc-card">
                  No observed hosts match query.
                </div>
              ) : (
                filteredHosts.map((host) => {
                  const ports = getHostPorts(host);
                  const packets = getHostPackets(host);
                  const bytes = getHostBytes(host);
                  const flows = getHostFlows(host);
                  const alertsCount = getHostAlerts(host);
                  const activity = getHostActivity(host);

                  return (
                    <div
                      key={host.ip}
                      onClick={() => handleSelectHost(host)}
                      className={`soc-card p-4 cursor-pointer transition-all ${
                        selectedHost?.ip === host.ip ? 'soc-card-active' : 'hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400">
                            <Server className="w-4 h-4" />
                          </div>
                          <div>
                            <span className="font-mono font-bold text-sm text-white">{host.ip}</span>
                            <span className="text-[11px] text-slate-400 block font-mono">
                              {flows} active flows • {(bytes / 1024).toFixed(1)} KB transferred
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          {alertsCount > 0 && (
                            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30 flex items-center gap-1">
                              <ShieldAlert className="w-3.5 h-3.5" />
                              {alertsCount} Alert{alertsCount > 1 ? 's' : ''}
                            </span>
                          )}
                          <span className="text-xs text-cyan-400">Inspect →</span>
                        </div>
                      </div>

                      <div className="mt-3 pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                        <span>Ports Contacted: {ports.length > 0 ? ports.slice(0, 4).join(', ') : 'None'}</span>
                        <span>Activity: {activity}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Selected Host Detail Panel */}
            <div className="soc-card p-5 space-y-5 h-fit sticky top-24">
              {selectedHost ? (
                <>
                  <div className="flex items-start justify-between pb-3 border-b border-slate-800">
                    <div>
                      <span className="text-xs font-mono uppercase text-slate-400">Host Profile</span>
                      <h3 className="font-mono text-lg font-bold text-cyan-400 mt-0.5">{selectedHost.ip}</h3>
                    </div>
                    <button
                      onClick={() => setSelectedHost(null)}
                      className="p-1 text-slate-400 hover:text-white"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>

                  {/* Observed Metrics */}
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex justify-between p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-slate-400">Packets Observed:</span>
                      <span className="text-white font-bold">{getHostPackets(selectedHost).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-slate-400">Bytes Observed:</span>
                      <span className="text-white font-bold">{(getHostBytes(selectedHost) / 1024).toFixed(1)} KB</span>
                    </div>
                    <div className="flex justify-between p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-slate-400">Concurrent Flows:</span>
                      <span className="text-white font-bold">{getHostFlows(selectedHost)}</span>
                    </div>
                    <div className="flex justify-between p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-slate-400">First Observed:</span>
                      <span className="text-slate-300">
                        {selectedHost.first_seen ? new Date(selectedHost.first_seen).toLocaleTimeString() : 'N/A'}
                      </span>
                    </div>
                    <div className="flex justify-between p-2 rounded bg-slate-900 border border-slate-800">
                      <span className="text-slate-400">Last Observed:</span>
                      <span className="text-slate-300">
                        {selectedHost.last_seen ? new Date(selectedHost.last_seen).toLocaleTimeString() : 'N/A'}
                      </span>
                    </div>
                  </div>

                  {/* Contacted Ports Breakdown */}
                  <div>
                    <h4 className="text-xs uppercase font-mono text-slate-400 mb-2">Observed Ports</h4>
                    <div className="flex flex-wrap gap-1.5 font-mono text-xs">
                      {getHostPorts(selectedHost).length > 0 ? (
                        getHostPorts(selectedHost).map((port) => (
                          <span
                            key={port}
                            className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300"
                          >
                            :{port}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 text-xs">No explicit ports recorded.</span>
                      )}
                    </div>
                  </div>

                  {/* Associated Alerts */}
                  <div>
                    <h4 className="text-xs uppercase font-mono text-slate-400 mb-2">
                      Associated Alerts ({getHostAlerts(selectedHost)})
                    </h4>
                    {getHostAlerts(selectedHost) === 0 ? (
                      <p className="text-xs text-slate-500">No anomalous alerts associated with this host.</p>
                    ) : (
                      <div className="p-2.5 rounded bg-red-500/10 border border-red-500/20 text-xs text-red-300">
                        Host has triggered security rules or flow anomaly thresholds.
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="p-12 text-center text-slate-500 text-xs font-mono">
                  Select an observed host from the inventory to view communication history, ports, and alerts.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* =======================================================================
          SHARED SLIDE-OVER INVESTIGATION DRAWER
      ======================================================================= */}
      <AlertDetailDrawer
        alert={selectedDrawerAlert}
        onClose={() => setSelectedDrawerAlert(null)}
        onVerdictUpdated={(alertId) => {
          setAlerts((prev) =>
            prev.map((a) => (a.alert_id === alertId ? { ...a, status: 'Resolved' } : a))
          );
        }}
      />
    </div>
  );
};

export default AlertsPage;

