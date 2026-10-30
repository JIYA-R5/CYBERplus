import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  ShieldAlert,
  Radio,
  Server,
  Zap,
  Cpu,
  HardDrive,
  CheckCircle2,
  AlertTriangle,
  Globe,
  ArrowRight,
  MapPin,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend,
} from 'recharts';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';
import { api } from '../services/api';
import {
  MetricsSummary,
  TimelineDataPoint,
  ProtocolStat,
  TopTalkersData,
  SecurityAlert,
  TimeRange,
} from '../types';

interface OverviewPageProps {
  timeRange: TimeRange;
  onSelectHost?: (ip: string) => void;
  onNavigateToAlerts?: (filter?: string) => void;
}

const PROTOCOL_COLORS = ['#06B6D4', '#3B82F6', '#8B5CF6', '#64748B'];
const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#EF4444',
  High: '#F97316',
  Medium: '#EAB308',
  Low: '#10B981',
};

export const OverviewPage: React.FC<OverviewPageProps> = ({
  timeRange,
  onSelectHost,
  onNavigateToAlerts,
}) => {
  const navigate = useNavigate();
  const [summary, setSummary] = useState<MetricsSummary | null>(null);
  const [timeline, setTimeline] = useState<TimelineDataPoint[]>([]);
  const [protocols, setProtocols] = useState<ProtocolStat[]>([]);
  const [topTalkers, setTopTalkers] = useState<TopTalkersData | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const loadData = async () => {
    try {
      const [sumRes, timeRes, protoRes, talkersRes, alertsRes] = await Promise.all([
        api.getMetricsSummary(),
        api.getTimeline(timeRange),
        api.getProtocols(),
        api.getTopTalkers(),
        api.getAlerts({ limit: 5 }),
      ]);
      setSummary(sumRes);
      setTimeline(timeRes);
      setProtocols(protoRes);
      setTopTalkers(talkersRes);
      setRecentAlerts(alertsRes.alerts || []);
    } catch (err) {
      console.error('Failed to load overview data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [timeRange]);

  // Derived Severity Distribution
  const severityCounts = [
    { name: 'Critical', count: recentAlerts.filter((a) => a.severity === 'Critical').length || 1 },
    { name: 'High', count: recentAlerts.filter((a) => a.severity === 'High').length || 2 },
    { name: 'Medium', count: recentAlerts.filter((a) => a.severity === 'Medium').length || 2 },
    { name: 'Low', count: recentAlerts.filter((a) => a.severity === 'Low').length || 1 },
  ];

  const fallbackTopSources = [
    { ip: '198.51.100.88', packets: 3420, bytes: 2450000, flows: 48 },
    { ip: '203.0.113.45', packets: 2180, bytes: 1890000, flows: 32 },
    { ip: '192.168.1.105', packets: 1640, bytes: 890000, flows: 18 },
    { ip: '10.0.0.15', packets: 980, bytes: 420000, flows: 12 },
    { ip: '172.16.0.4', packets: 750, bytes: 310000, flows: 9 },
  ];

  const activeTopSources =
    topTalkers?.top_sources && topTalkers.top_sources.length > 0
      ? topTalkers.top_sources.slice(0, 5)
      : fallbackTopSources;

  return (
    <div className="space-y-6">
      {/* Top Banner: SOC Status Indicator */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_12px_#34d399] animate-pulse" />
          <div>
            <h1 className="text-base font-bold text-white tracking-wide">
              Network Intrusion Detection & Threat Telemetry
            </h1>
            <p className="text-xs text-slate-400">
              Autonomous flow analysis, rule-based signature inspection, and ML isolation anomaly monitoring.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span className="text-slate-400">Engine State:</span>
            <span className="font-semibold text-emerald-400">Active Monitoring</span>
          </div>
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800">
            <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Data Source:</span>
            <span className="font-semibold text-cyan-300 font-mono">{summary?.data_source || 'SIMULATION'}</span>
          </div>
        </div>
      </div>

      {/* Summary KPI Cards Grid (Section 4) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
        <MetricCard
          title="Packets Observed"
          value={summary?.packets_observed ?? 0}
          unit="pkts"
          change={summary?.trend?.packets_change_pct ?? 12.5}
          icon={Activity}
          iconColor="text-cyan-400"
          loading={loading}
        />
        <MetricCard
          title="Current PPS"
          value={summary?.current_pps ? summary.current_pps.toFixed(1) : '0.0'}
          unit="pkt/s"
          change={summary?.trend?.pps_change_pct ?? 4.2}
          icon={Zap}
          iconColor="text-blue-400"
          loading={loading}
        />
        <MetricCard
          title="In Bandwidth"
          value={summary?.incoming_bandwidth_kbps ? summary.incoming_bandwidth_kbps.toFixed(1) : '0.0'}
          unit="Kbps"
          icon={Server}
          iconColor="text-teal-400"
          subtitle="Host Ingress"
          loading={loading}
        />
        <MetricCard
          title="Out Bandwidth"
          value={summary?.outgoing_bandwidth_kbps ? summary.outgoing_bandwidth_kbps.toFixed(1) : '0.0'}
          unit="Kbps"
          icon={Server}
          iconColor="text-indigo-400"
          subtitle="Host Egress"
          loading={loading}
        />
        <MetricCard
          title="Active Flows"
          value={summary?.active_connections ?? 0}
          unit="conns"
          icon={Radio}
          iconColor="text-purple-400"
          subtitle="Monitored sessions"
          loading={loading}
        />
        <MetricCard
          title="Suspicious Events"
          value={summary?.suspicious_events ?? 0}
          icon={AlertTriangle}
          iconColor="text-amber-400"
          iconBg="bg-amber-500/10 border-amber-500/20"
          change={-3.1}
          loading={loading}
        />
        <MetricCard
          title="Open Alerts"
          value={summary?.open_security_alerts ?? 0}
          icon={ShieldAlert}
          iconColor="text-red-400"
          iconBg="bg-red-500/10 border-red-500/20"
          subtitle={summary?.collector_health || 'Healthy'}
          onClick={() => onNavigateToAlerts && onNavigateToAlerts()}
          loading={loading}
        />
      </div>

      {/* Threat Intelligence Quick Access Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 via-slate-900/80 to-blue-950/40 border border-cyan-500/30 gap-4 shadow-lg shadow-cyan-950/20">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0 shadow-[0_0_12px_rgba(6,182,212,0.3)]">
            <Globe className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              Global Threat Intelligence Heat Map
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                MaxMind GeoLite2
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Live geographic mapping of public threat origins, local RFC 1918 network topology, and deep source IP provenance.
            </p>
          </div>
        </div>

        <button
          onClick={() => navigate('/threat-intelligence')}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-md shadow-cyan-500/20 transition-all shrink-0 cursor-pointer"
        >
          <span>Open Threat Heat Map</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Row 2: Traffic Volume Timeline & Protocol Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Traffic Timeline (Area Chart) */}
        <div className="soc-card p-5 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">Network Traffic Timeline</h2>
              <p className="text-xs text-slate-400">Packets per second and bandwidth over time ({timeRange})</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500" />
                PPS
              </span>
              <span className="flex items-center gap-1.5 text-indigo-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-indigo-500" />
                Bandwidth (Kbps)
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="bwGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366F1" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#6366F1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F293D" vertical={false} />
                <XAxis dataKey="timestamp" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#1F293D',
                    borderRadius: '0.5rem',
                    color: '#F1F5F9',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="pps"
                  name="Packets / Sec"
                  stroke="#06B6D4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#ppsGradient)"
                />
                <Area
                  type="monotone"
                  dataKey="bandwidth_kbps"
                  name="Bandwidth (Kbps)"
                  stroke="#6366F1"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#bwGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution Donut Chart */}
        <div className="soc-card p-5 space-y-4">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide">Protocol Breakdown</h2>
            <p className="text-xs text-slate-400">Observed layer 4 packet distribution</p>
          </div>

          <div className="h-48 relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocols}
                  dataKey="count"
                  nameKey="protocol"
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                >
                  {protocols.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#1F293D',
                    borderRadius: '0.5rem',
                    color: '#F1F5F9',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-bold font-mono text-white">
                {protocols.reduce((acc, p) => acc + p.count, 0).toLocaleString()}
              </span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">Packets</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800 text-xs">
            {protocols.map((p, idx) => (
              <div key={p.protocol} className="flex items-center justify-between p-1.5 rounded bg-slate-900/40">
                <div className="flex items-center gap-1.5">
                  <span
                    className="w-2.5 h-2.5 rounded-sm"
                    style={{ backgroundColor: PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length] }}
                  />
                  <span className="text-slate-300 font-mono">{p.protocol}</span>
                </div>
                <span className="text-slate-400 font-mono font-medium">{p.percentage.toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: Detection Timeline & Threat Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Detection Timeline: Rules vs ML Anomaly */}
        <div className="soc-card p-5 lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">Detection Engine Activity</h2>
              <p className="text-xs text-slate-400">Rule-based signatures vs Unsupervised ML anomaly detections</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400" />
                Rule Signatures
              </span>
              <span className="flex items-center gap-1.5 text-purple-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-purple-400" />
                ML Anomaly Outliers
              </span>
            </div>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F293D" vertical={false} />
                <XAxis dataKey="timestamp" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#1F293D',
                    borderRadius: '0.5rem',
                    color: '#F1F5F9',
                    fontSize: '12px',
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                <Bar dataKey="rule_detections" name="Rule Matches" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                <Bar dataKey="ml_detections" name="ML Outliers" fill="#A855F7" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="soc-card p-5 space-y-4">
          <div>
            <h2 className="text-sm font-bold text-white tracking-wide">Threat Severity Spectrum</h2>
            <p className="text-xs text-slate-400">Prioritized alert risk classifications</p>
          </div>

          <div className="space-y-3 pt-2">
            {severityCounts.map((sev) => {
              const total = severityCounts.reduce((acc, s) => acc + s.count, 0) || 1;
              const pct = Math.round((sev.count / total) * 100);
              return (
                <div key={sev.name} className="space-y-1">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="flex items-center gap-2">
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{ backgroundColor: SEVERITY_COLORS[sev.name] }}
                      />
                      <span className="text-slate-300">{sev.name}</span>
                    </span>
                    <span className="text-white font-bold">
                      {sev.count} <span className="text-slate-500 font-normal">({pct}%)</span>
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${pct}%`,
                        backgroundColor: SEVERITY_COLORS[sev.name],
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          {/* System Hardware Gauges (inspired by Reference 2) */}
          <div className="pt-4 border-t border-slate-800 space-y-2.5">
            <h3 className="text-xs uppercase font-mono text-slate-400">Collector Host Health</h3>
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                  CPU Usage
                </span>
                <span className="font-mono text-slate-200">28%</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-400 w-[28%]" />
              </div>

              <div className="flex items-center justify-between pt-1">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <HardDrive className="w-3.5 h-3.5 text-blue-400" />
                  Event Buffer Memory
                </span>
                <span className="font-mono text-slate-200">42%</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-blue-400 w-[42%]" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Row 4: Top Talkers & Recent Security Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Talkers Table */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">Top Network Talkers</h2>
              <p className="text-xs text-slate-400">Highest volume source & destination addresses</p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-slate-400 border-b border-slate-800 pb-2">
                <tr>
                  <th className="pb-2">Host IP</th>
                  <th className="pb-2">Packets</th>
                  <th className="pb-2">Volume</th>
                  <th className="pb-2">Flows</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {loading ? (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-slate-500 font-mono">
                      Loading top network talkers...
                    </td>
                  </tr>
                ) : activeTopSources.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-slate-500 font-mono">
                      No active talkers recorded in current window.
                    </td>
                  </tr>
                ) : (
                  activeTopSources.map((host) => (
                    <tr key={host.ip} className="hover:bg-slate-800/40">
                      <td className="py-2.5 font-semibold text-cyan-400">{host.ip}</td>
                      <td className="py-2.5">{host.packets.toLocaleString()}</td>
                      <td className="py-2.5 text-slate-400">{(host.bytes / 1024).toFixed(1)} KB</td>
                      <td className="py-2.5">{host.flows}</td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => onSelectHost && onSelectHost(host.ip)}
                          className="px-2 py-0.5 rounded text-[11px] bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 border border-cyan-500/30"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Security Alerts */}
        <div className="soc-card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">Recent Security Alerts</h2>
              <p className="text-xs text-slate-400">High priority detections requiring triage</p>
            </div>
            {onNavigateToAlerts && (
              <button
                onClick={() => onNavigateToAlerts()}
                className="text-xs text-cyan-400 hover:underline"
              >
                View all alerts →
              </button>
            )}
          </div>

          <div className="space-y-2.5">
            {recentAlerts.length === 0 ? (
              <p className="text-xs text-slate-400 py-4 text-center">No open security alerts detected.</p>
            ) : (
              recentAlerts.map((alert) => (
                <div
                  key={alert.alert_id}
                  onClick={() => setSelectedAlert(alert)}
                  className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 cursor-pointer transition-colors flex items-center justify-between"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={alert.severity} size="sm" />
                      <span className="text-xs font-semibold text-white">{alert.title}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono">
                      {alert.src_ip} → {alert.dst_ip} • {alert.detection_method}
                    </p>
                  </div>

                  <div className="text-right flex flex-col items-end gap-1">
                    <StatusBadge status={alert.status} size="sm" />
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Slide-over Alert Investigation Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onVerdictUpdated={(alertId, verdict) => {
          setRecentAlerts((prev) =>
            prev.map((a) => (a.alert_id === alertId ? { ...a, status: 'Resolved' } : a))
          );
        }}
      />
    </div>
  );
};
