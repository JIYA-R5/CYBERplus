import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Eye,
  Sliders,
  AlertTriangle,
  Info,
  CheckCircle2,
  Terminal,
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityAlert } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

export const ThreatDetectionPage: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Filters
  const [filterMethod, setFilterMethod] = useState<string>('All');
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const fetchDetections = async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({ limit: 100 });
      setAlerts(res.alerts || []);
    } catch (e) {
      console.error('Failed to load detections', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetections();
  }, []);

  const filtered = alerts.filter((a) => {
    if (filterMethod !== 'All' && a.detection_method !== filterMethod) return false;
    if (filterSeverity !== 'All' && a.severity !== filterSeverity) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchTitle = a.title.toLowerCase().includes(q);
      const matchHost = a.src_ip.toLowerCase().includes(q) || a.dst_ip.toLowerCase().includes(q);
      if (!matchTitle && !matchHost) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Page Header with Detection Methodology Summary */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
        <div>
          <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            Hybrid Threat Detection Engine
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Combines deterministic rule heuristics (port scans, SYN flooding, credential bursts) with unsupervised
            Isolation Forest flow anomaly scoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono">
            {filtered.length} Active Detections
          </div>
        </div>
      </div>

      {/* Detection Engine Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
        <div className="soc-card p-4 space-y-1">
          <span className="text-slate-400 uppercase text-[10px]">Methodology 1</span>
          <p className="font-semibold text-white">Rule Heuristics & Signatures</p>
          <p className="text-slate-500 text-[11px]">Deterministic pattern matching for known TTPs</p>
        </div>
        <div className="soc-card p-4 space-y-1">
          <span className="text-slate-400 uppercase text-[10px]">Methodology 2</span>
          <p className="font-semibold text-white">Flow Isolation Forest</p>
          <p className="text-slate-500 text-[11px]">Statistical distance from benign baselines</p>
        </div>
        <div className="soc-card p-4 space-y-1">
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
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Method:</span>
            <select
              value={filterMethod}
              onChange={(e) => setFilterMethod(e.target.value)}
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
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Detections List Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading ? (
          <div className="col-span-2 p-12 text-center text-slate-400 font-mono text-xs">
            Loading detections from SentinelAI engine...
          </div>
        ) : filtered.length === 0 ? (
          <div className="col-span-2 p-12 text-center text-slate-500 font-mono text-xs soc-card">
            No detections match the current filter criteria.
          </div>
        ) : (
          filtered.map((item) => (
            <div
              key={item.alert_id}
              onClick={() => setSelectedAlert(item)}
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

      {/* Investigation Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onVerdictUpdated={(alertId) => {
          setAlerts((prev) =>
            prev.map((a) => (a.alert_id === alertId ? { ...a, status: 'Resolved' } : a))
          );
        }}
      />
    </div>
  );
};
