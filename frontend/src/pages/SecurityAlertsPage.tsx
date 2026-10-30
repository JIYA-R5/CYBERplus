import React, { useState, useEffect } from 'react';
import {
  Bell,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  ArrowUpDown,
  UserCheck,
  Eye,
  RefreshCw,
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityAlert, Severity, AlertStatus } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { AlertDetailDrawer } from '../components/alerts/AlertDetailDrawer';

export const SecurityAlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [totalAlerts, setTotalAlerts] = useState<number>(0);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(0);
  const pageSize = 12;

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({
        limit: 100,
        severity: severityFilter,
        status: statusFilter,
        search: searchQuery,
      });
      setAlerts(res.alerts || []);
      setTotalAlerts(res.total || res.alerts?.length || 0);
    } catch (err) {
      console.error('Failed to load alerts', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [severityFilter, statusFilter, searchQuery]);

  const paginated = alerts.slice(page * pageSize, (page + 1) * pageSize);
  const totalPages = Math.ceil(alerts.length / pageSize) || 1;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
        <div>
          <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            <Bell className="w-5 h-5 text-cyan-400" />
            Security Alerts & Incident Triage
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Explainable intrusion alerts with verified ground-truth audit tracking and automated safe response.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadAlerts}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:text-white"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search alerts by title, source IP, or destination IP..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            className="w-full pl-9 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(0);
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
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(0);
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
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                    Loading security alerts...
                  </td>
                </tr>
              ) : paginated.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                    No security alerts found matching selected filters.
                  </td>
                </tr>
              ) : (
                paginated.map((alert) => (
                  <tr
                    key={alert.alert_id}
                    onClick={() => setSelectedAlert(alert)}
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
                          setSelectedAlert(alert);
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
            Showing {paginated.length} of {alerts.length} alerts
          </span>

          <div className="flex items-center gap-2">
            <button
              disabled={page === 0}
              onClick={() => setPage(page - 1)}
              className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:text-white"
            >
              Previous
            </button>
            <button
              disabled={page >= totalPages - 1}
              onClick={() => setPage(page + 1)}
              className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:text-white"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Slide-over Investigation Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onVerdictUpdated={(alertId, verdict) => {
          setAlerts((prev) =>
            prev.map((a) => (a.alert_id === alertId ? { ...a, status: 'Resolved' } : a))
          );
        }}
      />
    </div>
  );
};
