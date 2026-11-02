import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Settings,
  RefreshCw,
  Search,
  Filter,
  Plus,
  Trash2,
  Terminal,
  Brain,
  Info,
  ChevronRight,
  ExternalLink,
  Sliders,
  Radio,
  ArrowUpDown
} from 'lucide-react';
import { api, getAdminKey, setAdminKey } from '../services/api';
import {
  IPSMetrics,
  IPSSettings,
  IPSActionRecord,
  IPSAllowlistEntry,
  IPSPreventionMode,
} from '../types';

export const IntrusionPreventionPage: React.FC = () => {
  // State
  const [metrics, setMetrics] = useState<IPSMetrics | null>(null);
  const [settings, setSettings] = useState<IPSSettings | null>(null);
  const [isElevated, setIsElevated] = useState<boolean>(false);
  const [actions, setActions] = useState<IPSActionRecord[]>([]);
  const [totalActions, setTotalActions] = useState<number>(0);
  const [allowlist, setAllowlist] = useState<IPSAllowlistEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'activity' | 'allowlist' | 'settings'>('activity');

  // Filters & Pagination
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(15);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  // Modals / Drawers
  const [selectedAction, setSelectedAction] = useState<IPSActionRecord | null>(null);
  const [actionExplanation, setActionExplanation] = useState<any | null>(null);
  const [explainingLoading, setExplainingLoading] = useState<boolean>(false);
  const [showModeModal, setShowModeModal] = useState<boolean>(false);
  const [pendingMode, setPendingMode] = useState<IPSPreventionMode | null>(null);
  const [adminAuthKey, setAdminAuthKey] = useState<string>(getAdminKey());

  // Form states for allowlist and settings
  const [newAllowlistIp, setNewAllowlistIp] = useState<string>('');
  const [newAllowlistDesc, setNewAllowlistDesc] = useState<string>('');
  const [settingsForm, setSettingsForm] = useState<Partial<IPSSettings>>({});
  const [saveSuccessMsg, setSaveSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Initial load & periodic poll
  useEffect(() => {
    fetchIPSData();
    const interval = setInterval(fetchIPSData, 5000);
    return () => clearInterval(interval);
  }, [page, statusFilter, searchQuery]);

  const fetchIPSData = async () => {
    try {
      const [statusRes, actionsRes, allowlistRes] = await Promise.all([
        api.getIPSStatus(),
        api.getIPSActions({ page, page_size: pageSize, status: statusFilter, search: searchQuery }),
        api.getIPSAllowlist(),
      ]);

      setMetrics(statusRes.metrics);
      setSettings(statusRes.settings);
      setSettingsForm(statusRes.settings);
      setIsElevated(statusRes.is_elevated);
      setActions(actionsRes.items || []);
      setTotalActions(actionsRes.total || 0);
      setAllowlist(allowlistRes.allowlist || []);
    } catch (err: any) {
      console.error('Error fetching IPS data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchIPSData();
  };

  const handleModeSwitchRequest = (mode: IPSPreventionMode) => {
    if (mode === settings?.prevention_mode) return;
    if (mode === 'AUTOMATIC') {
      setPendingMode('AUTOMATIC');
      setShowModeModal(true);
    } else {
      executeModeSwitch(mode);
    }
  };

  const executeModeSwitch = async (mode: IPSPreventionMode) => {
    setErrorMsg(null);
    try {
      if (adminAuthKey) {
        setAdminKey(adminAuthKey);
      }
      await api.setIPSMode(mode, 'SOC Administrator', adminAuthKey || undefined);
      setShowModeModal(false);
      setPendingMode(null);
      setSaveSuccessMsg(`IPS operating mode successfully changed to ${mode}.`);
      setTimeout(() => setSaveSuccessMsg(null), 4000);
      fetchIPSData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to update IPS prevention mode');
    }
  };

  const handleUnblock = async (target: string) => {
    if (!window.confirm(`Are you sure you want to unblock host ${target} from Windows Defender Firewall?`)) return;
    try {
      await api.unblockIPS(target);
      setSaveSuccessMsg(`Host ${target} unblocked successfully and verified in firewall.`);
      setTimeout(() => setSaveSuccessMsg(null), 4000);
      fetchIPSData();
    } catch (err: any) {
      setErrorMsg(err.message || `Failed to unblock ${target}`);
      setTimeout(() => setErrorMsg(null), 5000);
    }
  };

  const handleViewActionDetails = async (action: IPSActionRecord) => {
    setSelectedAction(action);
    setActionExplanation(null);
    setExplainingLoading(true);
    try {
      const res = await api.getIPSActionExplanation(action.action_id);
      setActionExplanation(res.explanation);
    } catch (err) {
      console.error('Failed to get explanation:', err);
    } finally {
      setExplainingLoading(false);
    }
  };

  const handleAddAllowlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAllowlistIp.trim()) return;
    try {
      await api.addIPSAllowlist(newAllowlistIp.trim(), newAllowlistDesc.trim());
      setNewAllowlistIp('');
      setNewAllowlistDesc('');
      setSaveSuccessMsg('Protected entry added to allowlist.');
      setTimeout(() => setSaveSuccessMsg(null), 3000);
      fetchIPSData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to add allowlist entry');
      setTimeout(() => setErrorMsg(null), 4000);
    }
  };

  const handleDeleteAllowlist = async (entryId: string) => {
    try {
      await api.deleteIPSAllowlist(entryId);
      fetchIPSData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to delete allowlist entry');
    }
  };

  const handleToggleAllowlist = async (entryId: string, currentEnabled: number) => {
    try {
      await api.toggleIPSAllowlist(entryId, currentEnabled === 0);
      fetchIPSData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to toggle allowlist entry');
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.updateIPSSettings(settingsForm);
      setSaveSuccessMsg('IPS configuration parameters successfully saved.');
      setTimeout(() => setSaveSuccessMsg(null), 3000);
      fetchIPSData();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to save settings');
    }
  };

  const formatExpiry = (expiresAt?: string) => {
    if (!expiresAt) return 'Permanent / N/A';
    try {
      const expDate = new Date(expiresAt);
      const now = new Date();
      const diffMs = expDate.getTime() - now.getTime();
      if (diffMs <= 0) return 'Expired';
      const mins = Math.floor(diffMs / 60000);
      const secs = Math.floor((diffMs % 60000) / 1000);
      if (mins > 60) {
        const hrs = Math.floor(mins / 60);
        return `${hrs}h ${mins % 60}m remaining`;
      }
      return `${mins}m ${secs}s remaining`;
    } catch {
      return expiresAt;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'VERIFIED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            Verified Blocked
          </span>
        );
      case 'MONITORED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 border border-amber-500/30 text-amber-400">
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            Monitored Only
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
            Action Failed
          </span>
        );
      case 'UNBLOCKED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Unlock className="w-3.5 h-3.5 text-cyan-400" />
            Unblocked
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
            Allowlist Protected
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-800 border border-slate-700 text-slate-400">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner Alert for Administrator Privilege */}
      {!isElevated && (
        <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-300">
            <span className="font-semibold text-amber-300">Windows Defender Firewall Elevation Notice: </span>
            The SentinelAI backend process is currently running without local Administrator privileges. In AUTOMATIC mode, Windows Defender Firewall rule modifications require elevation. Run PowerShell or your terminal as Administrator for real live host firewall rule creation.
          </div>
        </div>
      )}

      {/* Notifications */}
      {saveSuccessMsg && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium flex items-center justify-between">
          <span>{saveSuccessMsg}</span>
          <button onClick={() => setSaveSuccessMsg(null)} className="text-emerald-300 hover:text-white">✕</button>
        </div>
      )}
      {errorMsg && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-medium flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-rose-300 hover:text-white">✕</button>
        </div>
      )}

      {/* Header and Mode Control */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <ShieldAlert className="w-7 h-7" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-white tracking-tight">Intrusion Prevention System (IPS)</h1>
              <span className={`text-[11px] font-mono uppercase px-2 py-0.5 rounded-full font-semibold border ${
                settings?.prevention_mode === 'AUTOMATIC'
                  ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'
                  : settings?.prevention_mode === 'MONITOR'
                  ? 'bg-amber-500/20 border-amber-500/40 text-amber-400'
                  : 'bg-slate-800 border-slate-700 text-slate-400'
              }`}>
                {settings?.prevention_mode || 'MONITOR'} MODE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Automated high-confidence threat containment via native Windows Defender Firewall rules
            </p>
          </div>
        </div>

        {/* Operating Mode Buttons */}
        <div className="flex items-center gap-2 bg-slate-950/70 p-1.5 rounded-xl border border-slate-800">
          <button
            onClick={() => handleModeSwitchRequest('MONITOR')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              settings?.prevention_mode === 'MONITOR'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Monitor Only
          </button>
          <button
            onClick={() => handleModeSwitchRequest('AUTOMATIC')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
              settings?.prevention_mode === 'AUTOMATIC'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Lock className="w-3 h-3 text-emerald-400" />
            Automatic Prevention
          </button>
          <button
            onClick={() => handleModeSwitchRequest('DISABLED')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              settings?.prevention_mode === 'DISABLED'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Disabled
          </button>
          <div className="w-[1px] h-5 bg-slate-800 mx-1" />
          <button
            onClick={handleManualRefresh}
            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800/80 transition-colors"
            title="Refresh IPS telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Live Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {/* Metric 1: Status */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">Status</div>
          <div className="text-base font-bold text-white mt-1 flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${
              settings?.prevention_mode === 'AUTOMATIC' ? 'bg-emerald-400 animate-pulse' : settings?.prevention_mode === 'MONITOR' ? 'bg-amber-400' : 'bg-slate-500'
            }`} />
            {metrics?.ips_status || 'Monitoring'}
          </div>
          <div className="text-[10px] text-slate-500 mt-1 truncate">State: {settings?.prevention_mode}</div>
        </div>

        {/* Metric 2: Total Blocked */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">Total Blocked</div>
          <div className="text-xl font-bold text-white mt-1 font-mono">
            {metrics?.total_threats_blocked ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Confirmed threats</div>
        </div>

        {/* Metric 3: Active Blocks */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">Active Blocks</div>
          <div className="text-xl font-bold text-emerald-400 mt-1 font-mono">
            {metrics?.currently_active_blocks ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Live in OS Firewall</div>
        </div>

        {/* Metric 4: Pending */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">Pending</div>
          <div className="text-xl font-bold text-amber-400 mt-1 font-mono">
            {metrics?.pending_decisions ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Under policy review</div>
        </div>

        {/* Metric 5: Verified Actions */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">Verified Rules</div>
          <div className="text-xl font-bold text-cyan-400 mt-1 font-mono">
            {metrics?.successful_firewall_actions ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Confirmed by OS</div>
        </div>

        {/* Metric 6: Failed Actions */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">Failed Actions</div>
          <div className="text-xl font-bold text-rose-400 mt-1 font-mono">
            {metrics?.failed_firewall_actions ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Elevation or error</div>
        </div>

        {/* Metric 7: Expiring Soon */}
        <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="text-[11px] font-medium text-slate-400 uppercase tracking-wider font-mono">Expiring Soon</div>
          <div className="text-xl font-bold text-indigo-400 mt-1 font-mono">
            {metrics?.expiring_blocks ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">&lt; 5 min remaining</div>
        </div>
      </div>

      {/* Tabs navigation: Activity / Allowlist / Settings */}
      <div className="flex border-b border-slate-800 text-sm font-medium">
        <button
          onClick={() => setActiveTab('activity')}
          className={`pb-3 px-4 flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'activity'
              ? 'border-cyan-500 text-cyan-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-4 h-4" />
          Prevention Activity Log ({totalActions})
        </button>
        <button
          onClick={() => setActiveTab('allowlist')}
          className={`pb-3 px-4 flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'allowlist'
              ? 'border-cyan-500 text-cyan-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Protected Allowlist ({allowlist.length})
        </button>
        <button
          onClick={() => setActiveTab('settings')}
          className={`pb-3 px-4 flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'settings'
              ? 'border-cyan-500 text-cyan-400 font-semibold'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Sliders className="w-4 h-4" />
          IPS Policy & Duration Settings
        </button>
      </div>

      {/* TAB 1: Prevention Activity Table */}
      {activeTab === 'activity' && (
        <div className="space-y-4">
          {/* Table Filters */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 flex items-center gap-1">
                <Filter className="w-3.5 h-3.5" /> Filter Status:
              </span>
              {['All', 'VERIFIED', 'MONITORED', 'FAILED', 'UNBLOCKED', 'REJECTED'].map((st) => (
                <button
                  key={st}
                  onClick={() => { setStatusFilter(st); setPage(1); }}
                  className={`text-xs px-2.5 py-1 rounded-md transition-colors ${
                    statusFilter === st
                      ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40'
                      : 'bg-slate-900/50 text-slate-400 hover:text-white border border-slate-800'
                  }`}
                >
                  {st === 'All' ? 'All Activity' : st}
                </button>
              ))}
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search IP, category..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                className="w-full pl-9 pr-3 py-1.5 bg-slate-900/60 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Activity Table */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Source IP & Location</th>
                    <th className="py-3 px-4">Threat Category</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Firewall Status</th>
                    <th className="py-3 px-4">Expiry / Remaining</th>
                    <th className="py-3 px-4 text-right">Controls</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {actions.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500">
                        No IPS prevention events recorded for the selected filter.
                      </td>
                    </tr>
                  ) : (
                    actions.map((act) => {
                      const isActiveBlock = act.action_status === 'VERIFIED' && !act.unblocked_at;
                      return (
                        <tr key={act.action_id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 px-4">
                            <div className="font-semibold text-white flex items-center gap-2">
                              {act.source_ip}
                              {act.geoip_country && act.geoip_country !== 'Unknown' && (
                                <span className="text-[10px] font-sans px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                                  {act.geoip_country}
                                </span>
                              )}
                            </div>
                            <div className="text-[10px] text-slate-500 font-sans mt-0.5 truncate max-w-xs">
                              {act.detection_reason}
                            </div>
                          </td>
                          <td className="py-3 px-4 text-slate-300 font-sans">
                            {act.threat_category}
                          </td>
                          <td className="py-3 px-4">
                            <span className="font-semibold text-cyan-400">
                              {(act.confidence * 100).toFixed(0)}%
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              act.action_type === 'BLOCK'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : 'bg-slate-800 text-slate-400 border border-slate-700'
                            }`}>
                              {act.action_type}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            {getStatusBadge(act.action_status)}
                          </td>
                          <td className="py-3 px-4 text-slate-400 font-sans text-[11px]">
                            {act.action_status === 'UNBLOCKED' ? (
                              <span className="text-cyan-400">Unblocked</span>
                            ) : (
                              formatExpiry(act.expires_at)
                            )}
                          </td>
                          <td className="py-3 px-4 text-right space-x-2 font-sans">
                            {isActiveBlock && (
                              <button
                                onClick={() => handleUnblock(act.source_ip)}
                                className="px-2.5 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 text-xs font-medium transition-colors"
                                title="Unblock from Windows Firewall"
                              >
                                Unblock
                              </button>
                            )}
                            <button
                              onClick={() => handleViewActionDetails(act)}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
                            >
                              Details
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalActions > pageSize && (
              <div className="flex items-center justify-between px-4 py-3 bg-slate-950/60 border-t border-slate-800 text-xs text-slate-400">
                <div>
                  Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, totalActions)} of {totalActions} events
                </div>
                <div className="flex items-center gap-2">
                  <button
                    disabled={page <= 1}
                    onClick={() => setPage(page - 1)}
                    className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <span className="font-mono">Page {page} of {Math.ceil(totalActions / pageSize)}</span>
                  <button
                    disabled={page >= Math.ceil(totalActions / pageSize)}
                    onClick={() => setPage(page + 1)}
                    className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Protected Allowlist */}
      {activeTab === 'allowlist' && (
        <div className="space-y-6">
          {/* Add Allowlist Card */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80">
            <h3 className="text-sm font-bold text-white mb-2 flex items-center gap-2">
              <Plus className="w-4 h-4 text-cyan-400" />
              Add Protected Host or Network CIDR
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Protected addresses are strictly shielded by the IPS safety validator and will never be blocked by automatic or manual containment rules.
            </p>
            <form onSubmit={handleAddAllowlist} className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input
                type="text"
                placeholder="IP Address or CIDR (e.g. 192.168.1.50 or 10.0.0.0/24)"
                value={newAllowlistIp}
                onChange={(e) => setNewAllowlistIp(e.target.value)}
                className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                required
              />
              <input
                type="text"
                placeholder="Description / Asset Owner"
                value={newAllowlistDesc}
                onChange={(e) => setNewAllowlistDesc(e.target.value)}
                className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-2"
              >
                <ShieldCheck className="w-4 h-4" />
                Add to Protected Allowlist
              </button>
            </form>
          </div>

          {/* Allowlist Table */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Protected IP / Subnet</th>
                  <th className="py-3 px-4">Description</th>
                  <th className="py-3 px-4">Added Timestamp</th>
                  <th className="py-3 px-4">Protection Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {allowlist.map((entry) => (
                  <tr key={entry.entry_id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-bold text-cyan-400">
                      {entry.ip_or_cidr}
                    </td>
                    <td className="py-3 px-4 text-slate-300 font-sans">
                      {entry.description}
                    </td>
                    <td className="py-3 px-4 text-slate-500 font-sans text-[11px]">
                      {entry.created_at}
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <button
                        onClick={() => handleToggleAllowlist(entry.entry_id, entry.enabled)}
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-colors ${
                          entry.enabled
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            : 'bg-slate-800 text-slate-500 border border-slate-700'
                        }`}
                      >
                        {entry.enabled ? 'Protected (Active)' : 'Disabled'}
                      </button>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleDeleteAllowlist(entry.entry_id)}
                        className="p-1 text-slate-400 hover:text-rose-400 transition-colors"
                        title="Delete allowlist rule"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: IPS Policy & Duration Settings */}
      {activeTab === 'settings' && (
        <form onSubmit={handleSaveSettings} className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800/80 space-y-6 max-w-3xl">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Sliders className="w-5 h-5 text-cyan-400" />
              Automated Prevention Thresholds & Safety Policies
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Configure deterministic decision criteria, containment durations, and anti-lockout safety rules.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
            {/* Confidence Threshold */}
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-200 flex justify-between">
                <span>Confidence Threshold</span>
                <span className="font-mono text-cyan-400">
                  {((settingsForm.confidence_threshold ?? 0.85) * 100).toFixed(0)}%
                </span>
              </label>
              <input
                type="range"
                min="0.50"
                max="0.99"
                step="0.01"
                value={settingsForm.confidence_threshold ?? 0.85}
                onChange={(e) => setSettingsForm({ ...settingsForm, confidence_threshold: parseFloat(e.target.value) })}
                className="w-full accent-cyan-500"
              />
              <p className="text-[11px] text-slate-500">
                Threat events must meet or exceed this confidence to be eligible for automatic blocking.
              </p>
            </div>

            {/* Default Duration */}
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-200">Default Temporary Block Duration (Minutes)</label>
              <input
                type="number"
                min="1"
                max="1440"
                value={settingsForm.default_block_duration ?? 15}
                onChange={(e) => setSettingsForm({ ...settingsForm, default_block_duration: parseInt(e.target.value) || 15 })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
              />
              <p className="text-[11px] text-slate-500">Initial containment duration applied to confirmed threats (Default: 15m).</p>
            </div>

            {/* Maximum Duration */}
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-200">Maximum Block Duration (Minutes)</label>
              <input
                type="number"
                min="60"
                max="10080"
                value={settingsForm.maximum_block_duration ?? 1440}
                onChange={(e) => setSettingsForm({ ...settingsForm, maximum_block_duration: parseInt(e.target.value) || 1440 })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
              />
              <p className="text-[11px] text-slate-500">Upper cap for recurrent malicious activity (Default: 1440m = 24h).</p>
            </div>

            {/* Max Active Blocks */}
            <div className="space-y-1.5">
              <label className="font-semibold text-slate-200">Maximum Active Firewall Rules Cap</label>
              <input
                type="number"
                min="5"
                max="500"
                value={settingsForm.maximum_active_blocks ?? 50}
                onChange={(e) => setSettingsForm({ ...settingsForm, maximum_active_blocks: parseInt(e.target.value) || 50 })}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:outline-none focus:border-cyan-500"
              />
              <p className="text-[11px] text-slate-500">Limits concurrent firewall rules to avoid OS rule table congestion (Default: 50).</p>
            </div>

            {/* Administrator Authorization Key */}
            <div className="space-y-1.5 md:col-span-2 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
              <label className="font-semibold text-slate-200 flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-amber-400">
                  <Lock className="w-3.5 h-3.5" />
                  Administrator API Authorization Key (X-Sentinel-Admin-Key)
                </span>
                <span className="text-[10px] text-slate-500 font-mono">Matches SENTINEL_ADMIN_KEY in .env</span>
              </label>
              <input
                type="password"
                placeholder="Enter admin key (default: wearewinning)"
                value={adminAuthKey}
                onChange={(e) => {
                  setAdminAuthKey(e.target.value);
                  setAdminKey(e.target.value);
                }}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-white font-mono text-xs focus:outline-none focus:border-amber-500"
              />
              <p className="text-[11px] text-slate-500">
                Used to authorize manual unblock actions, operating mode toggles, and allowlist updates.
              </p>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 space-y-3 text-xs">
            {/* Automatic Unblocking Toggle */}
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(settingsForm.automatic_unblocking_enabled ?? 1)}
                onChange={(e) => setSettingsForm({ ...settingsForm, automatic_unblocking_enabled: e.target.checked ? 1 : 0 })}
                className="w-4 h-4 rounded accent-cyan-500"
              />
              <div>
                <span className="font-semibold text-slate-200">Enable Background Automatic Unblocking Watchdog</span>
                <p className="text-[11px] text-slate-500">Continuously scans every 30 seconds to safely remove expired SentinelAI firewall rules.</p>
              </div>
            </label>

            {/* Private Networks Toggle */}
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(settingsForm.allow_private_network_blocks ?? 0)}
                onChange={(e) => setSettingsForm({ ...settingsForm, allow_private_network_blocks: e.target.checked ? 1 : 0 })}
                className="w-4 h-4 rounded accent-rose-500"
              />
              <div>
                <span className="font-semibold text-rose-300">Allow Containment of RFC 1918 Private Networks (Advanced)</span>
                <p className="text-[11px] text-slate-500">Warning: Keeping this disabled protects local workstations and internal routers from accidental isolation.</p>
              </div>
            </label>
          </div>

          <button
            type="submit"
            className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs transition-colors flex items-center gap-2"
          >
            <CheckCircle2 className="w-4 h-4" />
            Save IPS Policy Parameters
          </button>
        </form>
      )}

      {/* Modal: Confirmation for Enabling AUTOMATIC Mode */}
      {showModeModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-rose-400">
              <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/30">
                <AlertTriangle className="w-6 h-6 text-rose-400" />
              </div>
              <div>
                <h3 className="font-bold text-base text-white">Enable Automatic IPS Prevention</h3>
                <p className="text-xs text-rose-300">Privileged Operating System Modification</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Enabling <strong className="text-emerald-400">AUTOMATIC MODE</strong> permits SentinelAI to create real inbound blocking rules in Windows Defender Firewall for validated high-confidence threat events.
            </p>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-400 space-y-1 font-mono">
              <div>✓ Loopback (127.0.0.1) & Host IP protected</div>
              <div>✓ Private subnets (RFC 1918) protected by default</div>
              <div>✓ Temporary rules automatically removed on expiry</div>
              <div>✓ OS state verified before action confirmed</div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                <span>Admin Authorization Key</span>
                <span className="text-[10px] text-slate-500 font-mono">Optional if saved in Settings</span>
              </label>
              <input
                type="password"
                placeholder="Enter admin key (default: wearewinning)"
                value={adminAuthKey}
                onChange={(e) => {
                  setAdminAuthKey(e.target.value);
                  setAdminKey(e.target.value);
                }}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowModeModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => executeModeSwitch('AUTOMATIC')}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-white transition-colors flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                Confirm & Enable Live Prevention
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Drawer: Action Details & Gemini Copilot Explanation */}
      {selectedAction && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-cyan-400" />
                <h2 className="text-base font-bold text-white">Prevention Decision Dossier</h2>
              </div>
              <button
                onClick={() => setSelectedAction(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Action Summary Card */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-cyan-400">{selectedAction.action_id}</span>
                {getStatusBadge(selectedAction.action_status)}
              </div>
              <div className="text-sm font-bold text-white flex items-center gap-2">
                Target IP: <span className="font-mono text-emerald-400">{selectedAction.source_ip}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-300">
                <div>Category: <span className="text-white">{selectedAction.threat_category}</span></div>
                <div>Confidence: <span className="text-cyan-400">{(selectedAction.confidence * 100).toFixed(0)}%</span></div>
                <div>Created: <span className="text-slate-400">{selectedAction.created_at}</span></div>
                <div>Expires: <span className="text-slate-400">{formatExpiry(selectedAction.expires_at)}</span></div>
              </div>
              {selectedAction.firewall_rule_id && (
                <div className="text-xs font-mono text-slate-400 break-all bg-slate-900 p-2 rounded border border-slate-800">
                  Firewall Rule: <span className="text-emerald-300">{selectedAction.firewall_rule_id}</span>
                </div>
              )}
              {selectedAction.error_message && (
                <div className="text-xs text-rose-300 bg-rose-500/10 p-2 rounded border border-rose-500/20">
                  Note/Error: {selectedAction.error_message}
                </div>
              )}
            </div>

            {/* Gemini Copilot Reasoning Layer */}
            <div className="p-4 rounded-xl bg-gradient-to-br from-indigo-950/40 to-slate-900 border border-indigo-500/30 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-indigo-400 font-bold text-xs uppercase tracking-wider">
                  <Brain className="w-4 h-4" />
                  Gemini Security Copilot Analysis
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  Analytical Advisor Layer
                </span>
              </div>

              {explainingLoading ? (
                <div className="py-6 flex items-center justify-center gap-2 text-xs text-slate-400">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                  Generating AI analytical explanation...
                </div>
              ) : actionExplanation ? (
                <div className="space-y-3 text-xs text-slate-300">
                  {actionExplanation.ai_summary && (
                    <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-slate-200 leading-relaxed font-sans">
                      {actionExplanation.ai_summary}
                    </div>
                  )}

                  <div>
                    <h4 className="font-semibold text-slate-200 mb-1">Potential False-Positive Factors:</h4>
                    <ul className="list-disc pl-4 space-y-1 text-slate-400 font-sans text-[11px]">
                      {actionExplanation.false_positive_factors?.map((f: string, i: number) => (
                        <li key={i}>{f}</li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-semibold text-slate-200 mb-1">Recommended Analyst Triage:</h4>
                    <ul className="list-disc pl-4 space-y-1 text-slate-400 font-sans text-[11px]">
                      {actionExplanation.triage_recommendations?.map((r: string, i: number) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800 text-[10px] text-slate-500 font-sans">
                    Guardrail Notice: {actionExplanation.gemini_disclaimer}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-400">Unable to load AI analytical explanation.</p>
              )}
            </div>

            {/* Quick Actions in Drawer */}
            <div className="flex items-center justify-between pt-2">
              {selectedAction.action_status === 'VERIFIED' && !selectedAction.unblocked_at && (
                <button
                  onClick={() => {
                    handleUnblock(selectedAction.source_ip);
                    setSelectedAction(null);
                  }}
                  className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs transition-colors flex items-center gap-2"
                >
                  <Unlock className="w-4 h-4" />
                  Unblock from Firewall Now
                </button>
              )}
              <button
                onClick={() => setSelectedAction(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold ml-auto"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
