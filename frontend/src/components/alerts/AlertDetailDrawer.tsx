import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Clock,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  Play,
  Terminal,
  Activity,
  UserCheck,
  Check,
} from 'lucide-react';
import { SecurityAlert, ResponseAction } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { api } from '../../services/api';

interface AlertDetailDrawerProps {
  alert: SecurityAlert | null;
  onClose: () => void;
  onVerdictUpdated: (alertId: string, newVerdict: string) => void;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert,
  onClose,
  onVerdictUpdated,
}) => {
  const [activeTab, setActiveTab] = useState<'details' | 'evidence' | 'response'>('details');
  const [updatingVerdict, setUpdatingVerdict] = useState<boolean>(false);
  const [verdictSuccess, setVerdictSuccess] = useState<string | null>(null);
  const [reviewNotes, setReviewNotes] = useState<string>('');

  // Response execution states
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([]);
  const [loadingActions, setLoadingActions] = useState<boolean>(false);
  const [selectedAction, setSelectedAction] = useState<ResponseAction | null>(null);
  const [isSimulated, setIsSimulated] = useState<boolean>(true);
  const [executingAction, setExecutingAction] = useState<boolean>(false);
  const [actionResult, setActionResult] = useState<string | null>(null);

  if (!alert) return null;

  const handleUpdateVerdict = async (verdict: string) => {
    try {
      setUpdatingVerdict(true);
      setVerdictSuccess(null);
      await api.patchAlertVerdict(alert.alert_id, verdict, reviewNotes);
      setVerdictSuccess(`Alert marked as ${verdict}`);
      onVerdictUpdated(alert.alert_id, verdict);
    } catch (err: any) {
      window.alert(err.message || 'Failed to update verdict');
    } finally {
      setUpdatingVerdict(false);
    }
  };

  const loadResponseActions = async () => {
    setActiveTab('response');
    if (responseActions.length > 0) return;
    try {
      setLoadingActions(true);
      const res = await api.getResponseRecommendations(alert.alert_id);
      setResponseActions(res.actions || []);
      if (res.actions?.length > 0) {
        setSelectedAction(res.actions[0]);
      }
    } catch (e) {
      console.error('Failed to load response actions', e);
    } finally {
      setLoadingActions(false);
    }
  };

  const handleExecuteResponse = async () => {
    if (!selectedAction) return;
    try {
      setExecutingAction(true);
      setActionResult(null);
      const res = await api.executeResponse(selectedAction.action_id, isSimulated, reviewNotes);
      setActionResult(
        isSimulated
          ? `[SIMULATION SUCCEEDED]: ${res.result} (No actual firewall changes were made).`
          : `[LIVE ACTION EXECUTED]: ${res.result}`
      );
    } catch (err: any) {
      setActionResult(`Execution failed: ${err.message}`);
    } finally {
      setExecutingAction(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-2xl bg-[#0F172A] border-l border-slate-800 h-full flex flex-col shadow-2xl text-slate-200 overflow-hidden">
        {/* Top Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-900/50">
          <div className="space-y-1.5 pr-4">
            <div className="flex items-center gap-2.5">
              <SeverityBadge severity={alert.severity} size="md" />
              <span className="text-xs px-2.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                {alert.detection_method}
              </span>
              <span className="text-xs text-slate-400 font-mono">ID: {alert.alert_id}</span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight">{alert.title}</h2>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Clock className="w-3.5 h-3.5" />
              <span>Detected: {new Date(alert.timestamp).toLocaleString()}</span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center px-6 border-b border-slate-800 text-sm font-medium bg-slate-900/30">
          <button
            onClick={() => setActiveTab('details')}
            className={`py-3 px-4 border-b-2 transition-colors ${
              activeTab === 'details'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Investigation & Context
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-3 px-4 border-b-2 transition-colors ${
              activeTab === 'evidence'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Telemetry & Evidence
          </button>
          <button
            onClick={loadResponseActions}
            className={`py-3 px-4 border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'response'
                ? 'border-cyan-400 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Play className="w-3.5 h-3.5" />
            <span>Safe Response</span>
          </button>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'details' && (
            <div className="space-y-6">
              {/* Plain-English Explanation */}
              <div className="soc-card p-4 bg-slate-900/60 border-cyan-500/30">
                <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm mb-2">
                  <Terminal className="w-4 h-4" />
                  <span>Explainable Security Assessment</span>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">{alert.explanation}</p>
              </div>

              {/* Communication Endpoints */}
              <div className="soc-card p-4 bg-slate-900/40">
                <h4 className="text-xs uppercase font-mono text-slate-400 mb-3">Host Communication Flow</h4>
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                  <div>
                    <p className="text-xs text-slate-400">Source Host</p>
                    <p className="font-mono font-semibold text-cyan-300 text-sm mt-0.5">{alert.src_ip}</p>
                  </div>
                  <ArrowRight className="w-5 h-5 text-slate-500" />
                  <div>
                    <p className="text-xs text-slate-400">Destination Host</p>
                    <p className="font-mono font-semibold text-cyan-300 text-sm mt-0.5">{alert.dst_ip}</p>
                  </div>
                </div>
              </div>

              {/* Model Confidence vs Anomaly Score (Calibrated Notice) */}
              <div className="grid grid-cols-2 gap-4">
                <div className="soc-card p-4">
                  <p className="text-xs font-mono text-slate-400">Detection Method</p>
                  <p className="text-sm font-semibold text-white mt-1">{alert.detection_method}</p>
                  <p className="text-[11px] text-slate-500 mt-1">
                    {alert.detection_method === 'Rule-based'
                      ? 'Deterministic pattern match rule'
                      : 'Statistical outlier distance metric'}
                  </p>
                </div>

                <div className="soc-card p-4">
                  <p className="text-xs font-mono text-slate-400">Anomaly / Confidence</p>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="text-lg font-bold font-mono text-amber-400">
                      {alert.anomaly_score !== undefined
                        ? (alert.anomaly_score * 100).toFixed(1) + '%'
                        : alert.confidence !== undefined
                        ? (alert.confidence * 100).toFixed(1) + '%'
                        : 'Uncalibrated'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Score reflects outlier distance; not calibrated attack probability.
                  </p>
                </div>
              </div>

              {/* Recommended Investigation Steps */}
              <div className="soc-card p-4">
                <h4 className="text-xs uppercase font-mono text-slate-400 mb-2">Recommended Investigation Steps</h4>
                <div className="space-y-2 text-sm text-slate-300">
                  {alert.suggested_steps && alert.suggested_steps.length > 0 ? (
                    alert.suggested_steps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2.5">
                        <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-400 flex items-center justify-center text-xs shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <span>{step}</span>
                      </div>
                    ))
                  ) : (
                    <div className="flex items-start gap-2.5">
                      <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-400 flex items-center justify-center text-xs shrink-0 mt-0.5">
                        1
                      </span>
                      <span>{alert.recommended_action || 'Inspect flow history for this source host.'}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Analyst Verdict Decision Section */}
              <div className="soc-card p-5 border-slate-700">
                <div className="flex items-center gap-2 mb-3">
                  <UserCheck className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-sm font-semibold text-white">Analyst Verdict & Review Ground Truth</h4>
                </div>

                <p className="text-xs text-slate-400 mb-3">
                  Persist your decision into the audit log. Canonical verdicts improve future supervised evaluations.
                </p>

                {verdictSuccess && (
                  <div className="mb-3 p-2.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
                    <Check className="w-4 h-4" />
                    <span>{verdictSuccess}</span>
                  </div>
                )}

                <div className="space-y-3">
                  <textarea
                    placeholder="Optional analyst investigation notes..."
                    value={reviewNotes}
                    onChange={(e) => setReviewNotes(e.target.value)}
                    rows={2}
                    className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />

                  <div className="grid grid-cols-3 gap-2.5">
                    <button
                      disabled={updatingVerdict}
                      onClick={() => handleUpdateVerdict('Confirmed Suspicious')}
                      className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-red-500/20 text-red-400 border border-red-500/40 hover:bg-red-500/30 text-xs font-semibold transition-colors disabled:opacity-50"
                    >
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>True Positive</span>
                    </button>

                    <button
                      disabled={updatingVerdict}
                      onClick={() => handleUpdateVerdict('Benign')}
                      className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 hover:bg-emerald-500/30 text-xs font-semibold transition-colors disabled:opacity-50"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Benign (False +)</span>
                    </button>

                    <button
                      disabled={updatingVerdict}
                      onClick={() => handleUpdateVerdict('Needs Investigation')}
                      className="flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 hover:bg-yellow-500/30 text-xs font-semibold transition-colors disabled:opacity-50"
                    >
                      <HelpCircle className="w-3.5 h-3.5" />
                      <span>Escalate / Need Info</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="soc-card p-4">
                <h4 className="text-xs uppercase font-mono text-slate-400 mb-3">Telemetry Evidence Metrics</h4>
                {alert.evidence ? (
                  <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                    {Object.entries(alert.evidence).map(([key, val]) => (
                      <div key={key} className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[11px] uppercase">{key.replace(/_/g, ' ')}</span>
                        <span className="text-cyan-300 font-semibold mt-0.5 block truncate">
                          {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-400">No raw evidence dictionary attached to this event.</p>
                )}
              </div>

              {alert.related_events && alert.related_events.length > 0 && (
                <div className="soc-card p-4">
                  <h4 className="text-xs uppercase font-mono text-slate-400 mb-3">
                    Related Network Packets ({alert.related_events.length})
                  </h4>
                  <div className="overflow-x-auto max-h-60">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="pb-2">Time</th>
                          <th className="pb-2">Src Port</th>
                          <th className="pb-2">Dst Port</th>
                          <th className="pb-2">Protocol</th>
                          <th className="pb-2">Size</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300">
                        {alert.related_events.map((evt, i) => (
                          <tr key={i} className="hover:bg-slate-800/40">
                            <td className="py-1.5">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                            <td className="py-1.5 text-cyan-400">{evt.src_port}</td>
                            <td className="py-1.5 text-cyan-400">{evt.dst_port}</td>
                            <td className="py-1.5">{evt.protocol}</td>
                            <td className="py-1.5">{evt.packet_size}B</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'response' && (
            <div className="space-y-5">
              <div className="p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs">
                <div className="font-semibold flex items-center gap-1.5 mb-1">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>Safe Response Mode (Default: Dry-Run / Simulation)</span>
                </div>
                <p>
                  Disruptive mitigation actions require explicit analyst review and confirmation. By default, actions
                  execute in safe simulation mode without changing live production firewall state.
                </p>
              </div>

              {loadingActions ? (
                <div className="p-8 text-center text-slate-400 text-xs font-mono">Loading recommendations...</div>
              ) : responseActions.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-xs">
                  No automated response triggers registered for this alert type.
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="space-y-2.5">
                    <label className="text-xs uppercase font-mono text-slate-400">Available Mitigation Playbooks</label>
                    <div className="grid grid-cols-1 gap-2.5">
                      {responseActions.map((act) => (
                        <div
                          key={act.action_id}
                          onClick={() => setSelectedAction(act)}
                          className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                            selectedAction?.action_id === act.action_id
                              ? 'bg-cyan-500/10 border-cyan-400'
                              : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-sm text-white">{act.title}</span>
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                                act.risk_level === 'Low'
                                  ? 'bg-emerald-500/20 text-emerald-400'
                                  : act.risk_level === 'Medium'
                                  ? 'bg-yellow-500/20 text-yellow-400'
                                  : 'bg-red-500/20 text-red-400'
                              }`}
                            >
                              Risk: {act.risk_level}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 mt-1.5">{act.explanation}</p>
                          <p className="text-[11px] text-cyan-300/80 mt-1 font-mono">Target: {act.target}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Confirmation & Execution Panel */}
                  {selectedAction && (
                    <div className="soc-card p-4 border-slate-700 space-y-4 bg-slate-900/80">
                      <h4 className="text-xs uppercase font-mono text-slate-400">Action Execution Review</h4>

                      <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1.5 text-xs">
                        <div className="flex justify-between">
                          <span className="text-slate-400">Action:</span>
                          <span className="font-semibold text-white">{selectedAction.title}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Expected Effect:</span>
                          <span className="text-slate-300">{selectedAction.expected_effect}</span>
                        </div>
                      </div>

                      {/* Simulation checkbox */}
                      <label className="flex items-center gap-2.5 text-xs text-slate-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={isSimulated}
                          onChange={(e) => setIsSimulated(e.target.checked)}
                          className="w-4 h-4 rounded text-cyan-500 border-slate-700 bg-slate-900 focus:ring-0"
                        />
                        <span>
                          Run in <strong className="text-cyan-400">Simulation / Dry-Run Mode</strong> (Recommended)
                        </span>
                      </label>

                      {actionResult && (
                        <div className="p-3 rounded-lg bg-slate-950 border border-cyan-500/40 text-xs font-mono text-cyan-300 whitespace-pre-wrap">
                          {actionResult}
                        </div>
                      )}

                      <button
                        disabled={executingAction}
                        onClick={handleExecuteResponse}
                        className={`w-full py-2.5 px-4 rounded-lg font-semibold text-xs flex items-center justify-center gap-2 transition-all ${
                          isSimulated
                            ? 'bg-cyan-600 hover:bg-cyan-500 text-white'
                            : 'bg-red-600 hover:bg-red-500 text-white'
                        } disabled:opacity-50`}
                      >
                        <Activity className="w-4 h-4" />
                        <span>
                          {executingAction
                            ? 'Executing...'
                            : isSimulated
                            ? `Dry-Run '${selectedAction.title}'`
                            : `CONFIRM LIVE EXECUTION: '${selectedAction.title}'`}
                        </span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
