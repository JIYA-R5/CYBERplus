import React, { useState, useEffect } from 'react';
import {
  Compass,
  Search,
  Download,
  FileText,
  Clock,
  ArrowRight,
  ShieldAlert,
  Save,
  Check,
  Terminal,
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityAlert, NetworkEvent } from '../types';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const InvestigationPage: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [relatedEvents, setRelatedEvents] = useState<NetworkEvent[]>([]);
  const [investigationNotes, setInvestigationNotes] = useState<string>('');
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        setLoading(true);
        const res = await api.getAlerts({ limit: 50 });
        setAlerts(res.alerts || []);
        if (res.alerts?.length > 0) {
          handleSelectAlert(res.alerts[0]);
        }
      } catch (e) {
        console.error('Failed to load alerts for investigation', e);
      } finally {
        setLoading(false);
      }
    };
    fetchAlerts();
  }, []);

  const handleSelectAlert = async (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setSaveStatus(null);
    try {
      const full = await api.getAlert(alert.alert_id);
      setRelatedEvents(full.related_events || []);
    } catch {
      setRelatedEvents([]);
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedAlert) return;
    try {
      setSaveStatus('Saving notes...');
      await api.patchAlertVerdict(selectedAlert.alert_id, 'Under Review', investigationNotes);
      setSaveStatus('Investigation notes saved successfully!');
      setTimeout(() => setSaveStatus(null), 3000);
    } catch (err: any) {
      setSaveStatus(`Failed to save: ${err.message}`);
    }
  };

  const handleExportReport = (format: 'json' | 'csv') => {
    if (!selectedAlert) return;

    let content = '';
    let filename = `sentinelai_incident_${selectedAlert.alert_id}.${format}`;
    let mimeType = 'text/plain';

    if (format === 'json') {
      const report = {
        incident_id: selectedAlert.alert_id,
        title: selectedAlert.title,
        severity: selectedAlert.severity,
        detected_at: selectedAlert.timestamp,
        source_ip: selectedAlert.src_ip,
        destination_ip: selectedAlert.dst_ip,
        detection_method: selectedAlert.detection_method,
        explanation: selectedAlert.explanation,
        recommended_action: selectedAlert.recommended_action,
        analyst_notes: investigationNotes,
        evidence: selectedAlert.evidence,
        related_packets_count: relatedEvents.length,
        related_packets: relatedEvents,
      };
      content = JSON.stringify(report, null, 2);
      mimeType = 'application/json';
    } else {
      // CSV Export
      const headers = ['Timestamp', 'SourceIP', 'SourcePort', 'DestinationIP', 'DestinationPort', 'Protocol', 'PacketSize'];
      const rows = relatedEvents.map((e) =>
        [e.timestamp, e.src_ip, e.src_port, e.dst_ip, e.dst_port, e.protocol, e.packet_size].join(',')
      );
      content = [headers.join(','), ...rows].join('\n');
      mimeType = 'text/csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
        <div>
          <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            <Compass className="w-5 h-5 text-cyan-400" />
            Incident Forensic Investigation Workbench
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Reconstruct threat timelines, evaluate telemetry evidence against baselines, and export audit dossiers.
          </p>
        </div>

        {selectedAlert && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExportReport('json')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 hover:text-white"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={() => handleExportReport('csv')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30 text-xs font-semibold"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export Packets CSV</span>
            </button>
          </div>
        )}
      </div>

      {/* Main Grid: Incident Selector & Investigation Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Alerts List */}
        <div className="space-y-3">
          <h2 className="text-xs font-mono uppercase text-slate-400">Incident Dossiers</h2>
          <div className="space-y-2 max-h-[600px] overflow-y-auto">
            {loading ? (
              <div className="p-8 text-center text-slate-400 font-mono text-xs soc-card">
                Loading incident dossiers...
              </div>
            ) : alerts.length === 0 ? (
              <div className="p-8 text-center text-slate-500 font-mono text-xs soc-card">
                No incident dossiers recorded.
              </div>
            ) : (
              alerts.map((alt) => (
                <div
                  key={alt.alert_id}
                  onClick={() => handleSelectAlert(alt)}
                  className={`soc-card p-3.5 cursor-pointer transition-all ${
                    selectedAlert?.alert_id === alt.alert_id
                      ? 'soc-card-active'
                      : 'hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <SeverityBadge severity={alt.severity} size="sm" />
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(alt.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-white mt-1.5 line-clamp-1">{alt.title}</h4>
                  <p className="text-[11px] text-slate-400 font-mono mt-1">
                    {alt.src_ip} → {alt.dst_ip}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column (2 Cols): Forensic Details */}
        <div className="lg:col-span-2 space-y-5">
          {selectedAlert ? (
            <>
              {/* Incident Header */}
              <div className="soc-card p-5 space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={selectedAlert.severity} size="md" />
                      <span className="text-xs font-mono text-slate-400">ID: {selectedAlert.alert_id}</span>
                    </div>
                    <h3 className="text-lg font-bold text-white">{selectedAlert.title}</h3>
                  </div>

                  <div className="text-right font-mono text-xs text-slate-400">
                    <Clock className="w-3.5 h-3.5 inline mr-1 text-slate-500" />
                    <span>{new Date(selectedAlert.timestamp).toLocaleString()}</span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-slate-300 leading-relaxed">
                  <strong className="text-cyan-400 block mb-1">Observed Anomaly Context:</strong>
                  {selectedAlert.explanation}
                </div>
              </div>

              {/* Observed Communication Timeline */}
              <div className="soc-card p-5 space-y-4">
                <h3 className="text-xs uppercase font-mono text-slate-400">
                  Correlated Flow Activity ({relatedEvents.length} Packets)
                </h3>

                <div className="overflow-x-auto max-h-56">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="pb-2">Time</th>
                        <th className="pb-2">Source</th>
                        <th className="pb-2">Destination</th>
                        <th className="pb-2">Protocol</th>
                        <th className="pb-2">Bytes</th>
                        <th className="pb-2">Flags</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300">
                      {relatedEvents.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="py-6 text-center text-slate-500 font-mono">
                            No correlated packet traces stored for this incident.
                          </td>
                        </tr>
                      ) : (
                        relatedEvents.map((pkt, i) => (
                          <tr key={i} className="hover:bg-slate-800/40">
                            <td className="py-2 text-slate-400">{new Date(pkt.timestamp).toLocaleTimeString()}</td>
                            <td className="py-2 text-cyan-400">{pkt.src_ip}:{pkt.src_port}</td>
                            <td className="py-2 text-cyan-300">{pkt.dst_ip}:{pkt.dst_port}</td>
                            <td className="py-2 font-medium">{pkt.protocol}</td>
                            <td className="py-2">{pkt.packet_size}B</td>
                            <td className="py-2 text-slate-400">{pkt.flags || '—'}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Analyst Investigation Notes Section */}
              <div className="soc-card p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs uppercase font-mono text-slate-400">Analyst Investigation Dossier</h3>
                  {saveStatus && (
                    <span className="text-xs text-emerald-400 flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" />
                      {saveStatus}
                    </span>
                  )}
                </div>

                <textarea
                  rows={4}
                  placeholder="Record your forensic findings, root cause hypotheses, and remediation directives..."
                  value={investigationNotes}
                  onChange={(e) => setInvestigationNotes(e.target.value)}
                  className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />

                <div className="flex justify-end">
                  <button
                    onClick={handleSaveNotes}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>Save Investigation Record</span>
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="p-16 text-center text-slate-500 text-xs font-mono soc-card">
              Select an incident dossier from the list to begin investigation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
