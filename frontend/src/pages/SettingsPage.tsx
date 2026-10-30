import React, { useState } from 'react';
import {
  Settings,
  Save,
  Radio,
  Sliders,
  Shield,
  Bell,
  Database,
  Check,
  Terminal,
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [bufferSize, setBufferSize] = useState<number>(200);
  const [anomalyThreshold, setAnomalyThreshold] = useState<number>(0.75);
  const [simulationSpeed, setSimulationSpeed] = useState<string>('normal');
  const [allowlistIps, setAllowlistIps] = useState<string>('127.0.0.1\n10.0.0.1\n192.168.1.1');
  const [savedSuccess, setSavedSuccess] = useState<boolean>(false);

  const handleSave = () => {
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 3000);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Page Header */}
      <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            <Settings className="w-5 h-5 text-cyan-400" />
            Platform & Telemetry Settings
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Tune collector buffer limits, detection sensitivity thresholds, and benign network exclusions.
          </p>
        </div>

        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors"
        >
          {savedSuccess ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}
          <span>{savedSuccess ? 'Settings Saved' : 'Save Changes'}</span>
        </button>
      </div>

      {/* Settings Grid */}
      <div className="space-y-5">
        {/* Collector Buffer & Performance */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
            <Radio className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Collector Ingestion & Stream Buffer</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="text-slate-400 block mb-1">Max In-Memory Event Buffer (items)</label>
              <input
                type="number"
                value={bufferSize}
                onChange={(e) => setBufferSize(Number(e.target.value))}
                className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <span className="text-[11px] text-slate-500 block mt-1">
                Prevents browser memory exhaustion during high packet rates.
              </span>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Simulation Stream Rate</label>
              <select
                value={simulationSpeed}
                onChange={(e) => setSimulationSpeed(e.target.value)}
                className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="slow">Slow (1 event / 2s)</option>
                <option value="normal">Normal (2-5 events / sec)</option>
                <option value="high">High Stress (15-30 events / sec)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Anomaly Detection Sensitivity */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">ML Anomaly Sensitivity Threshold</h2>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between items-center font-mono">
              <span className="text-slate-400">Contamination Alert Threshold:</span>
              <span className="text-cyan-400 font-bold text-sm">{(anomalyThreshold * 100).toFixed(0)}%</span>
            </div>

            <input
              type="range"
              min="0.5"
              max="0.95"
              step="0.05"
              value={anomalyThreshold}
              onChange={(e) => setAnomalyThreshold(Number(e.target.value))}
              className="w-full accent-cyan-400 bg-slate-800 rounded-lg cursor-pointer"
            />

            <p className="text-[11px] text-slate-500 font-mono">
              Lower values detect subtle outliers but may produce higher false positives; higher values report only
              extreme deviations.
            </p>
          </div>
        </div>

        {/* Exclusion Allowlist */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Benign Subnet & Host Allowlist</h2>
          </div>

          <div className="text-xs space-y-2">
            <label className="text-slate-400 font-mono block">Trusted IP Addresses (One per line)</label>
            <textarea
              rows={4}
              value={allowlistIps}
              onChange={(e) => setAllowlistIps(e.target.value)}
              className="w-full p-3 rounded bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
            />
            <span className="text-[11px] text-slate-500 font-mono block">
              Events originating between allowlisted hosts will be suppressed from triggering high-severity alerts.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
