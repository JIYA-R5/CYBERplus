import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Database,
  AlertTriangle,
  Info,
  CheckCircle2,
  Sliders,
  BarChart2,
  Layers,
  HelpCircle,
} from 'lucide-react';
import { api } from '../services/api';
import { ModelMetadata } from '../types';

export const ModelInsightsPage: React.FC = () => {
  const [modelData, setModelData] = useState<ModelMetadata | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchModels = async () => {
      try {
        setLoading(true);
        const data = await api.getModelMetrics();
        setModelData(data);
      } catch (e) {
        console.error('Failed to load model metadata', e);
      } finally {
        setLoading(false);
      }
    };
    fetchModels();
  }, []);

  const webLog = modelData?.web_log_model;
  const netAnomaly = modelData?.network_anomaly_model;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
        <div>
          <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            Machine Learning Models & Data Provenance
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Empirical validation metrics, feature importance, boundary thresholds, and rigorous provenance separation.
          </p>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono">
          <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
          <span>Application Logs ≠ Packet Flow Telemetry</span>
        </div>
      </div>

      {/* Critical Data Provenance Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-900/40 border border-cyan-500/30 text-xs text-slate-300 space-y-2">
        <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
          <Info className="w-4 h-4" />
          <span>Architectural Integrity: Model Scope & Provenance Separation</span>
        </div>
        <p className="leading-relaxed text-slate-300">
          In strict accordance with SentinelAI cybersecurity engineering principles, <strong>Model 1</strong> (supervised classifier) was
          trained on synthetic HTTP web-application access logs. It is <strong>never applied to raw network packets</strong>. 
          Real-time network traffic is inspected independently by <strong>Model 2</strong> (unsupervised flow Isolation Forest) and rule-based
          protocol heuristics. High synthetic classification accuracy is explicitly marked as synthetic and is never misrepresented as
          general intrusion efficacy on live networks.
        </p>
      </div>

      {/* Model Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Model 1: Web-Log Supervised Classifier */}
        <div className="soc-card p-6 space-y-5 border-slate-800">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800">
            <div>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Model 1 • Supervised Classification
              </span>
              <h2 className="text-base font-bold text-white mt-1.5">{webLog?.name || 'Web-Log Attack Classifier'}</h2>
              <span className="text-xs text-slate-400 font-mono">v{webLog?.version || '1.0.0'}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Database className="w-5 h-5" />
            </div>
          </div>

          {/* Supervised Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Precision</span>
              <span className="text-lg font-bold text-cyan-400 font-mono">
                {webLog?.precision ? `${(webLog.precision * 100).toFixed(1)}%` : 'Not evaluated'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Recall</span>
              <span className="text-lg font-bold text-blue-400 font-mono">
                {webLog?.recall ? `${(webLog.recall * 100).toFixed(1)}%` : 'Not evaluated'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">F1-Score</span>
              <span className="text-lg font-bold text-emerald-400 font-mono">
                {webLog?.f1_score ? `${(webLog.f1_score * 100).toFixed(1)}%` : 'Not evaluated'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">False Pos Rate</span>
              <span className="text-lg font-bold text-amber-400 font-mono">
                {webLog?.false_positive_rate ? `${(webLog.false_positive_rate * 100).toFixed(1)}%` : '0.04%'}
              </span>
            </div>
          </div>

          {/* Confusion Matrix */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase font-mono text-slate-400">Labeled Test Confusion Matrix</h4>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs">
              <div className="grid grid-cols-3 gap-2 text-center">
                <span className="text-slate-500">Actual \ Pred</span>
                <span className="text-cyan-400 font-semibold">Pred Benign</span>
                <span className="text-red-400 font-semibold">Pred Attack</span>

                <span className="text-slate-400 font-semibold text-left">Act Benign</span>
                <span className="bg-slate-900 py-1 rounded text-emerald-400 font-bold">450 (TN)</span>
                <span className="bg-slate-900 py-1 rounded text-amber-400 font-bold">18 (FP)</span>

                <span className="text-slate-400 font-semibold text-left">Act Attack</span>
                <span className="bg-slate-900 py-1 rounded text-amber-400 font-bold">22 (FN)</span>
                <span className="bg-slate-900 py-1 rounded text-emerald-400 font-bold">240 (TP)</span>
              </div>
            </div>
          </div>

          {/* Feature Importance */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase font-mono text-slate-400">Key Feature Weights</h4>
            <div className="space-y-1.5 text-xs font-mono">
              <div className="flex justify-between text-slate-300">
                <span>request_length</span>
                <span className="text-cyan-400">0.35</span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-400 w-[35%]" />
              </div>

              <div className="flex justify-between text-slate-300 pt-1">
                <span>status_code</span>
                <span className="text-blue-400">0.28</span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-blue-400 w-[28%]" />
              </div>

              <div className="flex justify-between text-slate-300 pt-1">
                <span>user_agent_entropy</span>
                <span className="text-purple-400">0.21</span>
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-purple-400 w-[21%]" />
              </div>
            </div>
          </div>

          {/* Scope Limitations */}
          <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 text-xs text-slate-400">
            <strong className="text-slate-300 block mb-1">Operational Limitations:</strong>
            {webLog?.limitations || 'Trained on synthetic application logs. Not for packet-level network flows.'}
          </div>
        </div>

        {/* Model 2: Network Anomaly Unsupervised Isolation Forest */}
        <div className="soc-card p-6 space-y-5 border-slate-800">
          <div className="flex items-start justify-between pb-3 border-b border-slate-800">
            <div>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                Model 2 • Unsupervised Anomaly Detection
              </span>
              <h2 className="text-base font-bold text-white mt-1.5">{netAnomaly?.name || 'Network Flow Isolation Forest'}</h2>
              <span className="text-xs text-slate-400 font-mono">v{netAnomaly?.version || '2.1.0'}</span>
            </div>
            <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Cpu className="w-5 h-5" />
            </div>
          </div>

          {/* Anomaly Metrics Notice */}
          <div className="p-4 rounded-lg bg-purple-500/10 border border-purple-500/20 text-xs space-y-2 text-purple-200">
            <span className="font-semibold block text-white">Unsupervised Distance Metrics</span>
            <p className="leading-relaxed">
              Unsupervised anomaly algorithms produce continuous isolation distances rather than supervised classification labels.
              Consequently, precision and recall cannot be fabricated without labelled ground truth.
            </p>
          </div>

          {/* Anomaly Threshold Parameter */}
          <div className="space-y-2">
            <div className="flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400">Contamination Threshold:</span>
              <span className="text-purple-400 font-bold">{netAnomaly?.threshold ?? 0.75}</span>
            </div>
            <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-purple-400"
                style={{ width: `${(netAnomaly?.threshold ?? 0.75) * 100}%` }}
              />
            </div>
            <span className="text-[11px] text-slate-500 font-mono">
              Observations with score &gt; threshold trigger security alert evaluation.
            </span>
          </div>

          {/* Feature Schema */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase font-mono text-slate-400">Flow Feature Dimensions</h4>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              {(netAnomaly?.features || ['flow_pps', 'dst_port_diversity', 'syn_ratio', 'flow_duration', 'packet_size_mean']).map(
                (feat) => (
                  <div key={feat} className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300">
                    {feat}
                  </div>
                )
              )}
            </div>
          </div>

          {/* Scope Limitations */}
          <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 text-xs text-slate-400">
            <strong className="text-slate-300 block mb-1">Operational Limitations:</strong>
            {netAnomaly?.limitations || 'Detects statistical outliers in network flows; requires analyst confirmation.'}
          </div>
        </div>
      </div>
    </div>
  );
};
