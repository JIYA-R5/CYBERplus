import React, { useState, useEffect } from 'react';
import {
  Network,
  Search,
  Server,
  ShieldAlert,
  Clock,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import { HostInfo, NetworkEvent, SecurityAlert } from '../types';

interface HostsPageProps {
  initialHostIp?: string | null;
}

export const HostsPage: React.FC<HostsPageProps> = ({ initialHostIp }) => {
  const [hosts, setHosts] = useState<HostInfo[]>([]);
  const [selectedHost, setSelectedHost] = useState<HostInfo | null>(null);
  const [hostDetails, setHostDetails] = useState<{
    flows_history?: NetworkEvent[];
    alerts_history?: SecurityAlert[];
  } | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    const fetchHosts = async () => {
      try {
        setLoading(true);
        const data = await api.getHosts();
        setHosts(data || []);

        if (initialHostIp) {
          const match = data.find((h) => h.ip === initialHostIp);
          if (match) {
            handleSelectHost(match);
          }
        }
      } catch (err) {
        console.error('Failed to load hosts', err);
      } finally {
        setLoading(false);
      }
    };
    fetchHosts();
  }, [initialHostIp]);

  const handleSelectHost = async (host: HostInfo) => {
    setSelectedHost(host);
    try {
      const detailed = await api.getHost(host.ip);
      setHostDetails(detailed);
    } catch (e) {
      console.error('Failed to load host detail', e);
    }
  };

  const filteredHosts = hosts.filter((h) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
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
      {/* Page Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 gap-4">
        <div>
          <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            Observed Hosts & Connection Inventory
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Empirical inventory of observed IP endpoints, connection history, port footprint, and threat telemetry.
          </p>
        </div>

        <div className="text-xs font-mono text-cyan-400 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
          {hosts.length} Observed Endpoints
        </div>
      </div>

      {/* Search Bar */}
      <div className="soc-card p-4 flex items-center justify-between">
        <div className="relative w-full max-w-md">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search host by IP or contacted port..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Main Grid: Hosts List & Host Detail Drawer/Modal */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Host Cards / Table (2 Cols) */}
        <div className="lg:col-span-2 space-y-3">
          {loading ? (
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
              const alerts = getHostAlerts(host);
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
                      {alerts > 0 && (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30 flex items-center gap-1">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          {alerts} Alert{alerts > 1 ? 's' : ''}
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
  );
};
