import React, { useState, useEffect } from 'react';
import {
  Play,
  Square,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Clock,
  Wifi,
  Pause,
} from 'lucide-react';
import { api } from '../services/api';
import {
  CollectorStatus,
  NetworkInterface,
  NetworkEvent,
} from '../types';
import { StatusBadge } from '../components/common/StatusBadge';

interface LiveNetworkPageProps {
  liveEvents: NetworkEvent[];
  isPaused: boolean;
  onTogglePause: () => void;
  onSelectHost?: (ip: string) => void;
}

export const LiveNetworkPage: React.FC<LiveNetworkPageProps> = ({
  liveEvents,
  isPaused,
  onTogglePause,
  onSelectHost,
}) => {
  const [collectorStatus, setCollectorStatus] = useState<CollectorStatus | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [collectorMode, setCollectorMode] = useState<string>('simulation');
  const [loadingAction, setLoadingAction] = useState<boolean>(false);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);

  // Table filters
  const [filterProtocol, setFilterProtocol] = useState<string>('All');
  const [filterSuspiciousOnly, setFilterSuspiciousOnly] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(0);
  const pageSize = 15;

  const [historicalEvents, setHistoricalEvents] = useState<NetworkEvent[]>([]);
  const [useLiveBuffer, setUseLiveBuffer] = useState<boolean>(true);

  const fetchStatusAndInterfaces = async () => {
    try {
      const [statusRes, ifacesRes] = await Promise.all([
        api.getCollectorStatus(),
        api.getCollectorInterfaces(),
      ]);
      setCollectorStatus(statusRes);
      setInterfaces(ifacesRes);
      if (statusRes.mode || (statusRes as any).collector_mode) {
        const raw = (statusRes.mode || (statusRes as any).collector_mode || '').toLowerCase();
        if (raw.includes('live')) setCollectorMode('live');
        else if (raw.includes('pcap')) setCollectorMode('pcap');
        else if (raw.includes('sim')) setCollectorMode('simulation');
      }
      if (ifacesRes.length > 0 && !selectedInterface) {
        const first = ifacesRes[0];
        const firstName = typeof first === 'string' ? first : (first.name || first.id || '');
        const currentActive = statusRes.capture_interface || (statusRes as any).interface;
        const matched = ifacesRes.find(
          (i: any) =>
            i.id === currentActive ||
            i.name === currentActive ||
            i.alias === currentActive ||
            i.description === currentActive
        );
        setSelectedInterface(matched ? (matched.name || matched.id || '') : (firstName || ''));
      }
    } catch (e) {
      console.error('Failed to get collector status/interfaces', e);
    }
  };

  const handleSwitchMode = async (newMode: string) => {
    setCollectorMode(newMode);
    if (collectorStatus?.status === 'running') {
      try {
        setLoadingAction(true);
        await api.startCollector(selectedInterface, newMode, true);
        await fetchStatusAndInterfaces();
      } catch (err: any) {
        alert(`Failed to switch mode: ${err.message}`);
      } finally {
        setLoadingAction(false);
      }
    }
  };

  const getIfaceName = (iface: any) => {
    if (!iface) return '';
    if (typeof iface === 'string') return iface;
    return iface.name || iface.id || '';
  };

  const getIfaceLabel = (iface: any) => {
    if (!iface) return '';
    if (typeof iface === 'string') {
      return iface.replace(/\\Device\\NPF_\{[A-Fa-f0-9-]+\}\s*/gi, '').trim() || iface;
    }
    if (iface.description) {
      return iface.description.replace(/\\Device\\NPF_\{[A-Fa-f0-9-]+\}\s*/gi, '').trim();
    }
    if (iface.alias && iface.ip) {
      return `${iface.alias} (${iface.ip})`;
    }
    return iface.alias || iface.name || 'Network Adapter';
  };

  const fetchEventsFromApi = async () => {
    try {
      const res = await api.getEvents({
        limit: 100,
        protocol: filterProtocol !== 'All' ? filterProtocol : undefined,
        suspicious_only: filterSuspiciousOnly,
        search: searchQuery || undefined,
      });
      setHistoricalEvents(res.events || []);
    } catch (e) {
      console.error('Failed to load events', e);
    }
  };

  useEffect(() => {
    fetchStatusAndInterfaces();
    fetchEventsFromApi();
    const interval = setInterval(fetchStatusAndInterfaces, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleStartCapture = async () => {
    if (collectorStatus?.status === 'running') {
      setShowConfirmModal(true);
      return;
    }
    executeStart();
  };

  const executeStart = async () => {
    setShowConfirmModal(false);
    try {
      setLoadingAction(true);
      await api.startCollector(selectedInterface, collectorMode, true);
      await fetchStatusAndInterfaces();
    } catch (err: any) {
      alert(`Start failed: ${err.message}`);
    } finally {
      setLoadingAction(false);
    }
  };

  const handleStopCapture = async () => {
    try {
      setLoadingAction(true);
      await api.stopCollector();
      await fetchStatusAndInterfaces();
    } catch (err: any) {
      alert(`Stop failed: ${err.message}`);
    } finally {
      setLoadingAction(false);
    }
  };

  // Select events source: real-time live WebSocket buffer or queried historical buffer
  const displayedSource = useLiveBuffer && liveEvents.length > 0 ? liveEvents : historicalEvents;

  // Apply client filters
  const filteredEvents = displayedSource.filter((evt) => {
    if (filterProtocol !== 'All' && evt.protocol !== filterProtocol) return false;
    if (filterSuspiciousOnly && !evt.is_suspicious) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchIp = evt.src_ip.toLowerCase().includes(q) || evt.dst_ip.toLowerCase().includes(q);
      const matchPort = evt.src_port?.toString().includes(q) || evt.dst_port?.toString().includes(q);
      const matchProto = evt.protocol?.toLowerCase().includes(q);
      if (!matchIp && !matchPort && !matchProto) return false;
    }
    return true;
  });

  const paginatedEvents = filteredEvents.slice(page * pageSize, (page + 1) * pageSize);
  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;

  const formatUptime = (secs: number) => {
    if (!secs) return '0s';
    const mins = Math.floor(secs / 60);
    const hrs = Math.floor(mins / 60);
    if (hrs > 0) return `${hrs}h ${mins % 60}m`;
    if (mins > 0) return `${mins}m ${secs % 60}s`;
    return `${secs}s`;
  };

  return (
    <div className="space-y-6">
      {/* Collector Controls Section */}
      <div className="soc-card p-6 bg-slate-900/50 border-slate-800 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
              <Radio className="w-5 h-5 text-cyan-400" />
              Network Packet Collector & TShark Ingestion Engine
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              Host-side Npcap/TShark interface capture. Packets are normalized into layer-4 flow metadata; full raw
              payloads remain securely discarded.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <StatusBadge status={collectorStatus?.status || 'stopped'} size="md" />

            {collectorStatus?.status === 'running' ? (
              <button
                disabled={loadingAction}
                onClick={handleStopCapture}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/40 hover:bg-red-500/30 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop Collector</span>
              </button>
            ) : (
              <button
                disabled={loadingAction}
                onClick={handleStartCapture}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 hover:bg-emerald-500/30 font-semibold text-xs transition-colors disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Capture Session</span>
              </button>
            )}
          </div>
        </div>

        {/* Ingestion Mode Switcher Bar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-950/90 border border-slate-800">
          <div className="flex items-center gap-2.5">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Active Mode:
            </span>
            <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
              collectorMode === 'live'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : collectorMode === 'simulation'
                ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
            }`}>
              {collectorMode === 'live' ? 'LIVE HOST CAPTURE' : (collectorMode === 'simulation' ? 'SYNTHETIC SIMULATION' : 'PCAP REPLAY')}
            </span>
            {collectorStatus?.status === 'running' && (
              <span className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400 ml-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                Capture Session Active
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleSwitchMode('live')}
              disabled={loadingAction}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                collectorMode === 'live'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-sm shadow-emerald-500/20'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white hover:bg-slate-800'
              }`}
              title="Capture real traffic from your physical host network adapter"
            >
              <Wifi className="w-3.5 h-3.5 text-emerald-400" />
              <span>LIVE Host Wire</span>
            </button>

            <button
              onClick={() => handleSwitchMode('simulation')}
              disabled={loadingAction}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                collectorMode === 'simulation'
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/50 shadow-sm shadow-purple-500/20'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white hover:bg-slate-800'
              }`}
              title="Stream synthetic deterministic attack vectors and anomaly traffic"
            >
              <Radio className="w-3.5 h-3.5 text-purple-400" />
              <span>Synthetic Simulation</span>
            </button>

            <button
              onClick={() => handleSwitchMode('pcap')}
              disabled={loadingAction}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                collectorMode === 'pcap'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm shadow-cyan-500/20'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white hover:bg-slate-800'
              }`}
              title="Replay recorded PCAP capture file"
            >
              <Play className="w-3.5 h-3.5 text-cyan-400" />
              <span>PCAP Replay</span>
            </button>
          </div>
        </div>

        {/* Configuration Row */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1.5">Network Capture Interface</label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={collectorStatus?.status === 'running'}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 disabled:opacity-60"
            >
              {interfaces.length === 0 ? (
                <option value="">Detecting Host Interfaces...</option>
              ) : (
                interfaces.map((iface, idx) => {
                  const val = getIfaceName(iface);
                  const label = getIfaceLabel(iface);
                  return (
                    <option key={val || idx} value={val}>
                      {label}
                    </option>
                  );
                })
              )}
            </select>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1.5">Ingestion Mode</label>
            <select
              value={collectorMode}
              onChange={(e) => handleSwitchMode(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="simulation">SIMULATION (Synthetic Deterministic Traffic)</option>
              <option value="live">LIVE (Host TShark / Npcap)</option>
              <option value="pcap">PCAP REPLAY (Recorded Capture)</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1.5">Uptime & Active Session</label>
            <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                {formatUptime(collectorStatus?.uptime_seconds || 0)}
              </span>
              <span className="text-slate-500">
                {collectorStatus?.active_session ? `${collectorMode.toUpperCase()} Active` : 'No Session'}
              </span>
            </div>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1.5">Telemetry Counters</label>
            <div className="px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-between">
              <span>{collectorStatus?.packet_count?.toLocaleString() || 0} pkts</span>
              <span className="text-red-400">{collectorStatus?.parsing_errors || 0} errs</span>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="soc-card p-6 max-w-md w-full bg-slate-900 border-yellow-500/40 space-y-4">
            <div className="flex items-center gap-3 text-yellow-400">
              <AlertTriangle className="w-6 h-6" />
              <h3 className="font-bold text-base text-white">Restart Active Capture Session?</h3>
            </div>
            <p className="text-xs text-slate-300">
              A capture session is currently active on <code className="text-cyan-400">{collectorStatus?.capture_interface}</code>.
              Restarting will terminate the current stream and begin a new session on <code className="text-cyan-400">{selectedInterface}</code>.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowConfirmModal(false)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={executeStart}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 hover:bg-yellow-500/30"
              >
                Confirm Restart
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Live Traffic Stream Table */}
      <div className="soc-card p-5 space-y-4">
        {/* Table Controls Bar */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-sm font-bold text-white tracking-wide">Live Normalized Flow Stream</h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {filteredEvents.length} Events Buffered
            </span>

            {/* Visual Stream Tag */}
            {collectorStatus?.status === 'running' ? (
              collectorMode === 'live' ? (
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                  LIVE WIRE CAPTURE ({selectedInterface ? getIfaceLabel(interfaces.find(i => getIfaceName(i) === selectedInterface) || selectedInterface) : 'Adapter'})
                </span>
              ) : (
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                  SYNTHETIC SIMULATION (Test Attacks Active)
                </span>
              )
            ) : (
              <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
                CAPTURE STOPPED (Idle)
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Filter IP or port..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(0);
                }}
                className="pl-8 pr-3 py-1 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Protocol Filter */}
            <select
              value={filterProtocol}
              onChange={(e) => {
                setFilterProtocol(e.target.value);
                setPage(0);
              }}
              className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none"
            >
              <option value="All">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>

            {/* Suspicious Only Toggle */}
            <button
              onClick={() => {
                setFilterSuspiciousOnly(!filterSuspiciousOnly);
                setPage(0);
              }}
              className={`px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
                filterSuspiciousOnly
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              Suspicious Only
            </button>

            {/* Pause / Resume Button */}
            <button
              onClick={onTogglePause}
              className={`p-1.5 rounded border text-xs transition-colors ${
                isPaused
                  ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40'
                  : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
              title={isPaused ? 'Resume live event flow' : 'Pause visual updates'}
            >
              {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        {/* Data Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th className="pb-2.5 font-medium">Source</th>
                <th className="pb-2.5 font-medium">Timestamp</th>
                <th className="pb-2.5 font-medium">Source IP</th>
                <th className="pb-2.5 font-medium">Src Port</th>
                <th className="pb-2.5 font-medium">Destination IP</th>
                <th className="pb-2.5 font-medium">Dst Port</th>
                <th className="pb-2.5 font-medium">Protocol</th>
                <th className="pb-2.5 font-medium">Size</th>
                <th className="pb-2.5 font-medium">Flags</th>
                <th className="pb-2.5 font-medium">Detection</th>
                <th className="pb-2.5 text-right font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {paginatedEvents.length === 0 ? (
                <tr>
                  <td colSpan={11} className="py-8 text-center text-slate-500">
                    No packet events match current filters.
                  </td>
                </tr>
              ) : (
                paginatedEvents.map((evt) => (
                  <tr
                    key={evt.id}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      evt.is_suspicious ? 'bg-amber-500/5' : ''
                    }`}
                  >
                    <td className="py-2.5">
                      {evt.data_source === 'LIVE' ? (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          LIVE
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                          SIM
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                    <td className="py-2.5 font-semibold text-cyan-400">{evt.src_ip}</td>
                    <td className="py-2.5 text-slate-400">{evt.src_port || '—'}</td>
                    <td className="py-2.5 font-semibold text-cyan-300">{evt.dst_ip}</td>
                    <td className="py-2.5 text-slate-400">{evt.dst_port || '—'}</td>
                    <td className="py-2.5 font-medium text-slate-200">{evt.protocol}</td>
                    <td className="py-2.5 text-slate-400">{evt.packet_size}B</td>
                    <td className="py-2.5 text-slate-400">{evt.flags || '—'}</td>
                    <td className="py-2.5">
                      {evt.is_suspicious ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                          {evt.detection_status || 'Suspicious'}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">
                          Normal
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => onSelectHost && onSelectHost(evt.src_ip)}
                        className="px-2 py-0.5 rounded text-[11px] bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 border border-cyan-500/30"
                      >
                        Inspect
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
            Page {page + 1} of {totalPages} ({filteredEvents.length} total events)
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
    </div>
  );
};
