import React from 'react';
import {
  Search,
  Bell,
  Sun,
  Moon,
  Clock,
  Radio,
  Wifi,
  WifiOff,
  User,
  Pause,
  Play,
} from 'lucide-react';
import { CollectorStatus, DataSource, TimeRange } from '../../types';
import { WSConnectionStatus } from '../../hooks/useWebSocket';

interface HeaderProps {
  collapsed: boolean;
  timeRange: TimeRange;
  onTimeRangeChange: (r: TimeRange) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  dataSource: DataSource;
  collectorStatus: CollectorStatus | null;
  wsStatus: WSConnectionStatus;
  lastEventTime: Date | null;
  isPaused: boolean;
  onTogglePause: () => void;
  isDarkTheme: boolean;
  onToggleTheme: () => void;
  unreadAlertsCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  collapsed,
  timeRange,
  onTimeRangeChange,
  searchQuery,
  onSearchChange,
  dataSource,
  collectorStatus,
  wsStatus,
  lastEventTime,
  isPaused,
  onTogglePause,
  isDarkTheme,
  onToggleTheme,
  unreadAlertsCount,
}) => {
  const isRunning = collectorStatus?.status === 'running';

  const formatLastSeen = () => {
    if (!lastEventTime) {
      if (collectorStatus?.last_event_received) {
        try {
          const d = new Date(collectorStatus.last_event_received);
          return d.toLocaleTimeString();
        } catch {
          return collectorStatus.last_event_received;
        }
      }
      return 'No events yet';
    }
    return lastEventTime.toLocaleTimeString();
  };

  const getSourceBadgeStyle = (src: DataSource) => {
    switch (src) {
      case 'LIVE':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'PCAP REPLAY':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'SIMULATION':
      default:
        return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30';
    }
  };

  return (
    <header
      className={`fixed top-0 right-0 z-20 h-16 border-b border-slate-800/80 bg-[#0B0F19]/90 backdrop-blur-md transition-all duration-300 flex items-center justify-between px-6 ${
        collapsed ? 'left-20' : 'left-64'
      }`}
    >
      {/* Left: Search Bar & Feed Pause Control */}
      <div className="flex items-center gap-4 flex-1 max-w-md">
        <div className="relative w-full">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search IPs, ports, alerts, CVEs, or signatures..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 transition-colors"
          />
        </div>

        <button
          onClick={onTogglePause}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors shrink-0 ${
            isPaused
              ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30 hover:bg-yellow-500/20'
              : 'bg-slate-900/80 text-slate-400 border-slate-800 hover:text-slate-200'
          }`}
          title={isPaused ? 'Resume live visual feed updates' : 'Pause live visual feed'}
        >
          {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
          <span>{isPaused ? 'Paused' : 'Feed Live'}</span>
        </button>
      </div>

      {/* Right: Telemetry status, time-range, badges, controls */}
      <div className="flex items-center gap-4">
        {/* Data Source Badge */}
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] text-slate-400 font-mono uppercase">Source:</span>
          <span
            className={`px-2.5 py-1 text-xs font-semibold rounded-md border tracking-wider font-mono ${getSourceBadgeStyle(
              dataSource
            )}`}
          >
            {dataSource}
          </span>
        </div>

        {/* WebSocket Stream Indicator */}
        <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
          {wsStatus === 'connected' ? (
            <>
              <Wifi className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-medium">WS Live</span>
            </>
          ) : (
            <>
              <WifiOff className="w-3.5 h-3.5 text-slate-500" />
              <span>WS Sync</span>
            </>
          )}
        </div>

        {/* Collector State & Last Event */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-md bg-slate-900/60 border border-slate-800 text-xs">
          <Radio
            className={`w-3.5 h-3.5 ${
              isRunning ? 'text-emerald-400 animate-pulse' : 'text-slate-500'
            }`}
          />
          <div className="flex items-center gap-1.5 text-slate-400">
            <Clock className="w-3.5 h-3.5 text-slate-500" />
            <span className="font-mono text-slate-300">{formatLastSeen()}</span>
          </div>
        </div>

        {/* Global Time Range Selector */}
        <div className="flex items-center bg-slate-900/80 p-0.5 rounded-lg border border-slate-800 text-xs">
          {(['1h', '6h', '24h', '7d'] as TimeRange[]).map((r) => (
            <button
              key={r}
              onClick={() => onTimeRangeChange(r)}
              className={`px-2.5 py-1 rounded-md font-medium transition-colors ${
                timeRange === r
                  ? 'bg-cyan-500/20 text-cyan-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {r}
            </button>
          ))}
        </div>

        {/* Notifications Bell */}
        <div className="relative">
          <button
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            {unreadAlertsCount > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 ring-2 ring-[#0B0F19]" />
            )}
          </button>
        </div>

        {/* Theme Toggle */}
        <button
          onClick={onToggleTheme}
          className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
          title={isDarkTheme ? 'Switch to Light theme' : 'Switch to Dark theme'}
        >
          {isDarkTheme ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {/* Analyst Profile Menu */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden xl:flex flex-col text-left">
            <span className="text-xs font-semibold text-white">Lead Analyst</span>
            <span className="text-[10px] text-slate-400 font-mono">SOC Tier 2</span>
          </div>
        </div>
      </div>
    </header>
  );
};
