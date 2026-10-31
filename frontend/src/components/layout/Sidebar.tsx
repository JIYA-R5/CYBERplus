import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  BarChart3,
  ShieldAlert,
  Bell,
  Network,
  Compass,
  Cpu,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  Radio,
  Globe,
} from 'lucide-react';
import { CollectorStatus } from '../../types';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  openAlertsCount?: number;
  collectorStatus?: CollectorStatus | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  onToggle,
  openAlertsCount = 0,
  collectorStatus,
}) => {
  const navItems = [
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    { name: 'Live Network', path: '/live-network', icon: Activity },
    { name: 'Traffic Analytics', path: '/analytics', icon: BarChart3 },
    { name: 'Threat Intelligence', path: '/threat-intelligence', icon: Globe },
    { name: 'Alerts', path: '/alerts', icon: Bell, badge: openAlertsCount },
    { name: 'Incident Investigation', path: '/investigation', icon: Compass },
    { name: 'Model Insights', path: '/models', icon: Cpu },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const isRunning = collectorStatus?.status === 'running';

  return (
    <aside
      className={`fixed top-0 left-0 z-30 h-screen transition-all duration-300 ease-in-out border-r border-slate-800/80 bg-[#0B0F19]/95 backdrop-blur-md flex flex-col justify-between ${collapsed ? 'w-20' : 'w-64'
        }`}
    >
      {/* Top Branding */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)] shrink-0">
              <Shield className="w-6 h-6 text-white" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-bold text-base tracking-wide text-white flex items-center gap-1.5">
                  Sentinel<span className="text-cyan-400">AI</span>
                </span>
                <span className="text-[10px] tracking-wider uppercase text-slate-400 font-mono">
                  Autonomous SOC
                </span>
              </div>
            )}
          </div>

          <button
            onClick={onToggle}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Collector Live Pill in Sidebar */}
        <div className="px-3 pt-3">
          <div
            className={`flex items-center gap-2 p-2 rounded-lg border text-xs font-medium transition-colors ${isRunning
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-slate-800/40 border-slate-700/40 text-slate-400'
              }`}
          >
            <Radio className={`w-3.5 h-3.5 shrink-0 ${isRunning ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            {!collapsed && (
              <div className="flex items-center justify-between w-full">
                <span className="truncate">Collector: {isRunning ? 'Active' : 'Idle'}</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-black/30">
                  {collectorStatus?.mode || 'LIVE'}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1.5 mt-2">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group relative ${isActive
                  ? 'bg-gradient-to-r from-cyan-500/15 to-transparent text-cyan-400 border-l-2 border-cyan-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <item.icon className="w-5 h-5 shrink-0 transition-transform group-hover:scale-110" />
              {!collapsed && <span className="truncate">{item.name}</span>}
              {!collapsed && item.badge !== undefined && item.badge > 0 && (
                <span className="ml-auto px-2 py-0.5 text-xs font-semibold rounded-full bg-red-500/20 text-red-400 border border-red-500/30">
                  {item.badge}
                </span>
              )}
              {collapsed && item.badge !== undefined && item.badge > 0 && (
                <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-red-500 ring-2 ring-[#0B0F19]" />
              )}
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Bottom Footer Status */}
      <div className="p-3 border-t border-slate-800/80">
        <div
          className={`flex items-center gap-2 p-2 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400 ${collapsed ? 'justify-center' : ''
            }`}
        >
          <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]" />
          {!collapsed && (
            <div className="flex flex-col">
              <span className="text-white font-medium">SOC Engine Online</span>
              <span className="text-[10px] text-slate-500 font-mono">v2.4.0 • Enterprise</span>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
