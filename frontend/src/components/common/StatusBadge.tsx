import React from 'react';

interface StatusBadgeProps {
  status: string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const norm = (status || '').toLowerCase();

  const getStyle = () => {
    switch (norm) {
      case 'running':
      case 'active':
      case 'healthy':
      case 'operational':
        return {
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          dot: 'bg-emerald-400 shadow-[0_0_8px_#34d399]',
        };
      case 'stopped':
      case 'resolved':
        return {
          bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          dot: 'bg-slate-400',
        };
      case 'connecting':
      case 'investigating':
      case 'new':
        return {
          bg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
          dot: 'bg-cyan-400 animate-pulse',
        };
      case 'error':
      case 'degraded':
      case 'failed':
        return {
          bg: 'bg-red-500/10 text-red-400 border-red-500/30',
          dot: 'bg-red-400 shadow-[0_0_8px_#ef4444]',
        };
      default:
        return {
          bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          dot: 'bg-slate-400',
        };
    }
  };

  const style = getStyle();
  const sizeClass = size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-xs px-2.5 py-1';

  return (
    <span className={`inline-flex items-center gap-1.5 font-medium rounded-full border ${style.bg} ${sizeClass}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
      <span className="capitalize">{status}</span>
    </span>
  );
};
