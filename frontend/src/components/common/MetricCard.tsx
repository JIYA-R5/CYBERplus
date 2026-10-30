import React from 'react';
import { LucideIcon, TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  unit?: string;
  change?: number;
  changePeriod?: string;
  icon: LucideIcon;
  iconColor?: string;
  iconBg?: string;
  subtitle?: string;
  onClick?: () => void;
  loading?: boolean;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  unit,
  change,
  changePeriod = 'vs last 24h',
  icon: Icon,
  iconColor = 'text-cyan-400',
  iconBg = 'bg-cyan-500/10 border-cyan-500/20',
  subtitle,
  onClick,
  loading = false,
}) => {
  return (
    <div
      onClick={onClick}
      className={`soc-card p-5 relative overflow-hidden transition-all duration-200 ${
        onClick ? 'cursor-pointer hover:border-cyan-500/40 hover:-translate-y-0.5' : ''
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</p>
          {loading ? (
            <div className="h-8 w-28 bg-slate-800/80 animate-pulse rounded my-1" />
          ) : (
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold tracking-tight text-white font-mono-code">
                {typeof value === 'number' ? value.toLocaleString() : value}
              </span>
              {unit && <span className="text-xs text-slate-400 font-normal">{unit}</span>}
            </div>
          )}
        </div>

        <div className={`p-2.5 rounded-lg border ${iconBg}`}>
          <Icon className={`w-5 h-5 ${iconColor}`} />
        </div>
      </div>

      <div className="mt-4 flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs">
        {change !== undefined ? (
          <div className="flex items-center gap-1.5">
            {change > 0 ? (
              <span className="inline-flex items-center text-red-400 font-medium">
                <TrendingUp className="w-3.5 h-3.5 mr-0.5" />
                +{change}%
              </span>
            ) : change < 0 ? (
              <span className="inline-flex items-center text-emerald-400 font-medium">
                <TrendingDown className="w-3.5 h-3.5 mr-0.5" />
                {change}%
              </span>
            ) : (
              <span className="inline-flex items-center text-slate-400 font-medium">
                <Minus className="w-3.5 h-3.5 mr-0.5" />
                0%
              </span>
            )}
            <span className="text-slate-500">{changePeriod}</span>
          </div>
        ) : subtitle ? (
          <span className="text-slate-400">{subtitle}</span>
        ) : (
          <span className="text-slate-500 font-mono text-[11px]">SentinelAI Telemetry</span>
        )}
      </div>
    </div>
  );
};
