import { LEVEL_META, RiskLevel } from "../lib/types";

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
  size?: number;
}

export default function RiskGauge({ score, level, size = 140 }: RiskGaugeProps) {
  const meta = LEVEL_META[level];
  const radius = (size - 16) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score));
  const dash = (clamped / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth={12}
            className="text-slate-100"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={meta.color}
            strokeWidth={12}
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference - dash}`}
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold text-slate-900">{clamped}</span>
          <span className="text-xs font-medium text-slate-400">/ 100</span>
        </div>
      </div>
      <span
        className={`rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${meta.bg} ${meta.text}`}
      >
        {meta.label}
      </span>
    </div>
  );
}
