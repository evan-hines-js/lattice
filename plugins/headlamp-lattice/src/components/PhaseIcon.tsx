import type { ServicePhase } from '../types';

const PHASE_CONFIG: Record<string, { symbol: string; color: string; label: string }> = {
  Ready: { symbol: '\u2713', color: '#4caf50', label: 'Ready' },
  Pending: { symbol: '\u25cb', color: '#ff9800', label: 'Pending' },
  Compiling: { symbol: '\u21bb', color: '#2196f3', label: 'Compiling' },
  Failed: { symbol: '\u2717', color: '#f44336', label: 'Failed' },
  Unknown: { symbol: '?', color: '#9e9e9e', label: 'Unknown' },
};

interface PhaseIconProps {
  phase: ServicePhase | 'Unknown' | string;
  showLabel?: boolean;
}

export default function PhaseIcon({ phase, showLabel = true }: PhaseIconProps) {
  const config = PHASE_CONFIG[phase] ?? PHASE_CONFIG.Unknown;

  return (
    <span
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
      role="status"
      aria-label={`Phase: ${config.label}`}
    >
      <span style={{ color: config.color, fontSize: 16, fontWeight: 'bold' }} aria-hidden="true">
        {config.symbol}
      </span>
      {showLabel && <span style={{ color: config.color }}>{config.label}</span>}
    </span>
  );
}
