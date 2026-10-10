import type { RiskClassification, Severity, ThreatIntelStatus } from '@/types/api';
import { RISK_COLOR, RISK_BG, RISK_LABEL } from '@/lib/utils';

interface RiskBadgeProps {
  classification: RiskClassification;
  size?: 'sm' | 'md';
}

export function RiskBadge({ classification, size = 'md' }: RiskBadgeProps) {
  return (
    <span
      className={`badge ${size === 'sm' ? 'badge-sm' : ''}`}
      style={{
        color: RISK_COLOR[classification],
        background: RISK_BG[classification],
        border: `1px solid ${RISK_COLOR[classification]}33`,
      }}
    >
      {RISK_LABEL[classification]}
    </span>
  );
}

const SEVERITY_COLOR: Record<Severity, string> = {
  LOW:      'var(--color-safe)',
  MEDIUM:   'var(--color-warning)',
  HIGH:     'var(--color-danger)',
  CRITICAL: 'var(--color-critical)',
};

const SEVERITY_BG: Record<Severity, string> = {
  LOW:      'var(--color-safe-dim)',
  MEDIUM:   'var(--color-warning-dim)',
  HIGH:     'var(--color-danger-dim)',
  CRITICAL: 'var(--color-critical-dim)',
};

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span
      className="badge badge-sm"
      style={{
        color: SEVERITY_COLOR[severity],
        background: SEVERITY_BG[severity],
        border: `1px solid ${SEVERITY_COLOR[severity]}33`,
      }}
    >
      {severity}
    </span>
  );
}

const TI_COLORS: Record<ThreatIntelStatus, { color: string; bg: string }> = {
  CLEAN:      { color: 'var(--color-safe)',     bg: 'var(--color-safe-dim)' },
  SUSPICIOUS: { color: 'var(--color-warning)',  bg: 'var(--color-warning-dim)' },
  MALICIOUS:  { color: 'var(--color-critical)', bg: 'var(--color-critical-dim)' },
  UNKNOWN:    { color: 'var(--color-text-muted)', bg: 'rgba(255,255,255,0.05)' },
};

interface TIBadgeProps {
  status: ThreatIntelStatus;
}

export function TIBadge({ status }: TIBadgeProps) {
  const { color, bg } = TI_COLORS[status];
  return (
    <span
      className="badge"
      style={{ color, background: bg, border: `1px solid ${color}33` }}
    >
      {status}
    </span>
  );
}
