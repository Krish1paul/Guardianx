/**
 * Utility helpers — formatters, classname builder, risk tier helpers.
 */

import { formatDistanceToNow, format } from 'date-fns';
import type { RiskClassification, Severity } from '@/types/api';

// ---------------------------------------------------------------------------
// Classnames — simple concatenation helper
// ---------------------------------------------------------------------------

export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}

// ---------------------------------------------------------------------------
// Date/time formatters
// ---------------------------------------------------------------------------

export function timeAgo(dateStr: string): string {
  try {
    return formatDistanceToNow(new Date(dateStr), { addSuffix: true });
  } catch {
    return dateStr;
  }
}

export function formatDate(dateStr: string): string {
  try {
    return format(new Date(dateStr), 'MMM d, yyyy HH:mm');
  } catch {
    return dateStr;
  }
}

// ---------------------------------------------------------------------------
// URL truncation
// ---------------------------------------------------------------------------

export function truncateUrl(url: string, max = 60): string {
  if (url.length <= max) return url;
  const half = Math.floor((max - 3) / 2);
  return `${url.slice(0, half)}...${url.slice(url.length - half)}`;
}

// ---------------------------------------------------------------------------
// Risk tier helpers
// ---------------------------------------------------------------------------

export const RISK_COLOR: Record<RiskClassification, string> = {
  LOW_RISK:    'var(--color-safe)',
  MEDIUM_RISK: 'var(--color-warning)',
  HIGH_RISK:   'var(--color-danger)',
  CRITICAL:    'var(--color-critical)',
};

export const RISK_BG: Record<RiskClassification, string> = {
  LOW_RISK:    'var(--color-safe-dim)',
  MEDIUM_RISK: 'var(--color-warning-dim)',
  HIGH_RISK:   'var(--color-danger-dim)',
  CRITICAL:    'var(--color-critical-dim)',
};

export const RISK_LABEL: Record<RiskClassification, string> = {
  LOW_RISK:    'Low Risk',
  MEDIUM_RISK: 'Medium Risk',
  HIGH_RISK:   'High Risk',
  CRITICAL:    'Critical',
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  LOW:      'var(--color-safe)',
  MEDIUM:   'var(--color-warning)',
  HIGH:     'var(--color-danger)',
  CRITICAL: 'var(--color-critical)',
};

export function scoreToClassification(score: number): RiskClassification {
  if (score <= 25) return 'LOW_RISK';
  if (score <= 50) return 'MEDIUM_RISK';
  if (score <= 75) return 'HIGH_RISK';
  return 'CRITICAL';
}

export function scoreToColor(score: number): string {
  if (score <= 25) return 'var(--color-safe)';
  if (score <= 50) return 'var(--color-warning)';
  if (score <= 75) return 'var(--color-danger)';
  return 'var(--color-critical)';
}

// ---------------------------------------------------------------------------
// Dashboard stats
// ---------------------------------------------------------------------------

export function computeDashboardStats(items: Array<{ risk_score: number; classification: RiskClassification; threat_intelligence?: unknown }>) {
  if (items.length === 0) {
    return {
      total: 0,
      avgScore: 0,
      critical: 0,
      safe: 0,
      distribution: { LOW_RISK: 0, MEDIUM_RISK: 0, HIGH_RISK: 0, CRITICAL: 0 },
      histogram: [
        { label: '0–25', count: 0 },
        { label: '26–50', count: 0 },
        { label: '51–75', count: 0 },
        { label: '76–100', count: 0 },
      ],
    };
  }

  const total = items.length;
  const avgScore = Math.round(items.reduce((s, i) => s + i.risk_score, 0) / total);
  const critical = items.filter((i) => i.classification === 'CRITICAL').length;
  const safe = items.filter((i) => i.classification === 'LOW_RISK').length;

  const distribution = items.reduce(
    (acc, i) => { acc[i.classification]++; return acc; },
    { LOW_RISK: 0, MEDIUM_RISK: 0, HIGH_RISK: 0, CRITICAL: 0 } as Record<RiskClassification, number>,
  );

  const histogram = [
    { label: '0–25',   count: items.filter((i) => i.risk_score <= 25).length },
    { label: '26–50',  count: items.filter((i) => i.risk_score > 25 && i.risk_score <= 50).length },
    { label: '51–75',  count: items.filter((i) => i.risk_score > 50 && i.risk_score <= 75).length },
    { label: '76–100', count: items.filter((i) => i.risk_score > 75).length },
  ];

  return { total, avgScore, critical, safe, distribution, histogram };
}

// ---------------------------------------------------------------------------
// Security Incidents Helpers (M8)
// ---------------------------------------------------------------------------

export const STATUS_COLOR: Record<string, string> = {
  OPEN: 'var(--color-critical)',
  INVESTIGATING: 'var(--color-warning)',
  RESOLVED: 'var(--color-safe)',
  FALSE_POSITIVE: 'var(--color-text-muted)',
};

export const STATUS_LABEL: Record<string, string> = {
  OPEN: 'Open',
  INVESTIGATING: 'Investigating',
  RESOLVED: 'Resolved',
  FALSE_POSITIVE: 'False Positive',
};

export const STAGE_LABEL: Record<string, string> = {
  RECONNAISSANCE: 'Reconnaissance',
  INITIAL_ACCESS: 'Initial Access',
  CREDENTIAL_HARVESTING: 'Credential Harvesting',
  MALICIOUS_DELIVERY: 'Malicious Delivery',
  EVASION_EXECUTION: 'Evasion & Execution',
  SOCIAL_ENGINEERING: 'Social Engineering',
  MULTI_VECTOR_CAMPAIGN: 'Multi-Vector Attack Chain',
};
