import { motion } from 'framer-motion';
import { Globe } from 'lucide-react';
import type { URLScanSummary } from '@/types/api';
import { EmptyState } from '@/components/ui/EmptyState';
import type { ThreatIntelStatus } from '@/types/api';

interface ThreatIntelPanelProps {
  items: URLScanSummary[];
  isLoading: boolean;
}

// Derive TI breakdown from scan items (items that have TI data are ml-v1+ti)
function computeTIBreakdown(items: URLScanSummary[]) {
  // We only have URLScanSummary here (no TI details), so we derive from
  // analyzer_version and classification as a proxy.
  // Scans with analyzer_version containing 'ti' have TI data.
  const tiScans = items.filter((i) => i.analyzer_version.includes('ti'));

  if (tiScans.length === 0) return null;

  // Classify by risk as a proxy: LOW_RISK → CLEAN, MEDIUM → SUSPICIOUS, HIGH/CRITICAL → MALICIOUS
  const breakdown: Record<ThreatIntelStatus, number> = {
    CLEAN: tiScans.filter((i) => i.classification === 'LOW_RISK').length,
    SUSPICIOUS: tiScans.filter((i) => i.classification === 'MEDIUM_RISK').length,
    MALICIOUS: tiScans.filter((i) => i.classification === 'HIGH_RISK' || i.classification === 'CRITICAL').length,
    UNKNOWN: 0,
  };

  return { breakdown, total: tiScans.length };
}

const TI_COLORS: Record<ThreatIntelStatus, string> = {
  CLEAN:      'var(--color-safe)',
  SUSPICIOUS: 'var(--color-warning)',
  MALICIOUS:  'var(--color-critical)',
  UNKNOWN:    'rgba(255,255,255,0.3)',
};

export function ThreatIntelPanel({ items, isLoading }: ThreatIntelPanelProps) {
  const result = computeTIBreakdown(items);

  return (
    <div>
      <h3 className="chart-title">Threat Intelligence</h3>

      {!isLoading && (!result || result.total === 0) ? (
        <EmptyState
          icon={<Globe size={32} />}
          title="No TI data"
          description="Scans using the ml-v1+ti analyzer include threat intelligence enrichment"
        />
      ) : (
        result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 16 }}>
            {(Object.entries(result.breakdown) as Array<[ThreatIntelStatus, number]>)
              .filter(([, count]) => count > 0)
              .map(([status, count]) => {
                const pct = Math.round((count / result.total) * 100);
                return (
                  <div key={status}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: '0.78rem', color: TI_COLORS[status], fontWeight: 600 }}>{status}</span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>{count} ({pct}%)</span>
                    </div>
                    <div style={{ height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                      <motion.div
                        style={{ height: '100%', background: TI_COLORS[status], borderRadius: 3 }}
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.8, ease: 'easeOut', delay: 0.2 }}
                        aria-hidden="true"
                      />
                    </div>
                  </div>
                );
              })}
            <p style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)', marginTop: 4 }}>
              Based on {result.total} TI-enriched scan{result.total !== 1 ? 's' : ''}
            </p>
          </div>
        )
      )}
    </div>
  );
}
