import { AnimatePresence, motion, type Variants } from 'framer-motion';
import { AlertCircle, ChevronDown, ChevronRight, Info } from 'lucide-react';
import { useState } from 'react';
import type { RiskReason, ThreatIntelSummary, URLScanResponse } from '@/types/api';
import { ThreatGauge } from '@/components/dashboard/ThreatGauge';
import { RiskBadge, SeverityBadge, TIBadge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { formatDate, scoreToClassification, SEVERITY_COLOR } from '@/lib/utils';
import type { Severity } from '@/types/api';

// ---------------------------------------------------------------------------
// Reason item
// ---------------------------------------------------------------------------

function ReasonItem({ reason, index }: { reason: RiskReason; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const color = SEVERITY_COLOR[reason.severity as Severity];

  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.06, duration: 0.3, ease: 'easeOut' }}
      className="reason-item"
      style={{ borderLeft: `2px solid ${color}` }}
    >
      <div
        className="reason-header"
        onClick={() => setExpanded((e) => !e)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setExpanded((v) => !v); }}
        aria-expanded={expanded}
      >
        <AlertCircle size={15} style={{ color, flexShrink: 0 }} aria-hidden="true" />
        <span className="reason-code">{reason.code.replace(/_/g, ' ')}</span>
        <SeverityBadge severity={reason.severity} />
        {expanded
          ? <ChevronDown size={14} style={{ color: 'var(--color-text-muted)', marginLeft: 'auto' }} />
          : <ChevronRight size={14} style={{ color: 'var(--color-text-muted)', marginLeft: 'auto' }} />}
      </div>
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ overflow: 'hidden' }}
          >
            <p className="reason-message">{reason.message}</p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// TI chip
// ---------------------------------------------------------------------------

function ThreatIntelChip({ ti }: { ti: ThreatIntelSummary | null }) {
  if (!ti) {
    return (
      <div className="ti-chip">
        <Info size={14} style={{ color: 'var(--color-text-muted)' }} />
        <span style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem', marginLeft: 6 }}>
          Threat intelligence not available for this scan
        </span>
      </div>
    );
  }

  return (
    <div className="ti-chip ti-chip-active">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <TIBadge status={ti.status} />
        <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
          via {ti.provider}
          {ti.cached && ' (cached)'}
          {ti.provider_error && ' — provider error'}
        </span>
      </div>
      {ti.confidence !== null && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>Confidence</span>
          <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2 }}>
            <div style={{ width: `${ti.confidence * 100}%`, height: '100%', background: 'var(--color-cyan)', borderRadius: 2 }} />
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
            {Math.round(ti.confidence * 100)}%
          </span>
        </div>
      )}
      {ti.reason && (
        <p style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)', marginTop: 6 }}>{ti.reason}</p>
      )}
      <p style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', marginTop: 4 }}>
        Checked {formatDate(ti.checked_at)}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Feature breakdown
// ---------------------------------------------------------------------------

function FeatureBreakdown({ features }: { features: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  const entries = Object.entries(features).slice(0, 20);
  if (entries.length === 0) return null;

  return (
    <div className="feature-breakdown">
      <button className="feature-toggle" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <Info size={14} aria-hidden="true" />
        Technical feature breakdown
        {open ? <ChevronDown size={14} style={{ marginLeft: 'auto' }} /> : <ChevronRight size={14} style={{ marginLeft: 'auto' }} />}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            style={{ overflow: 'hidden' }}
          >
            <div className="feature-grid">
              {entries.map(([key, val]) => (
                <div key={key} className="feature-row">
                  <span className="feature-key">{key}</span>
                  <span className="feature-val">{String(val)}</span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main ScanResult
// ---------------------------------------------------------------------------

interface ScanResultProps {
  result: URLScanResponse;
  onScanAnother: () => void;
}

const resultVariants: Variants = {
  initial: { opacity: 0 },
  enter:   { opacity: 1, transition: { staggerChildren: 0.1 } },
};

const resultItemVariant: Variants = {
  initial: { opacity: 0, y: 16 },
  enter:   { opacity: 1, y: 0, transition: { duration: 0.35, ease: 'easeOut' } },
};

export function ScanResult({ result, onScanAnother }: ScanResultProps) {
  const classification = scoreToClassification(result.risk_score);

  return (
    <motion.div
      variants={resultVariants}
      initial="initial"
      animate="enter"
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
      role="region"
      aria-label="Scan result"
      aria-live="polite"
    >
      {/* Score reveal */}
      <motion.div variants={resultItemVariant}>
        <Card glow={result.risk_score > 75 ? 'red' : result.risk_score > 25 ? 'none' : 'green'}>
          <div className="result-score-row">
            <ThreatGauge score={result.risk_score} size={160} active />
            <div className="result-score-info">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <RiskBadge classification={classification} />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>
                  {result.analyzer_version}
                </span>
              </div>
              <p className="result-url" title={result.url}>{result.url}</p>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                Scanned {formatDate(result.created_at)}
              </p>
            </div>
          </div>
        </Card>
      </motion.div>

      {/* Risk reasons */}
      <motion.div variants={resultItemVariant}>
        <div className="result-section-title">
          {result.reasons.length === 0 ? '✓ No risk indicators detected' : `Risk Indicators (${result.reasons.length})`}
        </div>
        {result.reasons.length === 0 ? (
          <div className="result-safe-msg">
            This URL has no known risk indicators. Proceed with appropriate caution.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {result.reasons.map((r, i) => (
              <ReasonItem key={r.code} reason={r} index={i} />
            ))}
          </div>
        )}
      </motion.div>

      {/* Threat intelligence */}
      <motion.div variants={resultItemVariant}>
        <div className="result-section-title">Threat Intelligence</div>
        <ThreatIntelChip ti={result.threat_intelligence} />
      </motion.div>

      {/* Feature breakdown */}
      <motion.div variants={resultItemVariant}>
        <FeatureBreakdown features={result.features} />
      </motion.div>

      {/* CTAs */}
      <motion.div variants={resultItemVariant} style={{ display: 'flex', gap: 12 }}>
        <Button variant="primary" onClick={onScanAnother}>
          Scan Another URL
        </Button>
        <Button variant="ghost" onClick={() => window.location.href = '/history'}>
          View History
        </Button>
      </motion.div>
    </motion.div>
  );
}
