import { useState } from 'react';
import { AnimatePresence, motion, type Variants } from 'framer-motion';
import { AlertCircle, ChevronDown, ChevronRight, ExternalLink, Globe, ShieldCheck, Tag } from 'lucide-react';
import type { ExplainableReason, MessageScanResponse, Severity } from '@/types/api';
import { ThreatGauge } from '@/components/dashboard/ThreatGauge';
import { RiskBadge, SeverityBadge } from '@/components/ui/Badge';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { formatDate, scoreToClassification, SEVERITY_COLOR } from '@/lib/utils';

function ExplainableReasonItem({ reason, index }: { reason: ExplainableReason; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const color = SEVERITY_COLOR[reason.severity as Severity] || 'var(--color-cyan)';

  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3, ease: 'easeOut' }}
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
          <span className="reason-code" style={{ fontSize: '0.85rem', fontWeight: 600 }}>{reason.title}</span>
          <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
            Category: {reason.category.replace(/_/g, ' ')}
            {reason.score_contribution > 0 && ` • +${reason.score_contribution} pts`}
          </span>
        </div>
        <SeverityBadge severity={reason.severity} />
        {expanded
          ? <ChevronDown size={14} style={{ color: 'var(--color-text-muted)', marginLeft: 8 }} />
          : <ChevronRight size={14} style={{ color: 'var(--color-text-muted)', marginLeft: 8 }} />}
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
            <p className="reason-message" style={{ marginTop: 8, fontSize: '0.82rem', lineHeight: 1.5 }}>
              {reason.explanation}
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

interface MessageScanResultProps {
  result: MessageScanResponse;
  onScanAnother: () => void;
}

const resultVariants: Variants = {
  initial: { opacity: 0 },
  enter: { opacity: 1, transition: { staggerChildren: 0.08 } },
};

const resultItemVariant: Variants = {
  initial: { opacity: 0, y: 16 },
  enter: { opacity: 1, y: 0, transition: { duration: 0.35, ease: 'easeOut' } },
};

export function MessageScanResult({ result, onScanAnother }: MessageScanResultProps) {
  const classification = scoreToClassification(result.risk_score);
  const threatCategories = Array.from(new Set(result.reasons.map((r) => r.category)));
  const summaryText = result.reasons.length > 0
    ? `${result.reasons[0].title}: ${result.reasons[0].explanation}`
    : 'No malicious indicators or phishing patterns detected in message content.';

  return (
    <motion.div
      variants={resultVariants}
      initial="initial"
      animate="enter"
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
      role="region"
      aria-label="Message scan result"
      aria-live="polite"
    >
      {/* Score and summary reveal */}
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
                <span style={{
                  fontSize: '0.72rem',
                  padding: '2px 8px',
                  borderRadius: 12,
                  background: 'rgba(255, 255, 255, 0.06)',
                  color: 'var(--color-cyan)',
                  fontFamily: 'var(--font-mono)'
                }}>
                  Confidence: {Math.round(result.confidence * 100)}%
                </span>
              </div>
              <p style={{ fontSize: '0.92rem', color: 'var(--color-text)', marginTop: 8, lineHeight: 1.4 }}>
                {summaryText}
              </p>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginTop: 4 }}>
                Analyzed {formatDate(result.created_at)}
              </p>
            </div>
          </div>
        </Card>
      </motion.div>

      {/* Threat categories */}
      {threatCategories.length > 0 && (
        <motion.div variants={resultItemVariant}>
          <div className="result-section-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Tag size={14} /> Threat Vectors Detected
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {threatCategories.map((cat) => (
              <span
                key={cat}
                style={{
                  fontSize: '0.75rem',
                  padding: '4px 10px',
                  borderRadius: 6,
                  background: 'rgba(255, 75, 75, 0.1)',
                  border: '1px solid rgba(255, 75, 75, 0.3)',
                  color: 'var(--color-red)',
                  textTransform: 'capitalize',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {cat.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </motion.div>
      )}

      {/* Embedded URLs */}
      <motion.div variants={resultItemVariant}>
        <div className="result-section-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Globe size={14} /> Embedded Links ({result.extracted_urls.length})
        </div>
        {result.extracted_urls.length === 0 ? (
          <div className="result-safe-msg">
            No external hyperlinks were found in this message.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {result.extracted_urls.map((extracted, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--color-border)',
                  borderRadius: 8,
                  gap: 12,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                  <ExternalLink size={14} style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
                  <span
                    style={{
                      fontSize: '0.82rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-text)',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={extracted.url}
                  >
                    {extracted.url}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                  <RiskBadge classification={extracted.classification} />
                  <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                    {extracted.risk_score}/100
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </motion.div>


      {/* Explainable reasons */}
      <motion.div variants={resultItemVariant}>
        <div className="result-section-title">
          {result.reasons.length === 0 ? '✓ No risk indicators detected' : `Explainable Indicators (${result.reasons.length})`}
        </div>
        {result.reasons.length === 0 ? (
          <div className="result-safe-msg" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={16} style={{ color: 'var(--color-green)' }} />
            No malicious persuasion, urgency, or credential harvesting patterns detected.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {result.reasons.map((r, i) => (
              <ExplainableReasonItem key={i} reason={r} index={i} />
            ))}
          </div>
        )}
      </motion.div>

      {/* CTAs */}
      <motion.div variants={resultItemVariant} style={{ display: 'flex', gap: 12 }}>
        <Button variant="primary" onClick={onScanAnother}>
          Scan Another Message
        </Button>
        <Button variant="ghost" onClick={() => (window.location.href = '/history')}>
          View History
        </Button>
      </motion.div>
    </motion.div>
  );
}
