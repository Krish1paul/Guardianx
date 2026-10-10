import { useState } from 'react';
import { AnimatePresence, motion, type Variants } from 'framer-motion';
import { AlertCircle, Archive, Check, ChevronDown, ChevronRight, Copy, Cpu, FileCode, ShieldCheck, Tag } from 'lucide-react';
import type { ExplainableReason, FileScanResponse, Severity } from '@/types/api';
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

interface FileScanResultProps {
  result: FileScanResponse;
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

export function FileScanResult({ result, onScanAnother }: FileScanResultProps) {
  const [copied, setCopied] = useState(false);
  const classification = scoreToClassification(result.risk_score);
  const threatCategories = Array.from(new Set(result.reasons.map((r) => r.category)));
  const summaryText = result.reasons.length > 0
    ? `${result.reasons[0].title}: ${result.reasons[0].explanation}`
    : 'Static file headers match declared types with zero executable anomalies.';

  const isExecutable = Boolean(
    result.features.is_executable_extension ||
    result.features.is_hidden_executable ||
    result.detected_type === 'WINDOWS_PE' ||
    result.detected_type === 'LINUX_ELF' ||
    result.detected_type === 'MACOS_MACHO'
  );
  const isArchive = Boolean(
    result.detected_type === 'ZIP_ARCHIVE' ||
    result.detected_type === 'TAR_ARCHIVE' ||
    result.detected_type === 'GZIP_ARCHIVE' ||
    (typeof result.features.archive_entry_count === 'number' && result.features.archive_entry_count > 0)
  );
  const archiveCount = typeof result.features.archive_entry_count === 'number'
    ? result.features.archive_entry_count
    : null;

  const handleCopySha = () => {
    void navigator.clipboard.writeText(result.file_hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      variants={resultVariants}
      initial="initial"
      animate="enter"
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
      role="region"
      aria-label="File scan result"
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

      {/* File Technical Metadata */}
      <motion.div variants={resultItemVariant}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 12,
        }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--color-border)', borderRadius: 8, padding: '12px 14px' }}>
            <span style={{ display: 'block', fontSize: '0.72rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>
              Filename & Size
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <FileCode size={15} style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
              <span style={{ fontSize: '0.85rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {result.filename}
              </span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
              {(result.file_size / 1024).toFixed(1)} KB ({result.file_size.toLocaleString()} bytes)
            </span>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--color-border)', borderRadius: 8, padding: '12px 14px' }}>
            <span style={{ display: 'block', fontSize: '0.72rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>
              Magic Signature / MIME
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Cpu size={15} style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
              <span style={{ fontSize: '0.85rem', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                {result.detected_type}
              </span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
              {result.declared_mime}
            </span>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--color-border)', borderRadius: 8, padding: '12px 14px' }}>
            <span style={{ display: 'block', fontSize: '0.72rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>
              Characteristics
            </span>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
              {isExecutable && (
                <span style={{ fontSize: '0.72rem', padding: '2px 8px', borderRadius: 4, background: 'rgba(255, 75, 75, 0.15)', color: 'var(--color-red)' }}>
                  Executable
                </span>
              )}
              {isArchive && (
                <span style={{ fontSize: '0.72rem', padding: '2px 8px', borderRadius: 4, background: 'rgba(0, 245, 255, 0.1)', color: 'var(--color-cyan)', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Archive size={12} />
                  Archive {archiveCount !== null && `(${archiveCount} files)`}
                </span>
              )}
              {!isExecutable && !isArchive && (
                <span style={{ fontSize: '0.72rem', padding: '2px 8px', borderRadius: 4, background: 'rgba(255, 255, 255, 0.08)', color: 'var(--color-text-secondary)' }}>
                  Document / Data
                </span>
              )}
            </div>
          </div>
        </div>

        {/* SHA-256 fingerprint */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(0, 0, 0, 0.3)',
          border: '1px solid var(--color-border)',
          borderRadius: 8,
          padding: '8px 14px',
          marginTop: 8,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', flexShrink: 0 }}>SHA-256:</span>
            <code style={{ fontSize: '0.75rem', color: 'var(--color-cyan)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {result.file_hash}
            </code>
          </div>
          <button
            type="button"
            onClick={handleCopySha}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--color-text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              fontSize: '0.72rem',
              marginLeft: 8,
              flexShrink: 0,
            }}
          >
            {copied ? <Check size={14} style={{ color: 'var(--color-green)' }} /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
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


      {/* Explainable reasons */}
      <motion.div variants={resultItemVariant}>
        <div className="result-section-title">
          {result.reasons.length === 0 ? '✓ No anomalies detected' : `Explainable Indicators (${result.reasons.length})`}
        </div>
        {result.reasons.length === 0 ? (
          <div className="result-safe-msg" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={16} style={{ color: 'var(--color-green)' }} />
            Clean file structure: MIME headers match file extensions and no executable anomalies found.
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
          Scan Another File
        </Button>
        <Button variant="ghost" onClick={() => (window.location.href = '/history')}>
          View History
        </Button>
      </motion.div>
    </motion.div>
  );
}
