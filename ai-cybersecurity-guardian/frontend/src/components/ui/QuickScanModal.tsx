import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { ArrowRight, Globe, Loader2, ScanLine, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useScan } from '@/hooks/useScan';
import { useUI } from '@/providers/UIProvider';
import { RISK_COLOR, RISK_LABEL } from '@/lib/utils';
import { getErrorMessage } from '@/lib/api';
import type { RiskClassification } from '@/types/api';

export function QuickScanModal() {
  const { quickScanOpen, setQuickScanOpen } = useUI();
  const [url, setUrl] = useState('');
  const { mutateAsync: scan, isPending: isScanning, data: result, error, reset } = useScan();
  const navigate = useNavigate();

  if (!quickScanOpen) return null;

  const handleClose = () => {
    setQuickScanOpen(false);
    reset();
    setUrl('');
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim() || isScanning) return;
    try {
      await scan({ url: url.trim() });
    } catch {
      // Error handled by mutation state
    }
  };

  const handleViewFull = () => {
    handleClose();
    navigate('/scan');
  };

  const errorMsg = error ? getErrorMessage(error) : null;

  return (
    <AnimatePresence>
      <div className="modal-overlay" onClick={handleClose}>
        <motion.div
          className="modal-box"
          style={{ width: '100%', maxWidth: 540 }}
          initial={{ opacity: 0, scale: 0.95, y: 12 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 12 }}
          transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="modal-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--color-cyan-dim)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--color-cyan)',
                }}
              >
                <ScanLine size={18} />
              </div>
              <div>
                <h3 className="modal-title">Quick Threat Scan</h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                  Analyze any URL instantly with ML threat intelligence
                </p>
              </div>
            </div>
            <button className="modal-close" onClick={handleClose} aria-label="Close modal">
              <X size={18} />
            </button>
          </div>

          <div className="modal-content">
            <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ position: 'relative' }}>
                <Globe
                  size={16}
                  style={{
                    position: 'absolute',
                    left: 14,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    color: 'var(--color-text-muted)',
                  }}
                />
                <input
                  type="text"
                  className="input-field"
                  style={{ paddingLeft: 40, fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
                  placeholder="https://example.com/verify-account"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  autoFocus
                  disabled={isScanning}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="topbar-kbd">Press ESC to dismiss</span>
                <button
                  type="submit"
                  className="btn btn-primary btn-md"
                  disabled={!url.trim() || isScanning}
                >
                  {isScanning ? (
                    <>
                      <Loader2 size={16} className="spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <ScanLine size={16} />
                      Scan Now
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Error Message */}
            {errorMsg && (
              <div
                style={{
                  marginTop: 16,
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-md)',
                  background: 'rgba(255, 45, 85, 0.1)',
                  border: '1px solid rgba(255, 45, 85, 0.25)',
                  color: 'var(--color-critical)',
                  fontSize: '0.82rem',
                }}
              >
                {errorMsg}
              </div>
            )}

            {/* Scan Quick Result */}
            {result && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                style={{
                  marginTop: 20,
                  padding: 16,
                  borderRadius: 'var(--radius-lg)',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: `1px solid ${RISK_COLOR[result.classification as RiskClassification]}40`,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <span
                    className="badge"
                    style={{
                      background: `${RISK_COLOR[result.classification as RiskClassification]}20`,
                      color: RISK_COLOR[result.classification as RiskClassification],
                      border: `1px solid ${RISK_COLOR[result.classification as RiskClassification]}40`,
                    }}
                  >
                    {RISK_LABEL[result.classification as RiskClassification]}
                  </span>
                  <span style={{ fontSize: '1.2rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>
                    {result.risk_score} <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>/ 100</span>
                  </span>
                </div>

                <p
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.8rem',
                    color: 'var(--color-text-primary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    marginBottom: 12,
                  }}
                >
                  {result.url}
                </p>

                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  style={{ width: '100%' }}
                  onClick={handleViewFull}
                >
                  Inspect in URL Scanner
                  <ArrowRight size={14} />
                </button>
              </motion.div>
            )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
