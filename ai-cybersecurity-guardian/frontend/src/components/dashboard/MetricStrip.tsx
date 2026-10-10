import { motion, type Variants } from 'framer-motion';
import { ArrowUpRight, Database, ShieldAlert, ShieldCheck, TrendingUp } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useCountUp } from '@/hooks/useCountUp';
import { MiniRiskMeter } from './ThreatGauge';

interface MetricStripProps {
  critical: number;
  total: number;
  safe: number;
  avgScore: number;
  isLoading: boolean;
}

const cardVariants: Variants = {
  initial: { opacity: 0, y: 16 },
  enter: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.06, duration: 0.35, ease: 'easeOut' },
  }),
};

function AnimatedNumber({ value }: { value: number }) {
  const display = useCountUp(value, 800);
  return <>{display}</>;
}

export function MetricStrip({ critical, total, safe, avgScore, isLoading }: MetricStripProps) {
  const navigate = useNavigate();

  return (
    <div className="metric-strip">
      {/* Critical threats — Clickable to Threat Center */}
      <motion.div
        className="metric-card metric-card-critical glass-card glow-card glow-card-interactive"
        data-threat="CRITICAL"
        custom={0}
        initial="initial"
        animate="enter"
        variants={cardVariants}
        onClick={() => navigate('/threat-center')}
        title="View critical threats in Threat Center"
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && navigate('/threat-center')}
      >
        <div className="metric-icon-wrap metric-icon-critical">
          <ShieldAlert size={20} aria-hidden="true" />
        </div>
        <div className="metric-info">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="metric-label">Critical Threats</span>
            <ArrowUpRight size={14} style={{ color: 'var(--color-critical)', opacity: 0.7 }} />
          </div>
          <span className="metric-value metric-value-critical">
            {isLoading ? '—' : <AnimatedNumber value={critical} />}
          </span>
        </div>
      </motion.div>

      {/* Total scans — Clickable to History */}
      <motion.div
        className="metric-card glass-card glow-card glow-card-interactive"
        custom={1}
        initial="initial"
        animate="enter"
        variants={cardVariants}
        onClick={() => navigate('/history')}
        title="View all scans in History"
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && navigate('/history')}
      >
        <div className="metric-icon-wrap metric-icon-default">
          <Database size={18} aria-hidden="true" />
        </div>
        <div className="metric-info">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="metric-label">Total Scans</span>
            <ArrowUpRight size={14} style={{ color: 'var(--color-text-muted)' }} />
          </div>
          <span className="metric-value">
            {isLoading ? '—' : <AnimatedNumber value={total} />}
          </span>
        </div>
      </motion.div>

      {/* Safe URLs — Clickable to History */}
      <motion.div
        className="metric-card glass-card glow-card glow-card-interactive"
        data-threat="LOW_RISK"
        custom={2}
        initial="initial"
        animate="enter"
        variants={cardVariants}
        onClick={() => navigate('/history')}
        title="View safe scans in History"
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && navigate('/history')}
      >
        <div className="metric-icon-wrap metric-icon-safe">
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
        <div className="metric-info">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="metric-label">Safe URLs</span>
            <ArrowUpRight size={14} style={{ color: 'var(--color-safe)', opacity: 0.7 }} />
          </div>
          <span className="metric-value metric-value-safe">
            {isLoading ? '—' : <AnimatedNumber value={safe} />}
          </span>
        </div>
      </motion.div>

      {/* Average risk — Clickable to Analytics */}
      <motion.div
        className="metric-card glass-card glow-card glow-card-interactive"
        custom={3}
        initial="initial"
        animate="enter"
        variants={cardVariants}
        onClick={() => navigate('/analytics')}
        title="View detailed Analytics breakdown"
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && navigate('/analytics')}
      >
        <div className="metric-icon-wrap metric-icon-default">
          <TrendingUp size={18} aria-hidden="true" />
        </div>
        <div className="metric-info" style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="metric-label">Avg Risk Score</span>
            <ArrowUpRight size={14} style={{ color: 'var(--color-cyan)', opacity: 0.7 }} />
          </div>
          <span className="metric-value">
            {isLoading ? '—' : <AnimatedNumber value={avgScore} />}
          </span>
          {!isLoading && total > 0 && (
            <div style={{ marginTop: 6 }}>
              <MiniRiskMeter score={avgScore} width={120} />
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
