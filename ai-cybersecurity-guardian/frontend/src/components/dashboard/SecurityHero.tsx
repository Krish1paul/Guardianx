import { motion } from 'framer-motion';
import { ArrowRight, Clock, Radar, ScanLine, ShieldAlert, ShieldCheck, ShieldX, Zap } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { ThreatGauge } from './ThreatGauge';
import { Button } from '@/components/ui/Button';
import type { RiskClassification } from '@/types/api';
import { RISK_LABEL, timeAgo } from '@/lib/utils';

interface SecurityHeroProps {
  avgScore: number;
  classification: RiskClassification;
  totalScans: number;
  lastScanAt: string | null;
  isLoading: boolean;
}

const POSTURE_ICONS: Record<RiskClassification, React.ReactNode> = {
  LOW_RISK:    <ShieldCheck size={22} style={{ color: 'var(--color-safe)' }} />,
  MEDIUM_RISK: <ShieldAlert size={22} style={{ color: 'var(--color-warning)' }} />,
  HIGH_RISK:   <ShieldX    size={22} style={{ color: 'var(--color-danger)' }} />,
  CRITICAL:    <ShieldX    size={22} style={{ color: 'var(--color-critical)' }} />,
};

const POSTURE_DESC: Record<RiskClassification, string> = {
  LOW_RISK:    'System posture secure. Analyzed endpoints exhibit normal behavior with zero active threats detected.',
  MEDIUM_RISK: 'Elevated threat signals present. Some scanned URLs triggered rule and ML heuristic flags.',
  HIGH_RISK:   'High-risk URL patterns identified. Immediate containment and investigation recommended.',
  CRITICAL:    'Critical security threats detected in recent telemetry. Malicious payloads or phishing indicators confirmed.',
};

export function SecurityHero({
  avgScore,
  classification,
  totalScans,
  lastScanAt,
  isLoading,
}: SecurityHeroProps) {
  const navigate = useNavigate();

  return (
    <div
      className="hero-section glass-card glow-card"
      data-threat={classification}
      style={{ position: 'relative', overflow: 'hidden' }}
    >
      {/* Ambient background grid & radar accent */}
      <div
        style={{
          position: 'absolute',
          right: '30%',
          top: '50%',
          transform: 'translate(50%, -50%)',
          width: 380,
          height: 380,
          borderRadius: '50%',
          border: '1px solid rgba(0, 212, 255, 0.05)',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      >
        <div
          style={{
            position: 'absolute',
            inset: 40,
            borderRadius: '50%',
            border: '1px dashed rgba(0, 212, 255, 0.08)',
          }}
        />
        <div
          style={{
            position: 'absolute',
            inset: 90,
            borderRadius: '50%',
            border: '1px solid rgba(0, 212, 255, 0.06)',
          }}
        />
        <div
          className="radar-sweep"
          style={{
            position: 'absolute',
            inset: 0,
            borderRadius: '50%',
            background: 'conic-gradient(from 0deg, transparent 0deg, transparent 300deg, rgba(0, 212, 255, 0.08) 360deg)',
          }}
        />
      </div>

      {/* Left — posture telemetry */}
      <div className="hero-left" style={{ position: 'relative', zIndex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div className="hero-posture-label" style={{ marginBottom: 0 }}>
            SECURITY POSTURE
          </div>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              fontSize: '0.68rem',
              fontWeight: 700,
              color: 'var(--color-cyan)',
              background: 'rgba(0, 212, 255, 0.08)',
              padding: '2px 8px',
              borderRadius: 'var(--radius-full)',
              border: '1px solid rgba(0, 212, 255, 0.2)',
            }}
          >
            <Radar size={11} className="spin" style={{ animationDuration: '6s' }} />
            ACTIVE MONITOR
          </span>
        </div>

        <div className="hero-classification">
          {POSTURE_ICONS[classification]}
          <span style={{ color: 'var(--color-text-primary)', fontSize: '1.45rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
            {RISK_LABEL[classification]}
          </span>
        </div>

        <p className="hero-description">
          {totalScans === 0
            ? 'No telemetry data recorded yet. Submit your first URL to initiate multi-engine threat detection.'
            : POSTURE_DESC[classification]}
        </p>

        {lastScanAt && (
          <div className="hero-last-scan">
            <Clock size={13} aria-hidden="true" />
            Last scan telemetry: {timeAgo(lastScanAt)}
          </div>
        )}
        {totalScans === 0 && !isLoading && (
          <div className="hero-last-scan" style={{ color: 'var(--color-text-muted)' }}>
            <ScanLine size={13} aria-hidden="true" />
            Zero historical scans
          </div>
        )}
      </div>

      {/* Center — threat gauge with radar backdrop */}
      <motion.div
        className="hero-gauge"
        style={{ position: 'relative', zIndex: 1 }}
        initial={{ opacity: 0, scale: 0.88 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
      >
        <ThreatGauge score={avgScore} size={200} active={!isLoading} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 }}>
          <span className="status-dot status-dot-alive" style={{ color: 'var(--color-cyan)', width: 6, height: 6 }} />
          <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', textAlign: 'center' }}>
            Mean Risk Index ({totalScans} scan{totalScans !== 1 ? 's' : ''})
          </p>
        </div>
      </motion.div>

      {/* Right — Actions & Quick Telemetry */}
      <div className="hero-right" style={{ position: 'relative', zIndex: 1 }}>
        <Button
          variant="primary"
          size="lg"
          icon={<ScanLine size={18} />}
          onClick={() => navigate('/scan')}
          style={{ width: '100%', maxWidth: 220 }}
        >
          Analyze URL
        </Button>
        <Button
          variant="secondary"
          size="md"
          icon={<ArrowRight size={16} />}
          onClick={() => navigate('/history')}
          style={{ width: '100%', maxWidth: 220 }}
        >
          View Full History
        </Button>

        {totalScans > 0 && (
          <div
            className="hero-stat-mini"
            style={{
              padding: '10px 14px',
              borderRadius: 'var(--radius-md)',
              background: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid var(--color-border)',
              width: '100%',
              maxWidth: 220,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: 'var(--color-text-muted)', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Processed Scans
              </span>
              <Zap size={12} style={{ color: 'var(--color-cyan)' }} />
            </div>
            <span style={{ color: 'var(--color-text-primary)', fontWeight: 800, fontSize: '1.4rem', fontFamily: 'var(--font-mono)' }}>
              {totalScans}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
