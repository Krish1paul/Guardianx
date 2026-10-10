import { ScanLine, Shield } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useHistory } from '@/hooks/useHistory';
import { Spinner } from '@/components/ui/Spinner';
import { RISK_COLOR, RISK_LABEL } from '@/lib/utils';
import type { RiskClassification, URLScanSummary } from '@/types/api';

export default function AnalyticsPage() {
  const { data, isLoading } = useHistory(0);
  const navigate = useNavigate();

  if (isLoading) {
    return (
      <div className="page-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
        <Spinner size="lg" />
      </div>
    );
  }

  const items: URLScanSummary[] = data?.items ?? [];
  const total = data?.total ?? 0;

  // Calculate real metrics from historical scans
  const classificationCounts: Record<RiskClassification, number> = {
    LOW_RISK: 0,
    MEDIUM_RISK: 0,
    HIGH_RISK: 0,
    CRITICAL: 0,
  };

  const engineCounts: Record<string, number> = {};

  items.forEach((scan: URLScanSummary) => {
    const cls = scan.classification as RiskClassification;
    if (classificationCounts[cls] !== undefined) {
      classificationCounts[cls]++;
    }
    engineCounts[scan.analyzer_version] = (engineCounts[scan.analyzer_version] || 0) + 1;
  });

  const avgScore = total > 0
    ? Math.round(items.reduce((sum: number, s: URLScanSummary) => sum + s.risk_score, 0) / total)
    : 0;

  return (
    <div className="page-container animate-fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
            Security Analytics & Telemetry
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginTop: 4 }}>
            Aggregated heuristics, engine distribution, and threat pattern analytics across {total} scans.
          </p>
        </div>
        <button
          className="btn btn-primary btn-md"
          onClick={() => navigate('/scan')}
        >
          <ScanLine size={16} />
          Scan New URL
        </button>
      </div>

      {total === 0 ? (
        <div className="glass-card" style={{ padding: 48, textAlign: 'center' }}>
          <Shield size={40} style={{ color: 'var(--color-cyan)', margin: '0 auto 16px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>No Telemetry Recorded</h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', maxWidth: 460, margin: '8px auto 20px' }}>
            Run your first URL scan to populate real-time heuristics, engine diagnostics, and classification breakdowns.
          </p>
          <button className="btn btn-primary btn-md" onClick={() => navigate('/scan')}>
            Launch Scanner
          </button>
        </div>
      ) : (
        <>
          {/* Top KPI row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
            <div className="glass-card glow-card" style={{ padding: 20 }}>
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                Mean Risk Score
              </span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 8 }}>
                <span style={{ fontSize: '2rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{avgScore}</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>/ 100</span>
              </div>
            </div>

            <div className="glass-card glow-card" style={{ padding: 20 }}>
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                Engine Versions
              </span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 8 }}>
                <span style={{ fontSize: '2rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)' }}>
                  {Object.keys(engineCounts).length}
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>active engines</span>
              </div>
            </div>

            <div className="glass-card glow-card" style={{ padding: 20 }}>
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                Threat Ratio
              </span>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 8 }}>
                <span style={{ fontSize: '2rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--color-critical)' }}>
                  {Math.round(((classificationCounts.CRITICAL + classificationCounts.HIGH_RISK) / total) * 100)}%
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>flagged suspicious</span>
              </div>
            </div>
          </div>

          {/* Classification Breakdown & Engine Diagnostics */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20 }}>
            {/* Risk Classifications */}
            <div className="glass-card glow-card" style={{ padding: 24 }}>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-text-secondary)', marginBottom: 20 }}>
                Classification Distribution
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {(['LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL'] as RiskClassification[]).map((tier) => {
                  const count = classificationCounts[tier] || 0;
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  return (
                    <div key={tier}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 6 }}>
                        <span style={{ color: RISK_COLOR[tier], fontWeight: 600 }}>{RISK_LABEL[tier]}</span>
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                          {count} ({pct}%)
                        </span>
                      </div>
                      <div style={{ height: 6, borderRadius: 3, background: 'rgba(255, 255, 255, 0.05)', overflow: 'hidden' }}>
                        <div
                          style={{
                            width: `${pct}%`,
                            height: '100%',
                            background: RISK_COLOR[tier],
                            transition: 'width 0.6s ease',
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Engine Diagnostics */}
            <div className="glass-card glow-card" style={{ padding: 24 }}>
              <h3 style={{ fontSize: '0.9rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--color-text-secondary)', marginBottom: 20 }}>
                Detection Engine Breakdown
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {Object.entries(engineCounts).map(([engine, count]) => (
                  <div
                    key={engine}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 14px',
                      background: 'rgba(0, 0, 0, 0.2)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--color-border)',
                    }}
                  >
                    <div>
                      <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-cyan)', fontFamily: 'var(--font-mono)' }}>
                        {engine}
                      </span>
                      <p style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', marginTop: 2 }}>
                        {engine.includes('ti') ? 'ML + VirusTotal Threat Intelligence' : 'Rule Heuristics & Lexical Model'}
                      </p>
                    </div>
                    <span
                      className="badge badge-sm"
                      style={{
                        background: 'rgba(0, 212, 255, 0.12)',
                        color: 'var(--color-cyan)',
                        border: '1px solid rgba(0, 212, 255, 0.25)',
                      }}
                    >
                      {count} scans
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
