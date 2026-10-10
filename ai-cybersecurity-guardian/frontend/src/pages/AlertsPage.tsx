import { useState, useEffect } from 'react';
import { CheckCircle2, ChevronRight, Sliders } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useHistory } from '@/hooks/useHistory';
import { RISK_COLOR, timeAgo } from '@/lib/utils';
import type { RiskClassification, URLScanSummary } from '@/types/api';
import toast from 'react-hot-toast';

export default function AlertsPage() {
  const { data } = useHistory(0);
  const items: URLScanSummary[] = data?.items ?? [];

  const [criticalOnly, setCriticalOnly] = useState(() => {
    return localStorage.getItem('cg_alert_critical_only') === 'true';
  });
  const [audioEnabled, setAudioEnabled] = useState(() => {
    return localStorage.getItem('cg_alert_audio') === 'true';
  });
  const navigate = useNavigate();

  useEffect(() => {
    localStorage.setItem('cg_alert_critical_only', String(criticalOnly));
  }, [criticalOnly]);

  useEffect(() => {
    localStorage.setItem('cg_alert_audio', String(audioEnabled));
  }, [audioEnabled]);

  const alertScans = items.filter((s: URLScanSummary) => {
    if (criticalOnly) return s.classification === 'CRITICAL';
    return s.classification === 'CRITICAL' || s.classification === 'HIGH_RISK';
  });

  return (
    <div className="page-container animate-fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
          Security Alerts & Events
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginTop: 4 }}>
          Live alert feed triggered by multi-engine heuristics and threat intelligence scores.
        </p>
      </div>

      {/* Preferences Bar */}
      <div
        className="glass-card glow-card"
        style={{
          padding: '14px 20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Sliders size={16} style={{ color: 'var(--color-cyan)' }} />
          <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Alert Sensitivity</span>
        </div>

        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.82rem', color: 'var(--color-text-secondary)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={criticalOnly}
              onChange={(e) => setCriticalOnly(e.target.checked)}
              style={{ accentColor: 'var(--color-cyan)' }}
            />
            Critical Only (Score &gt;= 90)
          </label>

          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.82rem', color: 'var(--color-text-secondary)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={audioEnabled}
              onChange={(e) => {
                setAudioEnabled(e.target.checked);
                if (e.target.checked) toast.success('Audio cues enabled for critical threats');
              }}
              style={{ accentColor: 'var(--color-cyan)' }}
            />
            Audio Chime
          </label>
        </div>
      </div>

      {/* Alerts Feed */}
      {alertScans.length === 0 ? (
        <div className="glass-card" style={{ padding: 48, textAlign: 'center' }}>
          <CheckCircle2 size={36} style={{ color: 'var(--color-safe)', margin: '0 auto 12px', opacity: 0.8 }} />
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>No Active Security Alerts</h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', maxWidth: 440, margin: '6px auto 16px' }}>
            {criticalOnly
              ? 'No scans match the Critical classification threshold.'
              : 'No high-risk or critical alerts found in your scan telemetry.'}
          </p>
          <button className="btn btn-secondary btn-sm" onClick={() => setCriticalOnly(false)}>
            Reset Filters
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {alertScans.map((scan: URLScanSummary) => (
            <div
              key={scan.id}
              className="glass-card glow-card"
              style={{
                padding: '14px 18px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 14,
                cursor: 'pointer',
              }}
              onClick={() => navigate('/history')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0 }}>
                <span className="status-dot status-dot-alive" style={{ color: RISK_COLOR[scan.classification as RiskClassification] }} />
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span
                      className="badge badge-sm"
                      style={{
                        background: `${RISK_COLOR[scan.classification as RiskClassification]}20`,
                        color: RISK_COLOR[scan.classification as RiskClassification],
                      }}
                    >
                      {scan.classification}
                    </span>
                    <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                      {timeAgo(scan.created_at)}
                    </span>
                  </div>
                  <p
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.8rem',
                      color: 'var(--color-text-primary)',
                      marginTop: 3,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      maxWidth: 580,
                    }}
                  >
                    {scan.url}
                  </p>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 800, fontSize: '1.2rem', color: RISK_COLOR[scan.classification as RiskClassification] }}>
                  {scan.risk_score}
                </span>
                <ChevronRight size={16} style={{ color: 'var(--color-text-muted)' }} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
