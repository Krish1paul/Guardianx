import { useQuery } from '@tanstack/react-query';
import { healthAPI } from '@/lib/api';
import { useHistory } from '@/hooks/useHistory';
import type { URLScanSummary } from '@/types/api';

export default function ThreatIntelPage() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: healthAPI.ready,
  });

  const { data } = useHistory(0);
  const items: URLScanSummary[] = data?.items ?? [];
  const total = data?.total ?? 0;

  // Count how many scans have threat intel engine versions
  const tiScans = items.filter((s: URLScanSummary) => s.analyzer_version.includes('ti'));

  const isDbHealthy = health?.database === 'healthy' || health?.status === 'ready' || health?.status === 'ok';

  return (
    <div className="page-container animate-fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
          Threat Intelligence Feeds & Integrations
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginTop: 4 }}>
          External reputation telemetry, multi-vendor IOC correlation, and ML heuristic fusion.
        </p>
      </div>

      {/* Provider Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
        {/* VirusTotal Provider */}
        <div className="glass-card glow-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                Primary Provider
              </span>
              <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: 4 }}>
                VirusTotal API v3
              </h4>
            </div>
            <span
              className="badge badge-sm"
              style={{
                background: 'rgba(0, 230, 118, 0.15)',
                color: 'var(--color-safe)',
                border: '1px solid rgba(0, 230, 118, 0.3)',
              }}
            >
              Active
            </span>
          </div>

          <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginTop: 12, lineHeight: 1.5 }}>
            Correlates domains and URLs against 70+ antivirus and threat feeds. Falls back to deterministic mock provider in development.
          </p>

          <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
            <span>Provider mode</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-cyan)' }}>Dev / Mock Fail-safe</span>
          </div>
        </div>

        {/* Local ML Engine */}
        <div className="glass-card glow-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                Heuristic Classifier
              </span>
              <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: 4 }}>
                ML Pipeline (ml-v1)
              </h4>
            </div>
            <span
              className="badge badge-sm"
              style={{
                background: 'rgba(0, 212, 255, 0.15)',
                color: 'var(--color-cyan)',
                border: '1px solid rgba(0, 212, 255, 0.3)',
              }}
            >
              Loaded
            </span>
          </div>

          <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginTop: 12, lineHeight: 1.5 }}>
            High-speed local lexical & host feature extraction running in-process for low latency without external leak of sensitive endpoints.
          </p>

          <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
            <span>Inference latency</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-safe)' }}>&lt; 5ms</span>
          </div>
        </div>

        {/* Cache & DB Telemetry */}
        <div className="glass-card glow-card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
                Cache & Storage
              </span>
              <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: 4 }}>
                PostgreSQL + Cache
              </h4>
            </div>
            <span
              className="badge badge-sm"
              style={{
                background: isDbHealthy ? 'rgba(0, 230, 118, 0.15)' : 'rgba(255, 45, 85, 0.15)',
                color: isDbHealthy ? 'var(--color-safe)' : 'var(--color-critical)',
              }}
            >
              {isDbHealthy ? 'Healthy' : 'Degraded'}
            </span>
          </div>

          <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginTop: 12, lineHeight: 1.5 }}>
            Immutable storage for historical threat scans, URL hashes, and vendor intelligence results with 24h caching.
          </p>

          <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--color-border)', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
            <span>TI Enriched Scans</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-primary)' }}>{tiScans.length} of {total}</span>
          </div>
        </div>
      </div>

      {/* Integration Reference */}
      <div className="glass-card glow-card" style={{ padding: 24 }}>
        <h3 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: 14 }}>
          Intelligence Pipeline Architecture
        </h3>
        <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Guardianx employs a tiered defense-in-depth architecture. When a URL is submitted:
        </p>
        <ol style={{ paddingLeft: 20, marginTop: 12, fontSize: '0.82rem', color: 'var(--color-text-secondary)', lineHeight: 1.8 }}>
          <li><strong>Normalization & Hashing:</strong> The target URL is normalized and a SHA-256 hash is generated for privacy and deduplication.</li>
          <li><strong>Rule Engine (M2):</strong> Fast deterministic checks fire on high-confidence IOCs (suspicious TLDs, IP hosts, URL shorteners).</li>
          <li><strong>Machine Learning (M3):</strong> Lexical feature vector extracted and evaluated by the scikit-learn model.</li>
          <li><strong>Threat Intelligence (M4):</strong> Queries VirusTotal with local caching to incorporate live global threat feeds.</li>
          <li><strong>Risk Fusion:</strong> All signals are weighted and fused into a single 0–100 risk score and classification.</li>
        </ol>
      </div>
    </div>
  );
}
