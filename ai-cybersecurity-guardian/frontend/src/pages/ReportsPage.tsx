import { Download, FileJson, FileSpreadsheet, Printer, Sparkles } from 'lucide-react';
import { useHistory } from '@/hooks/useHistory';
import type { URLScanSummary } from '@/types/api';
import toast from 'react-hot-toast';

export default function ReportsPage() {
  const { data } = useHistory(0);
  const items: URLScanSummary[] = data?.items ?? [];
  const total = data?.total ?? 0;

  const handleExportJSON = () => {
    if (items.length === 0) {
      toast.error('No scan records to export');
      return;
    }
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(items, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `guardianx_report_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    toast.success('JSON export downloaded');
  };

  const handleExportCSV = () => {
    if (items.length === 0) {
      toast.error('No scan records to export');
      return;
    }
    const headers = ['id', 'url', 'risk_score', 'classification', 'analyzer_version', 'created_at'];
    const csvRows = [
      headers.join(','),
      ...items.map((s: URLScanSummary) =>
        [
          s.id,
          `"${s.url.replace(/"/g, '""')}"`,
          s.risk_score,
          s.classification,
          s.analyzer_version,
          `"${s.created_at}"`,
        ].join(',')
      ),
    ];
    const dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvRows.join('\n'));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `guardianx_report_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    toast.success('CSV export downloaded');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="page-container animate-fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
            Security Reports & Auditing
          </h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginTop: 4 }}>
            Generate, download, and review structured compliance audits from recorded telemetry.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-secondary btn-md" onClick={handlePrint} title="Print report">
            <Printer size={16} />
            Print Report
          </button>
        </div>
      </div>

      {/* Export Options */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
        <div className="glass-card glow-card" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: 'var(--radius-md)',
                background: 'rgba(0, 212, 255, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--color-cyan)',
              }}
            >
              <FileJson size={22} />
            </div>
            <div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Structured JSON Audit</h4>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Complete raw scan telemetry & indicators</p>
            </div>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--color-text-secondary)', marginBottom: 16 }}>
            Export all {total} scans including full ML features, heuristic reasons, and timestamps in standard JSON format.
          </p>
          <button className="btn btn-secondary btn-sm" onClick={handleExportJSON} style={{ width: '100%' }}>
            <Download size={14} />
            Export JSON
          </button>
        </div>

        <div className="glass-card glow-card" style={{ padding: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: 'var(--radius-md)',
                background: 'rgba(0, 230, 118, 0.12)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--color-safe)',
              }}
            >
              <FileSpreadsheet size={22} />
            </div>
            <div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Spreadsheet CSV Export</h4>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Tabular executive summaries</p>
            </div>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--color-text-secondary)', marginBottom: 16 }}>
            Export all scan records formatted for Excel, Google Sheets, or corporate SIEM ingestion.
          </p>
          <button className="btn btn-secondary btn-sm" onClick={handleExportCSV} style={{ width: '100%' }}>
            <Download size={14} />
            Export CSV
          </button>
        </div>

        <div className="glass-card glow-card" style={{ padding: 22, borderStyle: 'dashed' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: 'var(--radius-md)',
                background: 'rgba(124, 58, 237, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--color-purple)',
              }}
            >
              <Sparkles size={22} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Automated Digests</h4>
                <span className="badge badge-sm" style={{ background: 'rgba(124, 58, 237, 0.2)', color: 'var(--color-purple)' }}>
                  Coming M7
                </span>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Scheduled PDF email digests</p>
            </div>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--color-text-muted)', marginBottom: 16 }}>
            Recurring executive security briefings and weekly threat summaries sent automatically to SOC administrators.
          </p>
          <button className="btn btn-ghost btn-sm" disabled style={{ width: '100%' }}>
            Scheduled Delivery (M7)
          </button>
        </div>
      </div>
    </div>
  );
}
