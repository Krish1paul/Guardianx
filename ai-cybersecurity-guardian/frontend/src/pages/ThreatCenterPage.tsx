import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertCircle,
  AlertOctagon,
  Calendar,
  CheckCircle2,
  ChevronRight,
  Clock,
  FileCode,
  Globe,
  Layers,
  Mail,
  RefreshCw,
  ScanLine,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Tag,
  Zap,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useIncidents, useIncident, useIncidentTimeline, useUpdateIncidentStatus } from '@/hooks/useIncidents';
import { Modal } from '@/components/ui/Modal';
import { Spinner } from '@/components/ui/Spinner';
import { Skeleton } from '@/components/ui/Skeleton';
import {
  RISK_COLOR,
  RISK_BG,
  RISK_LABEL,
  STATUS_COLOR,
  STATUS_LABEL,
  STAGE_LABEL,
  timeAgo,
  formatDate,
} from '@/lib/utils';
import type { IncidentIndicator, IncidentStatus, IncidentSummary, RiskClassification } from '@/types/api';

const STAGE_ICON: Record<string, typeof ShieldAlert> = {
  RECONNAISSANCE: Globe,
  INITIAL_ACCESS: Mail,
  CREDENTIAL_HARVESTING: ShieldAlert,
  MALICIOUS_DELIVERY: FileCode,
  EVASION_EXECUTION: Zap,
  SOCIAL_ENGINEERING: AlertCircle,
  MULTI_VECTOR_CAMPAIGN: Layers,
};

export default function ThreatCenterPage() {
  const [selectedStatus, setSelectedStatus] = useState<IncidentStatus | 'ALL'>('ALL');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const navigate = useNavigate();

  const statusFilter = selectedStatus === 'ALL' ? undefined : selectedStatus;
  const { data, isLoading, isFetching, refetch } = useIncidents(statusFilter);
  const { data: incidentDetail, isLoading: detailLoading } = useIncident(selectedIncidentId);
  const { data: timelineData, isLoading: timelineLoading } = useIncidentTimeline(selectedIncidentId);
  const updateStatusMutation = useUpdateIncidentStatus();

  const items: IncidentSummary[] = data?.items ?? [];
  const statusCounts = data?.status_counts ?? {};

  // Overview metrics
  const activeCount = (statusCounts['OPEN'] ?? 0) + (statusCounts['INVESTIGATING'] ?? 0);
  const criticalCount = items.filter((i) => i.severity === 'CRITICAL').length;
  const multiVectorCount = items.filter((i) => i.attack_stage === 'MULTI_VECTOR_CAMPAIGN' || i.event_count > 1).length;
  const resolvedCount = statusCounts['RESOLVED'] ?? 0;

  const handleStatusChange = async (incidentId: string, newStatus: IncidentStatus) => {
    try {
      await updateStatusMutation.mutateAsync({ id: incidentId, status: newStatus });
    } catch {
      // Handled by query client
    }
  };

  return (
    <div className="page-container animate-fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2 style={{ fontSize: '1.45rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
              Security Intelligence & Incident Center
            </h2>
            {activeCount > 0 && (
              <span
                className="badge"
                style={{
                  background: 'rgba(255, 45, 85, 0.15)',
                  color: 'var(--color-critical)',
                  border: '1px solid rgba(255, 45, 85, 0.3)',
                  fontWeight: 700,
                }}
              >
                {activeCount} Active {activeCount === 1 ? 'Incident' : 'Incidents'}
              </span>
            )}
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginTop: 4 }}>
            Deterministic cross-vector correlation combining URL telemetry, phishing messages, and file payloads into unified attack chains.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className="btn btn-secondary btn-md"
            onClick={() => void refetch()}
            disabled={isFetching}
            title="Refresh incident intelligence"
          >
            <RefreshCw size={15} className={isFetching ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button className="btn btn-primary btn-md" onClick={() => navigate('/scan')}>
            <ScanLine size={16} />
            Scan New Vector
          </button>
        </div>
      </div>

      {/* KPI Metric Strip */}
      <div className="metric-strip" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
        <div className="metric-card glass-card glow-card" data-threat={activeCount > 0 ? 'CRITICAL' : 'LOW_RISK'}>
          <div className="metric-icon-wrap metric-icon-critical">
            <AlertOctagon size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-label">Active Incidents</span>
            <span className="metric-value metric-value-critical">{isLoading ? '—' : activeCount}</span>
          </div>
        </div>

        <div className="metric-card glass-card glow-card" data-threat={criticalCount > 0 ? 'CRITICAL' : 'LOW_RISK'}>
          <div className="metric-icon-wrap metric-icon-critical">
            <ShieldAlert size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-label">Critical Threats</span>
            <span className="metric-value" style={{ color: 'var(--color-critical)' }}>
              {isLoading ? '—' : criticalCount}
            </span>
          </div>
        </div>

        <div className="metric-card glass-card glow-card" data-threat={multiVectorCount > 0 ? 'HIGH_RISK' : 'LOW_RISK'}>
          <div className="metric-icon-wrap" style={{ background: 'rgba(255, 171, 0, 0.12)', color: 'var(--color-warning)' }}>
            <Layers size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-label">Correlated Chains</span>
            <span className="metric-value" style={{ color: 'var(--color-warning)' }}>
              {isLoading ? '—' : multiVectorCount}
            </span>
          </div>
        </div>

        <div className="metric-card glass-card glow-card">
          <div className="metric-icon-wrap metric-icon-safe">
            <ShieldCheck size={20} />
          </div>
          <div className="metric-info">
            <span className="metric-label">Resolved Incidents</span>
            <span className="metric-value metric-value-safe">{isLoading ? '—' : resolvedCount}</span>
          </div>
        </div>
      </div>

      {/* Filter Tabs */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          borderBottom: '1px solid var(--color-border)',
          paddingBottom: 10,
          overflowX: 'auto',
        }}
      >
        {(['ALL', 'OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'] as const).map((tab) => {
          const isActive = selectedStatus === tab;
          const count =
            tab === 'ALL'
              ? data?.total ?? 0
              : statusCounts[tab] ?? 0;

          return (
            <button
              key={tab}
              onClick={() => setSelectedStatus(tab)}
              className="btn btn-sm"
              style={{
                background: isActive ? 'var(--color-surface-hover)' : 'transparent',
                color: isActive ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
                border: isActive ? '1px solid var(--color-border-glow)' : '1px solid transparent',
                borderRadius: 'var(--radius-md)',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                fontWeight: isActive ? 700 : 500,
                padding: '6px 14px',
              }}
            >
              <span>{tab === 'ALL' ? 'All Incidents' : STATUS_LABEL[tab] || tab}</span>
              <span
                style={{
                  fontSize: '0.75rem',
                  padding: '1px 6px',
                  borderRadius: 10,
                  background: isActive ? 'rgba(0, 212, 255, 0.15)' : 'var(--color-surface)',
                  color: isActive ? 'var(--color-cyan)' : 'var(--color-text-muted)',
                }}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Incidents List */}
      {isLoading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} height={110} borderRadius="var(--radius-lg)" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <div className="glass-card" style={{ padding: 56, textAlign: 'center' }}>
          <div
            style={{
              width: 56,
              height: 56,
              borderRadius: '50%',
              background: 'rgba(0, 230, 118, 0.1)',
              border: '1px solid rgba(0, 230, 118, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 16px',
            }}
          >
            <CheckCircle2 size={30} style={{ color: 'var(--color-safe)' }} />
          </div>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            No Incidents Found
          </h3>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-muted)', maxWidth: 460, margin: '8px auto 20px' }}>
            {selectedStatus === 'ALL'
              ? 'No security incidents have been recorded or correlated yet. Run URL, message, or file scans to populate correlation telemetry.'
              : `No incidents with status "${STATUS_LABEL[selectedStatus] ?? selectedStatus}" were found.`}
          </p>
          <button className="btn btn-primary btn-md" onClick={() => navigate('/scan')}>
            <ScanLine size={16} />
            Start Vector Scan
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {items.map((incident: IncidentSummary) => {
            const StageIcon = STAGE_ICON[incident.attack_stage] || ShieldAlert;

            return (
              <motion.div
                key={incident.id}
                className="glass-card glow-card"
                data-threat={incident.severity}
                style={{
                  borderLeft: `4px solid ${RISK_COLOR[incident.severity as RiskClassification]}`,
                  padding: '18px 22px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12,
                  cursor: 'pointer',
                  transition: 'transform 0.15s ease, box-shadow 0.15s ease',
                }}
                onClick={() => setSelectedIncidentId(incident.id)}
                whileHover={{ y: -2 }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <span
                      className="badge"
                      style={{
                        background: RISK_BG[incident.severity as RiskClassification],
                        color: RISK_COLOR[incident.severity as RiskClassification],
                        border: `1px solid ${RISK_COLOR[incident.severity as RiskClassification]}40`,
                        fontWeight: 700,
                        fontSize: '0.75rem',
                      }}
                    >
                      {RISK_LABEL[incident.severity as RiskClassification] ?? incident.severity}
                    </span>

                    <span
                      className="badge"
                      style={{
                        background: 'rgba(0, 212, 255, 0.08)',
                        color: 'var(--color-cyan)',
                        border: '1px solid rgba(0, 212, 255, 0.25)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 5,
                        fontSize: '0.75rem',
                      }}
                    >
                      <StageIcon size={12} />
                      {STAGE_LABEL[incident.attack_stage] ?? incident.attack_stage}
                    </span>

                    <span
                      className="badge"
                      style={{
                        background: `${STATUS_COLOR[incident.status] ?? 'var(--color-text-muted)'}15`,
                        color: STATUS_COLOR[incident.status] ?? 'var(--color-text-muted)',
                        border: `1px solid ${STATUS_COLOR[incident.status] ?? 'var(--color-text-muted)'}40`,
                        fontSize: '0.75rem',
                        fontWeight: 600,
                      }}
                    >
                      {STATUS_LABEL[incident.status] ?? incident.status}
                    </span>

                    <span
                      style={{
                        fontSize: '0.75rem',
                        color: 'var(--color-text-muted)',
                        fontFamily: 'monospace',
                      }}
                    >
                      #{incident.id.slice(0, 8)}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Threat Score</span>
                      <div style={{ fontSize: '1.2rem', fontWeight: 800, color: RISK_COLOR[incident.severity as RiskClassification] }}>
                        {incident.risk_score ?? incident.threat_score ?? 0}
                        <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', fontWeight: 400 }}> / 100</span>
                      </div>
                    </div>

                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedIncidentId(incident.id);
                      }}
                      style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      Inspect Chain
                      <ChevronRight size={14} />
                    </button>
                  </div>
                </div>

                {/* Title */}
                <div>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                    {incident.title}
                  </h3>
                </div>

                {/* Footer Metadata Strip */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 18,
                    flexWrap: 'wrap',
                    fontSize: '0.8rem',
                    color: 'var(--color-text-muted)',
                    borderTop: '1px solid rgba(255, 255, 255, 0.05)',
                    paddingTop: 8,
                  }}
                >
                  <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Layers size={13} style={{ color: 'var(--color-cyan)' }} />
                    <strong style={{ color: 'var(--color-text-secondary)' }}>{incident.event_count}</strong> correlated {incident.event_count === 1 ? 'event' : 'events'}
                  </span>

                  <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Clock size={13} />
                    First seen {timeAgo(incident.created_at)}
                  </span>

                  <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Calendar size={13} />
                    Updated {timeAgo(incident.updated_at ?? incident.last_seen ?? incident.created_at)}
                  </span>

                  {incident.confidence > 0 && (
                    <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Shield size={13} style={{ color: 'var(--color-safe)' }} />
                      Confidence: {Math.round(incident.confidence * 100)}%
                    </span>
                  )}
                </div>
              </motion.div>
            );
          })}
        </div>
      )}

      {/* Incident Detail & Attack Chain Modal */}
      <Modal
        isOpen={Boolean(selectedIncidentId)}
        onClose={() => setSelectedIncidentId(null)}
        title={incidentDetail?.title ?? 'Attack Chain Investigation'}
        maxWidth="900px"
      >
        {detailLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}>
            <Spinner size="lg" />
          </div>
        ) : incidentDetail ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
            {/* Top Severity & Status Bar */}
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 12,
                background: 'var(--color-surface)',
                padding: '14px 18px',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--color-border)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <span
                  className="badge"
                  style={{
                    background: RISK_BG[incidentDetail.severity as RiskClassification],
                    color: RISK_COLOR[incidentDetail.severity as RiskClassification],
                    fontWeight: 800,
                  }}
                >
                  {RISK_LABEL[incidentDetail.severity as RiskClassification] ?? incidentDetail.severity}
                </span>

                <span
                  className="badge"
                  style={{
                    background: 'rgba(0, 212, 255, 0.1)',
                    color: 'var(--color-cyan)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                  }}
                >
                  <Layers size={13} />
                  {STAGE_LABEL[incidentDetail.attack_stage] ?? incidentDetail.attack_stage}
                </span>

                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)' }}>
                  Confidence: {Math.round(incidentDetail.confidence * 100)}%
                </span>
              </div>

              {/* Status Selector */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', fontWeight: 600 }}>Status:</span>
                <select
                  value={incidentDetail.status}
                  onChange={(e) => handleStatusChange(incidentDetail.id, e.target.value as IncidentStatus)}
                  className="input"
                  style={{
                    padding: '4px 10px',
                    fontSize: '0.82rem',
                    background: 'var(--color-surface-hover)',
                    color: STATUS_COLOR[incidentDetail.status] ?? 'var(--color-text-primary)',
                    fontWeight: 700,
                    cursor: 'pointer',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--color-border)',
                  }}
                  disabled={updateStatusMutation.isPending}
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                </select>
              </div>
            </div>

            {/* Score & Timing Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
              <div className="glass-card" style={{ padding: '12px 16px' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Threat Score</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 800, color: RISK_COLOR[incidentDetail.severity as RiskClassification] }}>
                  {incidentDetail.risk_score ?? incidentDetail.threat_score ?? 0} / 100
                </div>
              </div>
              <div className="glass-card" style={{ padding: '12px 16px' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Correlated Events</span>
                <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-cyan)' }}>
                  {incidentDetail.event_count}
                </div>
              </div>
              <div className="glass-card" style={{ padding: '12px 16px' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>First Detected</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text-primary)', marginTop: 4 }}>
                  {formatDate(incidentDetail.created_at)}
                </div>
              </div>
              <div className="glass-card" style={{ padding: '12px 16px' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>Last Activity</span>
                <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text-primary)', marginTop: 4 }}>
                  {formatDate(incidentDetail.updated_at ?? incidentDetail.last_seen ?? incidentDetail.created_at)}
                </div>
              </div>
            </div>

            {/* Indicators Section */}
            {incidentDetail.indicators && incidentDetail.indicators.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--color-text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Tag size={15} style={{ color: 'var(--color-cyan)' }} />
                  Correlated Indicators of Compromise (IOCs)
                </h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {incidentDetail.indicators.map((ioc: IncidentIndicator, idx: number) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                        background: 'var(--color-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '4px 10px',
                        fontSize: '0.8rem',
                      }}
                    >
                      <span style={{ color: 'var(--color-cyan)', fontWeight: 700, textTransform: 'uppercase', fontSize: '0.7rem' }}>
                        {ioc.indicator_type}:
                      </span>
                      <span style={{ fontFamily: 'monospace', color: 'var(--color-text-primary)' }}>
                        {ioc.indicator_value}
                      </span>
                      {ioc.frequency > 1 && (
                        <span
                          style={{
                            background: 'rgba(255, 171, 0, 0.15)',
                            color: 'var(--color-warning)',
                            borderRadius: 10,
                            padding: '1px 6px',
                            fontSize: '0.7rem',
                            fontWeight: 700,
                          }}
                        >
                          ×{ioc.frequency}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Explainable Correlation Reasons */}
            {incidentDetail.explainable_reasons && incidentDetail.explainable_reasons.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--color-text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <ShieldAlert size={15} style={{ color: 'var(--color-warning)' }} />
                  Explainable Correlation Signals
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {incidentDetail.explainable_reasons.map((reason, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: 'var(--color-surface)',
                        border: '1px solid var(--color-border)',
                        borderRadius: 'var(--radius-md)',
                        padding: '10px 14px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <span style={{ fontWeight: 700, color: 'var(--color-text-primary)', fontSize: '0.85rem' }}>
                          {reason.title}
                        </span>
                        {reason.explanation && (
                          <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginTop: 2 }}>
                            {reason.explanation}
                          </p>
                        )}
                      </div>
                      <span
                        className="badge"
                        style={{
                          background: 'rgba(255, 45, 85, 0.12)',
                          color: 'var(--color-critical)',
                          fontWeight: 700,
                        }}
                      >
                        +{reason.score_contribution} pts
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Chronological Attack Chain Timeline */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--color-text-primary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Layers size={16} style={{ color: 'var(--color-cyan)' }} />
                Attack Chain Timeline (Chronological)
              </h4>

              {timelineLoading ? (
                <div style={{ padding: '20px 0', textAlign: 'center' }}>
                  <Spinner size="md" />
                </div>
              ) : timelineData && timelineData.events.length > 0 ? (
                <div
                  style={{
                    position: 'relative',
                    paddingLeft: 26,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 16,
                  }}
                >
                  {/* Vertical Timeline Line */}
                  <div
                    style={{
                      position: 'absolute',
                      left: 10,
                      top: 10,
                      bottom: 10,
                      width: 2,
                      background: 'var(--color-border-glow)',
                    }}
                  />

                  {(timelineData?.events ?? []).map((event, idx) => {
                    const typeLower = event.event_type.toLowerCase();
                    const isUrl = typeLower.includes('url');
                    const isMsg = typeLower.includes('message');

                    const Icon = isUrl ? Globe : isMsg ? Mail : FileCode;
                    const eventTitle = isUrl ? 'URL Scan' : isMsg ? 'Message Phishing Scan' : 'Static File Inspection';

                    return (
                      <div
                        key={event.id}
                        style={{
                          position: 'relative',
                          background: 'var(--color-surface)',
                          border: '1px solid var(--color-border)',
                          borderRadius: 'var(--radius-md)',
                          padding: '12px 16px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 8,
                        }}
                      >
                        {/* Timeline Node Icon */}
                        <div
                          style={{
                            position: 'absolute',
                            left: -24,
                            top: 14,
                            width: 18,
                            height: 18,
                            borderRadius: '50%',
                            background: 'var(--color-bg)',
                            border: '2px solid var(--color-cyan)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            zIndex: 2,
                          }}
                        >
                          <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--color-cyan)' }} />
                        </div>

                        {/* Event Header */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span
                              style={{
                                fontSize: '0.75rem',
                                fontWeight: 800,
                                color: 'var(--color-cyan)',
                                background: 'rgba(0, 212, 255, 0.1)',
                                padding: '2px 6px',
                                borderRadius: 4,
                              }}
                            >
                              Step {idx + 1}
                            </span>
                            <Icon size={15} style={{ color: 'var(--color-text-secondary)' }} />
                            <strong style={{ fontSize: '0.85rem', color: 'var(--color-text-primary)' }}>
                              {eventTitle}
                            </strong>
                          </div>

                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            {event.risk_score !== null && event.risk_score !== undefined && (
                              <span
                                className="badge"
                                style={{
                                  background: 'rgba(255, 45, 85, 0.1)',
                                  color: 'var(--color-critical)',
                                  fontWeight: 700,
                                  fontSize: '0.75rem',
                                }}
                              >
                                Risk Score: {event.risk_score}
                              </span>
                            )}
                            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                              {timeAgo(event.created_at)}
                            </span>
                          </div>
                        </div>

                        {/* Event Correlation Reason */}
                        <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', margin: 0 }}>
                          {event.relationship_reason}
                        </p>

                        {/* Item Details Box */}
                        {event.summary && (
                          <div
                            style={{
                              background: 'rgba(0, 0, 0, 0.2)',
                              border: '1px solid rgba(255, 255, 255, 0.05)',
                              borderRadius: 'var(--radius-sm)',
                              padding: '6px 10px',
                              fontSize: '0.75rem',
                              fontFamily: 'monospace',
                              color: 'var(--color-text-muted)',
                              overflowX: 'auto',
                            }}
                          >
                            <div>Target: {event.summary}</div>
                            {event.classification && <div>Classification: {event.classification}</div>}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)', padding: '8px 0' }}>
                  No timeline sequence events available.
                </div>
              )}
            </div>

            {/* Modal Actions Footer */}
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                borderTop: '1px solid var(--color-border)',
                paddingTop: 14,
                marginTop: 4,
              }}
            >
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                ID: {incidentDetail.id}
              </span>

              <div style={{ display: 'flex', gap: 8 }}>
                {incidentDetail.status !== 'RESOLVED' && (
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleStatusChange(incidentDetail.id, 'RESOLVED')}
                    disabled={updateStatusMutation.isPending}
                    style={{ color: 'var(--color-safe)' }}
                  >
                    <CheckCircle2 size={14} />
                    Mark Resolved
                  </button>
                )}
                <button className="btn btn-secondary btn-sm" onClick={() => setSelectedIncidentId(null)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
