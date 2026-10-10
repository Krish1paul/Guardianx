import { useState, useRef, useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Bell, CheckCircle2, ChevronRight, ShieldAlert } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useHistory } from '@/hooks/useHistory';
import { RISK_COLOR, timeAgo } from '@/lib/utils';
import type { RiskClassification, URLScanSummary } from '@/types/api';

export function NotificationsPopover() {
  const [open, setOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  // Fetch recent scans to derive real alert events
  const { data } = useHistory(0);
  const items: URLScanSummary[] = data?.items ?? [];
  const threats = items.filter((s: URLScanSummary) => s.classification === 'CRITICAL' || s.classification === 'HIGH_RISK');

  // Close when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  const handleNavigate = (path: string) => {
    setOpen(false);
    navigate(path);
  };

  return (
    <div ref={popoverRef} style={{ position: 'relative' }}>
      <button
        className="topbar-icon-btn"
        onClick={() => setOpen((prev) => !prev)}
        aria-label="Security alerts"
        title="Security alerts and threat notifications"
      >
        <Bell size={16} />
        {threats.length > 0 && (
          <span className="notification-badge" aria-label={`${threats.length} critical threats`}>
            {threats.length}
          </span>
        )}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            className="user-menu-dropdown"
            style={{ width: 320, padding: 0 }}
            initial={{ opacity: 0, y: 8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            transition={{ duration: 0.15 }}
          >
            {/* Popover Header */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 14px',
                borderBottom: '1px solid var(--color-border)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <ShieldAlert size={16} style={{ color: threats.length > 0 ? 'var(--color-critical)' : 'var(--color-safe)' }} />
                <span style={{ fontSize: '0.82rem', fontWeight: 700 }}>Security Alerts</span>
              </div>
              <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
                {threats.length} active
              </span>
            </div>

            {/* List */}
            <div style={{ maxHeight: 280, overflowY: 'auto' }}>
              {threats.length === 0 ? (
                <div style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--color-text-muted)' }}>
                  <CheckCircle2 size={24} style={{ color: 'var(--color-safe)', margin: '0 auto 8px', opacity: 0.8 }} />
                  <p style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-text-primary)' }}>All Clear</p>
                  <p style={{ fontSize: '0.72rem', marginTop: 2 }}>No high or critical threats found in recent scans</p>
                </div>
              ) : (
                threats.map((scan: URLScanSummary) => (
                  <div
                    key={scan.id}
                    onClick={() => handleNavigate(`/history`)}
                    style={{
                      padding: '10px 14px',
                      borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 4,
                      transition: 'background var(--transition-fast)',
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background = 'rgba(255, 255, 255, 0.04)';
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background = 'transparent';
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span
                        className="badge badge-sm"
                        style={{
                          background: `${RISK_COLOR[scan.classification as RiskClassification]}20`,
                          color: RISK_COLOR[scan.classification as RiskClassification],
                        }}
                      >
                        {scan.classification}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>
                        {timeAgo(scan.created_at)}
                      </span>
                    </div>
                    <p
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.75rem',
                        color: 'var(--color-text-primary)',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {scan.url}
                    </p>
                  </div>
                ))
              )}
            </div>

            {/* Footer */}
            <div
              style={{
                padding: '8px 12px',
                borderTop: '1px solid var(--color-border)',
                background: 'rgba(0, 0, 0, 0.2)',
                display: 'flex',
                justifyContent: 'space-between',
              }}
            >
              <button
                onClick={() => handleNavigate('/threat-center')}
                className="user-menu-item"
                style={{ padding: '4px 8px', fontSize: '0.75rem', color: 'var(--color-cyan)', justifyContent: 'center' }}
              >
                Open Threat Center
                <ChevronRight size={14} />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
