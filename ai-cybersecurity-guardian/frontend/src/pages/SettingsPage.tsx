import { useState } from 'react';
import { Check, Copy, Lock, Monitor } from 'lucide-react';
import { useAuth } from '@/providers/AuthProvider';
import toast from 'react-hot-toast';

export default function SettingsPage() {
  const { user } = useAuth();
  const [copied, setCopied] = useState(false);

  const handleCopyId = () => {
    if (!user?.id) return;
    navigator.clipboard.writeText(user.id);
    setCopied(true);
    toast.success('User ID copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="page-container animate-fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 900 }}>
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-text-primary)' }}>
          Platform & Security Settings
        </h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginTop: 4 }}>
          Identity management, cryptographic specifications, and user interface preferences.
        </p>
      </div>

      {/* Account Profile Card */}
      <div className="glass-card glow-card" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
          <div
            style={{
              width: 46,
              height: 46,
              borderRadius: '50%',
              background: 'var(--color-cyan-dim)',
              border: '1px solid rgba(0, 212, 255, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '1.2rem',
              fontWeight: 800,
              color: 'var(--color-cyan)',
            }}
          >
            {user?.email[0].toUpperCase() ?? 'U'}
          </div>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
              {user?.email}
            </h3>
            <span
              className="badge badge-sm"
              style={{
                background: 'rgba(0, 212, 255, 0.12)',
                color: 'var(--color-cyan)',
                border: '1px solid rgba(0, 212, 255, 0.25)',
                marginTop: 4,
              }}
            >
              Role: Security Analyst
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, borderTop: '1px solid var(--color-border)', paddingTop: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem' }}>
            <span style={{ color: 'var(--color-text-muted)' }}>Analyst ID</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--color-text-secondary)' }}>
                {user?.id ?? 'N/A'}
              </code>
              <button
                onClick={handleCopyId}
                className="btn btn-ghost btn-sm"
                style={{ padding: '3px 6px' }}
                title="Copy User ID"
              >
                {copied ? <Check size={14} style={{ color: 'var(--color-safe)' }} /> : <Copy size={14} />}
              </button>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem' }}>
            <span style={{ color: 'var(--color-text-muted)' }}>Multi-Factor Authentication (MFA)</span>
            <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.82rem' }}>Disabled (Standard Session)</span>
          </div>
        </div>
      </div>

      {/* Cryptographic & Token Specifications (M0-M5 Hardening) */}
      <div className="glass-card glow-card" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <Lock size={18} style={{ color: 'var(--color-cyan)' }} />
          <h3 style={{ fontSize: '0.95rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Production Security Controls (M0–M5)
          </h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 14 }}>
          <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid var(--color-border)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Token Signature</span>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: 4 }}>
              HMAC-SHA256 (HS256)
            </p>
            <span style={{ fontSize: '0.7rem', color: 'var(--color-safe)' }}>32-byte production secret</span>
          </div>

          <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid var(--color-border)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Access Expiry / JTI</span>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: 4 }}>
              15 Minutes (Sliding)
            </p>
            <span style={{ fontSize: '0.7rem', color: 'var(--color-safe)' }}>JTI Revocation supported</span>
          </div>

          <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid var(--color-border)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Refresh Token Rotation</span>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: 4 }}>
              7 Days / Strict Rotation
            </p>
            <span style={{ fontSize: '0.7rem', color: 'var(--color-safe)' }}>Reuse detection active</span>
          </div>

          <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'rgba(0, 0, 0, 0.2)', border: '1px solid var(--color-border)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>Correlation ID Tracing</span>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text-primary)', marginTop: 4 }}>
              X-Request-ID Header
            </p>
            <span style={{ fontSize: '0.7rem', color: 'var(--color-safe)' }}>Audit trail correlated</span>
          </div>
        </div>
      </div>

      {/* UI & Experience Preferences */}
      <div className="glass-card glow-card" style={{ padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <Monitor size={18} style={{ color: 'var(--color-cyan)' }} />
          <h3 style={{ fontSize: '0.95rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Interface & Motion
          </h3>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', lineHeight: 1.6 }}>
          Guardianx employs hardware-accelerated animations and an interactive motion cursor. On touch devices, mobile viewports, or when operating system level <code>prefers-reduced-motion</code> is active, non-essential motion and the desktop cursor automatically deactivate for accessibility and performance.
        </p>
      </div>
    </div>
  );
}
