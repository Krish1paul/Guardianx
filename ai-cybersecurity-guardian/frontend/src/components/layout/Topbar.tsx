import { useState, useRef, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  ChevronDown,
  FileText,
  LogOut,
  Menu,
  Plus,
  Settings,
} from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { healthAPI } from '@/lib/api';
import { useAuth } from '@/providers/AuthProvider';
import { useUI } from '@/providers/UIProvider';
import { NotificationsPopover } from './NotificationsPopover';
import toast from 'react-hot-toast';

const PAGE_TITLES: Record<string, { title: string; section: string }> = {
  '/dashboard':     { title: 'Security Command Center', section: 'MONITOR' },
  '/analytics':     { title: 'Security Analytics',       section: 'MONITOR' },
  '/threat-center': { title: 'Active Threat Center',    section: 'MONITOR' },
  '/scan':          { title: 'URL Threat Analyzer',      section: 'ANALYZE' },
  '/threat-intel':  { title: 'Threat Intelligence Feeds', section: 'ANALYZE' },
  '/history':       { title: 'Historical Scan Records',  section: 'ANALYZE' },
  '/reports':       { title: 'Security Audit Reports',  section: 'SYSTEM' },
  '/alerts':        { title: 'Security Alerts & Events', section: 'SYSTEM' },
  '/settings':      { title: 'Platform Settings',       section: 'SYSTEM' },
};

export function Topbar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { setMobileSidebarOpen, setQuickScanOpen } = useUI();
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);

  const meta = PAGE_TITLES[location.pathname] ?? { title: 'Guardianx', section: 'SOC' };

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: healthAPI.ready,
    refetchInterval: 30_000,
    retry: false,
  });

  const isHealthy = health?.status === 'ready' || health?.status === 'ok';

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false);
      }
    };
    if (userMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [userMenuOpen]);

  const handleLogout = async () => {
    setUserMenuOpen(false);
    await logout();
    toast.success('Signed out successfully');
    navigate('/login');
  };

  return (
    <header className="topbar">
      {/* Left: Mobile hamburger + breadcrumb title */}
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <button
          className="mobile-nav-toggle"
          onClick={() => setMobileSidebarOpen((prev) => !prev)}
          aria-label="Toggle navigation menu"
        >
          <Menu size={20} />
        </button>

        <div className="topbar-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-cyan)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              {meta.section}
            </span>
            <span style={{ color: 'var(--color-border)', fontSize: '0.8rem' }}>/</span>
            <h1 style={{ fontSize: '0.98rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
              {meta.title}
            </h1>
          </div>
        </div>
      </div>

      {/* Right: Command center actions */}
      <div className="topbar-actions">
        {/* Quick Scan CTA */}
        <button
          className="topbar-quick-btn"
          onClick={() => setQuickScanOpen(true)}
          title="Quick Threat Scan (⌘K)"
        >
          <Plus size={15} />
          <span>Quick Scan</span>
          <span className="topbar-kbd">⌘K</span>
        </button>

        {/* Notifications / Alerts */}
        <NotificationsPopover />

        {/* Backend health indicator */}
        <div
          className="topbar-health"
          title={isHealthy ? 'Backend online — Postgres Healthy, Engine ML-v1 Ready' : 'Backend unreachable'}
        >
          <span
            className={isHealthy ? 'status-dot status-dot-alive' : 'status-dot status-dot-offline'}
            aria-label={isHealthy ? 'Backend online' : 'Backend offline'}
            style={{ color: isHealthy ? 'var(--color-safe)' : 'var(--color-critical)' }}
          />
          <Activity size={14} style={{ color: 'var(--color-text-muted)' }} aria-hidden="true" />
          <span style={{ fontSize: '0.75rem', color: isHealthy ? 'var(--color-safe)' : 'var(--color-critical)', fontWeight: 600 }}>
            {isHealthy ? 'Online' : 'Offline'}
          </span>
        </div>

        {/* User profile dropdown */}
        {user && (
          <div ref={userMenuRef} style={{ position: 'relative' }}>
            <button
              onClick={() => setUserMenuOpen((prev) => !prev)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid var(--color-border)',
                borderRadius: 'var(--radius-full)',
                padding: '3px 10px 3px 3px',
                cursor: 'pointer',
                color: 'var(--color-text-primary)',
              }}
              aria-label="User account menu"
            >
              <div className="sidebar-avatar" style={{ width: 26, height: 26, fontSize: '0.7rem' }}>
                {user.email[0].toUpperCase()}
              </div>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, maxWidth: 110, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user.email.split('@')[0]}
              </span>
              <ChevronDown size={14} style={{ color: 'var(--color-text-muted)' }} />
            </button>

            <AnimatePresence>
              {userMenuOpen && (
                <motion.div
                  className="user-menu-dropdown"
                  initial={{ opacity: 0, y: 8, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: 6, scale: 0.98 }}
                  transition={{ duration: 0.15 }}
                >
                  <div style={{ padding: '8px 12px 6px' }}>
                    <p style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--color-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {user.email}
                    </p>
                    <p style={{ fontSize: '0.7rem', color: 'var(--color-cyan)', marginTop: 2 }}>Security Analyst</p>
                  </div>
                  <div className="user-menu-divider" />

                  <button
                    className="user-menu-item"
                    onClick={() => {
                      setUserMenuOpen(false);
                      navigate('/settings');
                    }}
                  >
                    <Settings size={15} />
                    <span>Settings</span>
                  </button>

                  <button
                    className="user-menu-item"
                    onClick={() => {
                      setUserMenuOpen(false);
                      navigate('/reports');
                    }}
                  >
                    <FileText size={15} />
                    <span>Security Reports</span>
                  </button>

                  <div className="user-menu-divider" />

                  <button
                    className="user-menu-item"
                    style={{ color: 'var(--color-critical)' }}
                    onClick={handleLogout}
                  >
                    <LogOut size={15} />
                    <span>Sign Out</span>
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}
      </div>
    </header>
  );
}
