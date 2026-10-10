import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  ChevronLeft,
  ChevronRight,
  Cpu,
  FileText,
  History,
  LayoutDashboard,
  LogOut,
  ScanLine,
  Settings,
  Shield,
  X,
} from 'lucide-react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '@/providers/AuthProvider';
import { useUI } from '@/providers/UIProvider';
import toast from 'react-hot-toast';

interface NavItem {
  to: string;
  icon: React.ElementType;
  label: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: 'MONITOR',
    items: [
      { to: '/dashboard',     icon: LayoutDashboard, label: 'Overview' },
      { to: '/analytics',     icon: BarChart3,       label: 'Security Analytics' },
      { to: '/threat-center', icon: AlertTriangle,   label: 'Threat Center' },
    ],
  },
  {
    title: 'ANALYZE',
    items: [
      { to: '/scan',         icon: ScanLine, label: 'URL Scanner' },
      { to: '/threat-intel', icon: Cpu,      label: 'Threat Intelligence' },
      { to: '/history',      icon: History,  label: 'Scan History' },
    ],
  },
  {
    title: 'SYSTEM',
    items: [
      { to: '/reports',  icon: FileText, label: 'Security Reports' },
      { to: '/alerts',   icon: Bell,     label: 'Alerts' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [hoveredTooltip, setHoveredTooltip] = useState<string | null>(null);
  const { user, logout } = useAuth();
  const { mobileSidebarOpen, setMobileSidebarOpen } = useUI();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    toast.success('Signed out successfully');
    navigate('/login');
  };

  const content = (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Logo */}
      <div className="sidebar-logo">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
          <Shield size={24} className="float-glow" style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: 'auto' }}
                exit={{ opacity: 0, width: 0 }}
                transition={{ duration: 0.2 }}
                style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}
              >
                <span className="sidebar-logo-text">Guardianx</span>
                <span style={{ display: 'block', fontSize: '0.62rem', color: 'var(--color-cyan)', letterSpacing: '0.08em', fontWeight: 600 }}>
                  SOC PLATFORM
                </span>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Mobile close button */}
        {mobileSidebarOpen && (
          <button
            onClick={() => setMobileSidebarOpen(false)}
            style={{ background: 'none', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer' }}
            aria-label="Close navigation"
          >
            <X size={20} />
          </button>
        )}
      </div>

      {/* Nav Sections */}
      <nav className="sidebar-nav" aria-label="Main navigation" style={{ overflowY: 'auto' }}>
        {NAV_SECTIONS.map((section) => (
          <div key={section.title} className="sidebar-section">
            {!collapsed && (
              <span className="sidebar-section-title">
                {section.title}
              </span>
            )}
            {section.items.map(({ to, icon: Icon, label }) => {
              const isActive = location.pathname === to;
              return (
                <div
                  key={to}
                  className="sidebar-link-wrap"
                  onMouseEnter={() => collapsed && setHoveredTooltip(label)}
                  onMouseLeave={() => setHoveredTooltip(null)}
                >
                  <NavLink
                    to={to}
                    onClick={() => setMobileSidebarOpen(false)}
                    className={`sidebar-link ${isActive ? 'sidebar-link-active' : ''}`}
                    aria-current={isActive ? 'page' : undefined}
                  >
                    {isActive && (
                      <motion.div
                        className="sidebar-active-pill"
                        layoutId="sidebarActivePill"
                        transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                      />
                    )}
                    <Icon size={18} style={{ flexShrink: 0 }} />
                    <AnimatePresence>
                      {!collapsed && (
                        <motion.span
                          initial={{ opacity: 0, width: 0 }}
                          animate={{ opacity: 1, width: 'auto' }}
                          exit={{ opacity: 0, width: 0 }}
                          transition={{ duration: 0.18 }}
                          style={{ overflow: 'hidden', whiteSpace: 'nowrap', zIndex: 1 }}
                        >
                          {label}
                        </motion.span>
                      )}
                    </AnimatePresence>
                  </NavLink>

                  {/* Floating tooltip when collapsed */}
                  {collapsed && hoveredTooltip === label && (
                    <div className="sidebar-tooltip animate-fade-up">
                      {label}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Bottom Section */}
      <div className="sidebar-bottom">
        {/* Backend Status Pill */}
        {!collapsed && (
          <div className="sidebar-status-pill">
            <span className="status-dot status-dot-alive" style={{ color: 'var(--color-safe)' }} />
            <Activity size={13} style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              Core Engine: Online
            </span>
          </div>
        )}

        {/* User Info */}
        {user && !collapsed && (
          <motion.div
            className="sidebar-user"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="sidebar-avatar" aria-hidden="true">
              {user.email[0].toUpperCase()}
            </div>
            <div style={{ minWidth: 0, flex: 1 }}>
              <p
                style={{
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  color: 'var(--color-text-primary)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {user.email}
              </p>
              <p style={{ fontSize: '0.7rem', color: 'var(--color-text-muted)' }}>Analyst</p>
            </div>
          </motion.div>
        )}

        {/* Logout */}
        <button
          className="sidebar-logout"
          onClick={handleLogout}
          title="Sign out"
          aria-label="Sign out"
        >
          <LogOut size={16} style={{ flexShrink: 0 }} />
          <AnimatePresence>
            {!collapsed && (
              <motion.span
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: 'auto' }}
                exit={{ opacity: 0, width: 0 }}
                transition={{ duration: 0.18 }}
                style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}
              >
                Sign Out
              </motion.span>
            )}
          </AnimatePresence>
        </button>

        {/* Collapse toggle (desktop only) */}
        <button
          className="sidebar-collapse-btn"
          onClick={() => setCollapsed((c) => !c)}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <motion.aside
        className="sidebar"
        animate={{ width: collapsed ? 64 : 240 }}
        transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
        style={{ overflow: 'hidden' }}
      >
        {content}
      </motion.aside>

      {/* Mobile Drawer */}
      <AnimatePresence>
        {mobileSidebarOpen && (
          <>
            <motion.div
              className="mobile-drawer-overlay"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setMobileSidebarOpen(false)}
            />
            <motion.aside
              className="sidebar"
              style={{
                position: 'fixed',
                left: 0,
                top: 0,
                bottom: 0,
                width: 260,
                zIndex: 1000,
                boxShadow: 'var(--shadow-lg)',
              }}
              initial={{ x: -260 }}
              animate={{ x: 0 }}
              exit={{ x: -260 }}
              transition={{ type: 'spring', damping: 28, stiffness: 300 }}
            >
              {content}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
