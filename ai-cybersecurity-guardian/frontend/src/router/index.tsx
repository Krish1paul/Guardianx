import { lazy, Suspense } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from '@/providers/AuthProvider';
import { Spinner } from '@/components/ui/Spinner';
import { AppShell } from '@/components/layout/AppShell';

const LoginPage        = lazy(() => import('@/pages/LoginPage'));
const RegisterPage     = lazy(() => import('@/pages/RegisterPage'));
const DashboardPage    = lazy(() => import('@/pages/DashboardPage'));
const AnalyticsPage    = lazy(() => import('@/pages/AnalyticsPage'));
const ThreatCenterPage = lazy(() => import('@/pages/ThreatCenterPage'));
const ScannerPage      = lazy(() => import('@/pages/ScannerPage'));
const ThreatIntelPage  = lazy(() => import('@/pages/ThreatIntelPage'));
const HistoryPage      = lazy(() => import('@/pages/HistoryPage'));
const ReportsPage      = lazy(() => import('@/pages/ReportsPage'));
const AlertsPage       = lazy(() => import('@/pages/AlertsPage'));
const SettingsPage     = lazy(() => import('@/pages/SettingsPage'));

function PageLoader() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
      <Spinner size="lg" />
    </div>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();
  if (isLoading) return <PageLoader />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();
  if (isLoading) return <PageLoader />;
  if (user) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}

export function AppRouter() {
  return (
    <BrowserRouter>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          {/* Public routes */}
          <Route path="/login"    element={<PublicRoute><LoginPage /></PublicRoute>} />
          <Route path="/register" element={<PublicRoute><RegisterPage /></PublicRoute>} />

          {/* Protected routes inside AppShell */}
          <Route path="/" element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard"     element={<DashboardPage />} />
            <Route path="analytics"     element={<AnalyticsPage />} />
            <Route path="threat-center" element={<ThreatCenterPage />} />
            <Route path="incidents"     element={<ThreatCenterPage />} />
            <Route path="scan"          element={<ScannerPage />} />
            <Route path="threat-intel"  element={<ThreatIntelPage />} />
            <Route path="history"       element={<HistoryPage />} />
            <Route path="reports"       element={<ReportsPage />} />
            <Route path="alerts"        element={<AlertsPage />} />
            <Route path="settings"      element={<SettingsPage />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
