import { motion, type Variants } from 'framer-motion';
import { RefreshCw, Server } from 'lucide-react';
import { Suspense } from 'react';
import { useDashboardStats, useRecentScans } from '@/hooks/useDashboardStats';
import { SecurityHero } from '@/components/dashboard/SecurityHero';
import { MetricStrip } from '@/components/dashboard/MetricStrip';
import { RiskPieChart } from '@/components/dashboard/RiskPieChart';
import { ScoreHistogram } from '@/components/dashboard/ScoreHistogram';
import { RecentActivity } from '@/components/dashboard/RecentActivity';
import { ThreatIntelPanel } from '@/components/dashboard/ThreatIntelPanel';
import { Card } from '@/components/ui/Card';
import { ErrorState } from '@/components/ui/EmptyState';
import { Skeleton } from '@/components/ui/Skeleton';
import { scoreToClassification } from '@/lib/utils';

const sectionVariants: Variants = {
  initial: { opacity: 0 },
  enter:   { opacity: 1, transition: { staggerChildren: 0.08 } },
};

const sectionItem: Variants = {
  initial: { opacity: 0, y: 16 },
  enter:   { opacity: 1, y: 0, transition: { duration: 0.35, ease: 'easeOut' } },
};

function DashboardSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <Skeleton height={220} borderRadius="var(--radius-lg)" />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        {[0,1,2,3].map((i) => <Skeleton key={i} height={100} />)}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Skeleton height={250} />
        <Skeleton height={250} />
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { stats, isLoading, isError, refetch } = useDashboardStats();
  const { data: recent, isLoading: recentLoading } = useRecentScans(5);

  if (isError) {
    return (
      <div className="page-container">
        <Card>
          <ErrorState
            icon={<Server size={40} />}
            title="Could not load dashboard"
            description="The backend service appears to be unavailable. Make sure the API server is running."
            action={{ label: 'Retry', onClick: () => void refetch() }}
          />
        </Card>
      </div>
    );
  }

  const classification = stats.total > 0 ? scoreToClassification(stats.avgScore) : 'LOW_RISK';
  const lastScanAt = recent?.items?.[0]?.created_at ?? null;

  return (
    <div className="page-container">
      {isLoading ? (
        <DashboardSkeleton />
      ) : (
        <motion.div
          variants={sectionVariants}
          initial="initial"
          animate="enter"
          style={{ display: 'flex', flexDirection: 'column', gap: 24 }}
        >
          {/* A — Security Command Center Hero */}
          <motion.div variants={sectionItem}>
            <SecurityHero
              avgScore={stats.avgScore}
              classification={classification}
              totalScans={stats.total}
              lastScanAt={lastScanAt}
              isLoading={isLoading}
            />
          </motion.div>

          {/* B — Metric Strip */}
          <motion.div variants={sectionItem}>
            <MetricStrip
              critical={stats.critical}
              total={stats.total}
              safe={stats.safe}
              avgScore={stats.avgScore}
              isLoading={isLoading}
            />
          </motion.div>

          {/* C — Charts row */}
          <motion.div
            variants={sectionItem}
            style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}
          >
            <Card>
              <Suspense fallback={<Skeleton height={220} />}>
                <RiskPieChart
                  distribution={stats.distribution}
                  total={stats.total}
                  isLoading={isLoading}
                />
              </Suspense>
            </Card>
            <Card>
              <Suspense fallback={<Skeleton height={220} />}>
                <ScoreHistogram
                  histogram={stats.histogram}
                  total={stats.total}
                  isLoading={isLoading}
                />
              </Suspense>
            </Card>
          </motion.div>

          {/* D — Activity + TI Panel */}
          <motion.div
            variants={sectionItem}
            style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}
          >
            <Card>
              <RecentActivity items={recent?.items ?? []} isLoading={recentLoading} />
            </Card>
            <Card>
              <ThreatIntelPanel items={recent?.items ?? []} isLoading={recentLoading} />
            </Card>
          </motion.div>

          {/* Refresh note */}
          {stats.total > 0 && (
            <motion.div variants={sectionItem}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--color-text-muted)', fontSize: '0.72rem' }}>
                <RefreshCw size={11} aria-hidden="true" />
                Dashboard refreshes automatically every 30s
              </div>
            </motion.div>
          )}
        </motion.div>
      )}
    </div>
  );
}
