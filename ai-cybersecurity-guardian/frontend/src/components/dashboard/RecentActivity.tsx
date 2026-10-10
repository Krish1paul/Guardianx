import { motion, type Variants } from 'framer-motion';
import { Clock, ScanLine } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import type { URLScanSummary } from '@/types/api';
import { RiskBadge } from '@/components/ui/Badge';
import { EmptyState } from '@/components/ui/EmptyState';
import { SkeletonCard } from '@/components/ui/Skeleton';
import { timeAgo, truncateUrl } from '@/lib/utils';

interface RecentActivityProps {
  items: URLScanSummary[];
  isLoading: boolean;
}

const listVariants: Variants = {
  enter: { transition: { staggerChildren: 0.06 } },
};

const itemVariants: Variants = {
  initial: { opacity: 0, x: -12 },
  enter:   { opacity: 1, x: 0, transition: { duration: 0.3, ease: 'easeOut' } },
};

export function RecentActivity({ items, isLoading }: RecentActivityProps) {
  const navigate = useNavigate();

  return (
    <div>
      <h3 className="chart-title">Recent Activity</h3>

      {isLoading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[0, 1, 2].map((i) => <SkeletonCard key={i} lines={2} />)}
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={<ScanLine size={36} />}
          title="No recent scans"
          description="Your recently analyzed URLs will appear here"
          action={{ label: 'Analyze a URL', onClick: () => navigate('/scan') }}
        />
      ) : (
        <motion.div
          variants={listVariants}
          initial="initial"
          animate="enter"
          style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
        >
          {items.map((item) => (
            <motion.div
              key={item.id}
              variants={itemVariants}
              className="recent-item glass-card"
              onClick={() => navigate('/history')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === 'Enter') navigate('/history'); }}
              title={item.url}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <p className="recent-url">{truncateUrl(item.url, 55)}</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                  <Clock size={11} style={{ color: 'var(--color-text-muted)', flexShrink: 0 }} aria-hidden="true" />
                  <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                    {timeAgo(item.created_at)}
                  </span>
                  <span style={{ fontSize: '0.68rem', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    · {item.analyzer_version}
                  </span>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  fontSize: '0.9rem',
                  color: item.risk_score > 75 ? 'var(--color-critical)' :
                         item.risk_score > 50 ? 'var(--color-danger)' :
                         item.risk_score > 25 ? 'var(--color-warning)' : 'var(--color-safe)',
                }}>
                  {item.risk_score}
                </span>
                <RiskBadge classification={item.classification} size="sm" />
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}
    </div>
  );
}
