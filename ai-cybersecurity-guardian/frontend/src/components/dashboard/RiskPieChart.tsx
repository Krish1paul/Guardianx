
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { ShieldCheck } from 'lucide-react';
import type { RiskClassification } from '@/types/api';
import { RISK_COLOR, RISK_LABEL } from '@/lib/utils';

interface RiskPieChartProps {
  distribution: Record<RiskClassification, number>;
  total: number;
  isLoading: boolean;
}

const TIERS: RiskClassification[] = ['LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL'];

const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: Array<{ name: string; value: number }> }) => {
  if (active && payload?.length) {
    return (
      <div style={{
        background: 'rgba(13, 20, 38, 0.95)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: 8,
        padding: '8px 12px',
        fontSize: '0.8rem',
      }}>
        <p style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{payload[0].name}</p>
        <p style={{ color: 'var(--color-text-secondary)' }}>{payload[0].value} scans</p>
      </div>
    );
  }
  return null;
};

export function RiskPieChart({ distribution, total, isLoading }: RiskPieChartProps) {
  if (isLoading) return <Skeleton height={220} />;

  const data = TIERS
    .map((tier) => ({ name: RISK_LABEL[tier], value: distribution[tier], color: RISK_COLOR[tier] }))
    .filter((d) => d.value > 0);

  return (
    <div>
      <h3 className="chart-title">Risk Distribution</h3>
      {total === 0 ? (
        <EmptyState
          icon={<ShieldCheck size={36} />}
          title="No scan data yet"
          description="Analyze URLs to see your risk distribution"
        />
      ) : (
        <>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={52}
                outerRadius={78}
                paddingAngle={3}
                dataKey="value"
                isAnimationActive={true}
                animationBegin={100}
                animationDuration={800}
              >
                {data.map((entry, i) => (
                  <Cell key={i} fill={entry.color} stroke="transparent" />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>

          {/* Legend */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 16px', marginTop: 8 }}>
            {data.map((entry) => (
              <div key={entry.name} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: entry.color, flexShrink: 0 }} />
                <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
                  {entry.name} ({entry.value})
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
