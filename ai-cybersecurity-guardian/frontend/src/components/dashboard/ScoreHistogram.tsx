import {
  Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis
} from 'recharts';
import { Skeleton } from '@/components/ui/Skeleton';
import { EmptyState } from '@/components/ui/EmptyState';
import { BarChart3 } from 'lucide-react';

interface HistogramBucket { label: string; count: number; }

interface ScoreHistogramProps {
  histogram: HistogramBucket[];
  total: number;
  isLoading: boolean;
}

const BUCKET_COLORS = [
  'var(--color-safe)',
  'var(--color-warning)',
  'var(--color-danger)',
  'var(--color-critical)',
];

const CustomTooltip = ({ active, payload, label }: {
  active?: boolean;
  payload?: Array<{ value: number }>;
  label?: string;
}) => {
  if (active && payload?.length) {
    return (
      <div style={{
        background: 'rgba(13,20,38,0.95)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: 8,
        padding: '8px 12px',
        fontSize: '0.8rem',
      }}>
        <p style={{ color: 'var(--color-text-secondary)' }}>Score: {label}</p>
        <p style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{payload[0].value} scans</p>
      </div>
    );
  }
  return null;
};

export function ScoreHistogram({ histogram, total, isLoading }: ScoreHistogramProps) {
  if (isLoading) return <Skeleton height={220} />;

  return (
    <div>
      <h3 className="chart-title">Score Distribution</h3>
      {total === 0 ? (
        <EmptyState
          icon={<BarChart3 size={36} />}
          title="No scan data yet"
          description="Analyze URLs to see score distribution"
        />
      ) : (
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={histogram} barSize={32} margin={{ top: 4, right: 0, left: -24, bottom: 0 }}>
            <XAxis
              dataKey="label"
              tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 11, fontFamily: 'JetBrains Mono' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive animationBegin={150} animationDuration={800}>
              {histogram.map((_, i) => (
                <Cell key={i} fill={BUCKET_COLORS[i]} opacity={0.85} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
