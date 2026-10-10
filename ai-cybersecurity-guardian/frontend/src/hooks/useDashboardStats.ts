import { useQuery } from '@tanstack/react-query';
import { scanAPI } from '@/lib/api';
import type { URLScanHistoryResponse } from '@/types/api';
import { computeDashboardStats } from '@/lib/utils';

const STATS_LIMIT = 100;

export function useDashboardStats() {
  const query = useQuery<URLScanHistoryResponse>({
    queryKey: ['history', 'stats', STATS_LIMIT],
    queryFn: () => scanAPI.history({ limit: STATS_LIMIT, offset: 0 }),
    staleTime: 30_000,
  });

  const stats = computeDashboardStats(query.data?.items ?? []);

  return { ...query, stats };
}

export function useRecentScans(limit = 5) {
  return useQuery<URLScanHistoryResponse>({
    queryKey: ['history', 'recent', limit],
    queryFn: () => scanAPI.history({ limit, offset: 0 }),
    staleTime: 15_000,
  });
}
