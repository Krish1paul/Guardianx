import { useQuery } from '@tanstack/react-query';
import { scanAPI } from '@/lib/api';
import type { URLScanHistoryResponse } from '@/types/api';

export const HISTORY_PAGE_SIZE = 15;

export function useHistory(offset: number) {
  return useQuery<URLScanHistoryResponse>({
    queryKey: ['history', offset],
    queryFn: () => scanAPI.history({ limit: HISTORY_PAGE_SIZE, offset }),
    staleTime: 15_000,
  });
}
