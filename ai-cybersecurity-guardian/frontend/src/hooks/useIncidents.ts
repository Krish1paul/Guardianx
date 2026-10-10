import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { incidentAPI } from '@/lib/api';
import type { IncidentDetail, IncidentListResponse, IncidentStatus, IncidentTimelineResponse } from '@/types/api';

export function useIncidents(status?: IncidentStatus, limit = 50, offset = 0) {
  return useQuery<IncidentListResponse>({
    queryKey: ['incidents', status ?? 'ALL', limit, offset],
    queryFn: () => incidentAPI.list({ status, limit, offset }),
    staleTime: 15_000,
  });
}

export function useIncident(id: string | null) {
  return useQuery<IncidentDetail>({
    queryKey: ['incident', id],
    queryFn: () => (id ? incidentAPI.getById(id) : Promise.reject('No ID')),
    enabled: Boolean(id),
    staleTime: 10_000,
  });
}

export function useIncidentTimeline(id: string | null) {
  return useQuery<IncidentTimelineResponse>({
    queryKey: ['incident-timeline', id],
    queryFn: () => (id ? incidentAPI.getTimeline(id) : Promise.reject('No ID')),
    enabled: Boolean(id),
    staleTime: 10_000,
  });
}

export function useUpdateIncidentStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: IncidentStatus }) =>
      incidentAPI.updateStatus(id, status),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.setQueryData(['incident', data.id], data);
    },
  });
}
