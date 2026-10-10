/**
 * Axios API client — attaches auth headers, handles 401 → token refresh → retry.
 *
 * Security:
 * - Tokens are never logged, even in error handlers.
 * - Authorization header is injected by interceptor, not stored in Axios defaults.
 * - On refresh failure, tokens are cleared and user is redirected to /login.
 */

import axios, { type AxiosError } from 'axios';
import { clearTokens, getAccessToken, getRefreshToken, setTokens } from './auth-store';
import type { TokenPair } from '@/types/api';

// Vite dev proxy forwards /api → http://localhost:8000
const BASE_URL = '/api/v1';

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 15_000,
  headers: { 'Content-Type': 'application/json' },
});

// ---------------------------------------------------------------------------
// Request interceptor — attach access token
// ---------------------------------------------------------------------------

apiClient.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

// ---------------------------------------------------------------------------
// Response interceptor — silent refresh on 401
// ---------------------------------------------------------------------------

let _refreshPromise: Promise<TokenPair> | null = null;

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as typeof error.config & { _retried?: boolean };
    const status = error.response?.status;

    // Only attempt refresh on 401, and only once per request
    if (status === 401 && !originalRequest?._retried) {
      const refreshToken = getRefreshToken();
      if (!refreshToken || !originalRequest) {
        clearTokens();
        window.location.href = '/login';
        return Promise.reject(error);
      }

      originalRequest._retried = true;

      try {
        // Deduplicate concurrent refresh calls
        if (!_refreshPromise) {
          _refreshPromise = axios
            .post<TokenPair>(`${BASE_URL}/auth/refresh`, { refresh_token: refreshToken })
            .then((r) => r.data)
            .finally(() => { _refreshPromise = null; });
        }

        const tokens = await _refreshPromise;
        setTokens(tokens.access_token, tokens.refresh_token);
        originalRequest.headers['Authorization'] = `Bearer ${tokens.access_token}`;
        return apiClient(originalRequest);
      } catch {
        clearTokens();
        window.location.href = '/login';
        return Promise.reject(error);
      }
    }

    return Promise.reject(error);
  },
);

import type {
  FileScanHistoryResponse,
  FileScanResponse,
  IncidentDetail,
  IncidentListResponse,
  IncidentStatus,
  IncidentTimelineResponse,
  LoginRequest,
  LogoutRequest,
  MessageScanHistoryResponse,
  MessageScanRequest,
  MessageScanResponse,
  RegisterRequest,
  TokenPair as TP,
  URLScanHistoryResponse,
  URLScanRequest,
  URLScanResponse,
  UserMeResponse,
} from '@/types/api';

export const authAPI = {
  register: (data: RegisterRequest) =>
    apiClient.post<UserMeResponse>('/auth/register', data).then((r) => r.data),

  login: (data: LoginRequest) =>
    apiClient.post<TP>('/auth/login', data).then((r) => r.data),

  refresh: (data: { refresh_token: string }) =>
    apiClient.post<TP>('/auth/refresh', data).then((r) => r.data),

  logout: (data: LogoutRequest) =>
    apiClient.post<void>('/auth/logout', data).then((r) => r.data),

  me: () => apiClient.get<UserMeResponse>('/auth/me').then((r) => r.data),
};

export const scanAPI = {
  analyze: (data: URLScanRequest) =>
    apiClient.post<URLScanResponse>('/analyze/url', data).then((r) => r.data),

  history: (params: { limit?: number; offset?: number }) =>
    apiClient
      .get<URLScanHistoryResponse>('/analyze/url/history', { params })
      .then((r) => r.data),

  analyzeMessage: (data: MessageScanRequest) =>
    apiClient.post<MessageScanResponse>('/analyze/message', data).then((r) => r.data),

  messageHistory: (params: { limit?: number; offset?: number }) =>
    apiClient
      .get<MessageScanHistoryResponse>('/analyze/message/history', { params })
      .then((r) => r.data),

  analyzeFile: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiClient
      .post<FileScanResponse>('/analyze/file', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      .then((r) => r.data);
  },

  fileHistory: (params: { limit?: number; offset?: number }) =>
    apiClient
      .get<FileScanHistoryResponse>('/analyze/file/history', { params })
      .then((r) => r.data),
};

export const incidentAPI = {
  list: (params?: { status?: IncidentStatus; limit?: number; offset?: number }) =>
    apiClient
      .get<IncidentListResponse>('/incidents', { params })
      .then((r) => r.data),

  getById: (id: string) =>
    apiClient
      .get<IncidentDetail>(`/incidents/${id}`)
      .then((r) => r.data),

  updateStatus: (id: string, status: IncidentStatus) =>
    apiClient
      .patch<IncidentDetail>(`/incidents/${id}/status`, { status })
      .then((r) => r.data),

  getTimeline: (id: string) =>
    apiClient
      .get<IncidentTimelineResponse>(`/incidents/${id}/timeline`)
      .then((r) => r.data),
};


export const healthAPI = {
  ready: () =>
    axios.get('/health/ready').then((r) => r.data as { status: string; database?: string; redis?: string }),
};

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

export function getErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      const first = detail[0] as Record<string, unknown>;
      return String(first?.msg ?? 'Validation error');
    }
    if (error.response?.status === 429) return 'Too many requests. Please wait a moment.';
    if (error.response?.status === 503) return 'Service temporarily unavailable.';
    if (error.response?.status === 502) return 'Cannot reach the backend server. Please start the API server and try again.';
    if (error.response?.status === 500) return 'An unexpected server error occurred.';
    if (error.response?.status === 401) return 'Invalid email or password.';
    if (!error.response) return 'Cannot connect to the server. Is the backend running?';
  }
  return 'An unexpected error occurred.';
}
