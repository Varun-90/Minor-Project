/**
 * NetShield AI API Client (Axios)
 * Holds the Bearer token strictly in JavaScript memory (never in localStorage/sessionStorage).
 */

import axios from 'axios';
import type { ModelEvaluationMetrics } from '../ml/pipeline.ts';
import type { StoredAlert, StoredNetworkEvent, SystemSettings } from '../server/store.ts';
import type { AuthUser, UserRole } from '../server/auth.ts';

let inMemoryToken: string | null = null;
let tokenProvider: (() => Promise<string | null>) | null = null;

export function setAuthToken(token: string | null) {
  inMemoryToken = token;
}

export function setDynamicTokenProvider(provider: (() => Promise<string | null>) | null) {
  tokenProvider = provider;
}

export const apiClient = axios.create({
  baseURL: '/api/v1',
  timeout: 20000,
});

apiClient.interceptors.request.use(async (config) => {
  let token = inMemoryToken;
  if (!token && tokenProvider) {
    token = await tokenProvider();
  }
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export interface DashboardSummary {
  totalEvents: number;
  normalCount: number;
  suspiciousCount: number;
  openAlerts: number;
  investigatingAlerts: number;
  resolvedAlerts: number;
  totalPackets: number;
  totalBytes: number;
  activeModelVersion: string;
  protocolDistribution: { protocol: string; count: number }[];
  threatDistribution: { name: string; count: number }[];
  activitySeries: { time: string; normal: number; attack: number }[];
  recentEvents: StoredNetworkEvent[];
}

export interface PaginatedEvents {
  items: StoredNetworkEvent[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface CsvImportResponse {
  batchName: string;
  cleaningReport: {
    totalRawRows: number;
    duplicatesRemoved: number;
    missingValuesImputed: number;
    infiniteValuesReplaced: number;
    validRowsRetained: number;
  };
  importedCount: number;
  suspiciousCount: number;
  normalCount: number;
  events: StoredNetworkEvent[];
  alerts: StoredAlert[];
}

export const netshieldApi = {
  async getAuthStatus() {
    const { data } = await apiClient.get<{
      localBootstrapRequired: boolean;
      envPasswordConfigured: boolean;
    }>('/auth/status');
    return data;
  },

  async bootstrapLocalAdmin(username: string, password: string) {
    const { data } = await apiClient.post<{
      access_token: string;
      token_type: string;
      user: AuthUser;
    }>('/auth/bootstrap', { username, password });
    return data;
  },

  async loginLocal(username: string, password: string) {
    const { data } = await apiClient.post<{
      access_token: string;
      token_type: string;
      user: AuthUser;
    }>('/auth/login', { username, password });
    return data;
  },

  async getHealth() {
    const { data } = await apiClient.get<{
      status: string;
      service: string;
      mode: string;
      activeModelVersion: string;
      timestamp: string;
    }>('/health');
    return data;
  },

  async getDashboardSummary() {
    const { data } = await apiClient.get<DashboardSummary>('/dashboard/summary');
    return data;
  },

  async getEvents(params: {
    page?: number;
    limit?: number;
    search?: string;
    prediction?: string;
    protocol?: string;
    severity?: string;
  }) {
    const { data } = await apiClient.get<PaginatedEvents>('/events', { params });
    return data;
  },

  async getEventById(id: string) {
    const { data } = await apiClient.get<{ event: StoredNetworkEvent; alert: StoredAlert | null }>(
      `/events/${encodeURIComponent(id)}`
    );
    return data;
  },

  async submitSinglePrediction(payload: Record<string, string | number>) {
    const { data } = await apiClient.post<{ event: StoredNetworkEvent; alert: StoredAlert | null }>(
      '/predictions',
      payload
    );
    return data;
  },

  async importCsvFile(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const { data } = await apiClient.post<CsvImportResponse>('/events/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return data;
  },

  async downloadSampleCsv(): Promise<string> {
    const { data } = await apiClient.get<string>('/events/sample-csv', {
      responseType: 'text',
    });
    return data;
  },

  async getAlerts(params?: { status?: string; severity?: string; search?: string }) {
    const { data } = await apiClient.get<{ items: StoredAlert[]; total: number }>('/alerts', {
      params,
    });
    return data;
  },

  async updateAlertStatus(id: string, status: 'Open' | 'Investigating' | 'Resolved') {
    const { data } = await apiClient.patch<{ alert: StoredAlert }>(
      `/alerts/${encodeURIComponent(id)}`,
      { status }
    );
    return data;
  },

  async getModelMetrics() {
    const { data } = await apiClient.get<{
      activeModel: ModelEvaluationMetrics;
      history: ModelEvaluationMetrics[];
    }>('/models/metrics');
    return data;
  },

  async retrainModel(nEstimators: number, maxDepth: number) {
    const { data } = await apiClient.post<{
      activeModel: ModelEvaluationMetrics;
      history: ModelEvaluationMetrics[];
    }>('/models/retrain', { nEstimators, maxDepth });
    return data;
  },

  async getSettings() {
    const { data } = await apiClient.get<{ settings: SystemSettings }>('/settings');
    return data;
  },

  async updateSettings(patch: Partial<SystemSettings>) {
    const { data } = await apiClient.patch<{ settings: SystemSettings }>('/settings', patch);
    return data;
  },

  async getLocalUsers() {
    const { data } = await apiClient.get<{
      users: Array<{ id: string; username: string; email: string; role: UserRole; createdAt: string }>;
    }>('/users');
    return data;
  },

  async createLocalUser(username: string, password: string, role: UserRole) {
    const { data } = await apiClient.post<{
      user: { id: string; username: string; email: string; role: UserRole; createdAt: string };
    }>('/users', { username, password, role });
    return data;
  },

  async updateLocalUserRole(id: string, role: UserRole) {
    const { data } = await apiClient.patch<{
      user: { id: string; username: string; email: string; role: UserRole; createdAt: string };
    }>(`/users/${encodeURIComponent(id)}`, { role });
    return data;
  },

  async parseZeekRecord(zeekJson: string) {
    const { data } = await apiClient.post<{ event: StoredNetworkEvent; alert: StoredAlert | null }>(
      '/zeek/parse',
      { zeekJson }
    );
    return data;
  },
};
