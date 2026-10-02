import axios from 'axios';

const API_BASE = 'http://localhost:8001/api/v1';
const TOKEN_KEY = 'sentinelloop_auth_token';

const client = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to all requests
client.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Export the axios client for direct use
export { client };

export interface Target {
  id: string;
  name: string;
  url: string;
  environment: string;
  ownership_verified: boolean;
  watcher_enabled: boolean;
  last_probed_at?: string;
  created_at: string;
}

export interface RegisterTargetResponse {
  id: string;
  name: string;
  url: string;
  environment: string;
  ownership_verified: boolean;
  watcher_enabled: boolean;
  created_at: string;
  management_token: string;
  management_token_warning: string;
  verification_token: string;
  verification_instructions: string;
  watcher_disclosure: string;
}

export interface Scan {
  id: string;
  target_id: string;
  scan_type: string;
  triggered_by: string;
  status: string;
  total_attacks: number;
  completed_attacks: number;
  started_at?: string;
  completed_at?: string;
  created_at: string;
  findings: Finding[];
}

export interface Finding {
  id: string;
  scan_id?: string;
  target_id: string;
  attack_type: string;
  severity: string;
  status: string;
  attack_payload?: string;
  attack_response?: string;
  layer_failed?: string;
  risk_score: number;
  fix_recommendation?: string;
  fix_code_snippet?: string;
  owasp_category?: string;
  compliance?: {
    eu_ai_act: string;
    iso_42001: string;
    nist_ai_rmf: string;
    disclaimer: string;
    guidance_only: boolean;
  };
  detection_method?: string;
  confidence?: number;
  retest_history?: any[];
  created_at: string;
}

export interface GuardCheckResult {
  risk_score: number;
  attack_type: string;
  decision: 'BLOCK' | 'ALLOW';
  method: string;
  reason: string;
  llm_response?: string | null;
}

export interface GuardLog extends GuardCheckResult {
  id: string;
  prompt: string;
  forwarded: boolean;
  created_at: string;
}

export interface GuardStats {
  total: number;
  blocked: number;
  allowed: number;
}

export const api = {
  // Targets
  getTargets: async () => {
    const res = await client.get<Target[]>('/targets/');
    return res.data;
  },
  getTarget: async (id: string) => {
    const res = await client.get<Target>(`/targets/${id}`);
    return res.data;
  },
  registerTarget: async (data: { name: string; url: string; environment: string; auth_token?: string }) => {
    const res = await client.post<RegisterTargetResponse>('/targets/', null, { params: data });
    return res.data;
  },
  verifyOwnership: async (id: string) => {
    const res = await client.get(`/targets/${id}/verify`);
    return res.data;
  },
  toggleWatcher: async (id: string, enabled: boolean, managementToken: string) => {
    const res = await client.patch(`/targets/${id}/watcher`, null, {
      params: { enabled },
      headers: { 'X-Management-Token': managementToken },
    });
    return res.data;
  },

  // API Keys
  createApiKey: async (targetId: string, label: string, managementToken: string) => {
    const res = await client.post('/api-keys/', null, {
      params: { target_id: targetId, label },
      headers: { 'X-Management-Token': managementToken },
    });
    return res.data;
  },
  getApiKeys: async (targetId: string) => {
    const res = await client.get(`/api-keys/`, { params: { target_id: targetId } });
    return res.data;
  },
  revokeApiKey: async (keyId: string, targetId: string, managementToken: string) => {
    const res = await client.delete(`/api-keys/${keyId}`, {
      params: { target_id: targetId },
      headers: { 'X-Management-Token': managementToken },
    });
    return res.data;
  },

  // Scans
  triggerScan: async (targetId: string) => {
    const res = await client.post<{ scan_id: string; status: string; stream_url: string }>('/scans/', null, {
      params: { target_id: targetId },
    });
    return res.data;
  },
  getScan: async (id: string) => {
    const res = await client.get<Scan>(`/scans/${id}`);
    return res.data;
  },
  triggerRetest: async (scanId: string) => {
    const res = await client.post<{ retest_scan_id: string; status: string; stream_url: string }>(`/scans/${scanId}/retest`);
    return res.data;
  },

  // Findings
  getFindings: async (targetId: string, status?: string) => {
    const res = await client.get<Finding[]>('/findings/', { params: { target_id: targetId, status } });
    return res.data;
  },
  getFinding: async (id: string) => {
    const res = await client.get<Finding>(`/findings/${id}`);
    return res.data;
  },

  // Real-time inline guard
  guardCheck: async (prompt: string, forward: boolean = true) => {
    const res = await client.post<GuardCheckResult>('/guard/check', { prompt, forward });
    return res.data;
  },
  getGuardLogs: async (limit: number = 25) => {
    const res = await client.get<GuardLog[]>('/guard/logs', { params: { limit } });
    return res.data;
  },
  getGuardStats: async () => {
    const res = await client.get<GuardStats>('/guard/stats');
    return res.data;
  },
};
