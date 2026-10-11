/**
 * Client-side API wrapper for the PhishGuard Next.js API routes.
 *
 * Rules (this is a security product):
 * - Never invent results. If a request fails, throw an ApiError with a
 *   human-readable message; the UI shows an error state with Retry.
 * - Identity comes from the server-issued httpOnly session cookie.
 *   Same-origin fetch sends it automatically; we never send a user id.
 */

export interface RiskBreakdownItem {
  layer: string;
  riskContribution: number;
  weight: number;
  details: string;
}

/** Shape of `analysis.result` as returned by the analyze routes (fields are optional on purpose). */
export interface AnalysisResultPayload {
  confidence?: number;
  threat_level?: string;
  risk_score?: number;
  indicators?: string[];
  recommendations?: string[];
  riskBreakdown?: RiskBreakdownItem[];
  risk_breakdown?: RiskBreakdownItem[];
  scan_duration_ms?: number;
  layers?: Record<string, string>;
  [key: string]: unknown;
}

export interface AnalysisPayload {
  id?: string | null;
  /** false when the result could not be saved to history */
  saved?: boolean;
  type?: string;
  target?: string;
  result: AnalysisResultPayload;
  timestamp?: string;
  model_version?: string;
  scan_duration_ms?: number;
  layers?: Record<string, string>;
  file?: { name?: string; size?: number; type?: string };
  summary?: Record<string, number | undefined>;
  [key: string]: unknown;
}

export interface AnalysisResponse {
  success: boolean;
  analysis: AnalysisPayload;
}

export interface StoredScan {
  id: string;
  type: string;
  target: string;
  result: {
    confidence?: number;
    threat_level?: string;
    risk_score?: number;
    indicators?: string[];
    recommendations?: string[];
  };
  timestamp?: string;
  model_version?: string;
}

export interface HealthResponse {
  success?: boolean;
  /** 'ok' | 'degraded' */
  status?: string;
  timestamp?: string;
  models?: string[];
  models_available?: number;
  /** 'up' | 'down' */
  database?: string;
  [key: string]: unknown;
}

/** Raw stats object; every field is optional because the route is evolving. */
export type StatsPayload = Record<string, unknown>;

export interface UserSettings {
  realTimeScanning: boolean;
  autoQuarantine: boolean;
  detectionSensitivity: number;
  defaultAction: string;
  emailAlerts: boolean;
  desktopAlerts: boolean;
  dailySummary: boolean;
  dataRetentionDays: number;
  securityLevel: string;
}

export interface ChatTurn {
  role: 'user' | 'assistant';
  content: string;
}

export interface ChatResponse {
  success: boolean;
  response: string;
  model?: string;
  fallback?: boolean;
}

export interface DomainIntelResponse {
  success: boolean;
  domain_intelligence?: {
    domain?: string;
    risk_score?: number;
    indicators?: string[];
    whois_data?: {
      registrar?: string;
      createdDate?: string;
      expiresDate?: string;
      updatedDate?: string;
      registrantName?: string;
      registrantOrg?: string;
      domainAge?: number;
    } | null;
    dns_data?: {
      ipAddresses?: string[];
      mxRecords?: string[];
      nsRecords?: string[];
      txtRecords?: string[];
    } | null;
    reputation?: {
      isKnownPhishing?: boolean;
      isKnownMalware?: boolean;
      reportCount?: number;
    } | null;
  };
}

export interface IntegrationServiceStatus {
  configured: boolean;
  working: boolean;
  message: string;
}

export interface IntegrationTestResponse {
  success: boolean;
  summary?: { working?: number; total?: number; status?: string };
  services?: Record<string, IntegrationServiceStatus>;
  timestamp?: string;
}

/** Error thrown for any failed request. `message` is safe to show to the user. */
export class ApiError extends Error {
  status: number;
  retryAfterSeconds?: number;
  aborted: boolean;

  constructor(message: string, status: number, opts: { retryAfterSeconds?: number; aborted?: boolean } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryAfterSeconds = opts.retryAfterSeconds;
    this.aborted = opts.aborted ?? false;
  }
}

export function isAbortError(error: unknown): boolean {
  return (
    (error instanceof ApiError && error.aborted) ||
    (error instanceof DOMException && error.name === 'AbortError')
  );
}

/** Turn any thrown value into a user-facing message. */
export function errorMessage(error: unknown, fallback = 'Something went wrong — try again.'): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds);
  const date = Date.parse(header);
  if (!Number.isNaN(date)) return Math.max(0, Math.ceil((date - Date.now()) / 1000));
  return undefined;
}

class BackendServiceClass {
  private readonly baseUrl = '/api';

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { timeoutMs = 15000, signal: externalSignal, headers, ...rest } = options;

    const controller = new AbortController();
    let timedOut = false;
    const timeoutId = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    const onExternalAbort = () => controller.abort();
    if (externalSignal) {
      if (externalSignal.aborted) controller.abort();
      else externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }

    const isFormData = typeof FormData !== 'undefined' && rest.body instanceof FormData;

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...rest,
        credentials: 'same-origin',
        headers: isFormData ? headers : { 'Content-Type': 'application/json', ...headers },
        signal: controller.signal,
      });
    } catch {
      if (controller.signal.aborted && !timedOut) {
        throw new ApiError('Request cancelled.', 0, { aborted: true });
      }
      if (timedOut) {
        throw new ApiError('The scanner took too long to respond — try again.', 0);
      }
      throw new ApiError("Couldn't reach the scanner — check your connection and try again.", 0);
    } finally {
      clearTimeout(timeoutId);
      externalSignal?.removeEventListener('abort', onExternalAbort);
    }

    let data: { success?: unknown; error?: unknown } | null = null;
    try {
      const parsed: unknown = await response.json();
      data = parsed && typeof parsed === 'object' ? (parsed as { success?: unknown; error?: unknown }) : null;
    } catch {
      data = null;
    }

    if (response.status === 429) {
      const retryAfter = parseRetryAfter(response.headers.get('Retry-After'));
      throw new ApiError(
        retryAfter !== undefined
          ? `You're scanning too fast — try again in ${retryAfter} second${retryAfter === 1 ? '' : 's'}.`
          : "You're scanning too fast — wait a moment and try again.",
        429,
        { retryAfterSeconds: retryAfter }
      );
    }

    if (response.status === 413) {
      throw new ApiError('That is too large to scan. Try a shorter text or a smaller file.', 413);
    }

    if (!response.ok) {
      const serverMessage = data && typeof data.error === 'string' ? data.error : null;
      if (response.status >= 400 && response.status < 500 && serverMessage) {
        throw new ApiError(serverMessage, response.status);
      }
      if (response.status === 503) {
        throw new ApiError(serverMessage || 'This scanner is temporarily unavailable — try again shortly.', 503);
      }
      throw new ApiError(
        serverMessage
          ? `${serverMessage}. Try again in a moment.`
          : `The scanner hit a problem (error ${response.status}) — try again.`,
        response.status
      );
    }

    if (!data) {
      throw new ApiError('The scanner sent an unreadable response — try again.', response.status);
    }
    if (data.success === false) {
      throw new ApiError(typeof data.error === 'string' ? data.error : 'The request failed — try again.', response.status);
    }
    return data as unknown as T;
  }

  // ---------- Health & stats ----------

  getHealth(signal?: AbortSignal): Promise<HealthResponse> {
    return this.request<HealthResponse>('/health', { signal, timeoutMs: 8000 });
  }

  async getStats(signal?: AbortSignal): Promise<StatsPayload> {
    const tzOffset = new Date().getTimezoneOffset();
    const data = await this.request<{ success: boolean; stats?: StatsPayload }>(
      `/stats?tzOffset=${encodeURIComponent(String(tzOffset))}`,
      { signal }
    );
    if (!data.stats || typeof data.stats !== 'object') {
      throw new ApiError('Statistics are unavailable right now.', 200);
    }
    return data.stats;
  }

  // ---------- Scanning ----------

  analyzeUrl(url: string, signal?: AbortSignal): Promise<AnalysisResponse> {
    return this.request<AnalysisResponse>('/analyze/url', {
      method: 'POST',
      body: JSON.stringify({ url }),
      signal,
      timeoutMs: 45000,
    });
  }

  /** `raw` is the full pasted email text (headers optional). */
  analyzeEmail(raw: string, signal?: AbortSignal): Promise<AnalysisResponse> {
    return this.request<AnalysisResponse>('/analyze/email', {
      method: 'POST',
      body: JSON.stringify({ raw }),
      signal,
      timeoutMs: 45000,
    });
  }

  analyzeMessage(message: string, signal?: AbortSignal): Promise<AnalysisResponse> {
    return this.request<AnalysisResponse>('/analyze/message', {
      method: 'POST',
      body: JSON.stringify({ message }),
      signal,
      timeoutMs: 45000,
    });
  }

  analyzeFile(file: File, signal?: AbortSignal): Promise<AnalysisResponse> {
    const formData = new FormData();
    formData.append('file', file);
    return this.request<AnalysisResponse>('/analyze/file', {
      method: 'POST',
      body: formData,
      signal,
      timeoutMs: 120000,
    });
  }

  // ---------- Scan history ----------

  async getScans(limit = 100, signal?: AbortSignal): Promise<StoredScan[]> {
    const safeLimit = Math.max(1, Math.min(100, Math.floor(limit)));
    const data = await this.request<{ success: boolean; scans?: StoredScan[] }>(
      `/scans?limit=${encodeURIComponent(String(safeLimit))}`,
      { signal }
    );
    return Array.isArray(data.scans) ? data.scans : [];
  }

  getScanDetails(scanId: string, signal?: AbortSignal): Promise<{ success: boolean; scan: StoredScan }> {
    return this.request(`/scans/${encodeURIComponent(scanId)}`, { signal });
  }

  deleteScan(scanId: string): Promise<{ success: boolean }> {
    return this.request(`/scans/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
  }

  // ---------- Settings ----------

  async getSettings(signal?: AbortSignal): Promise<{ settings: Partial<UserSettings>; isDefault: boolean }> {
    const data = await this.request<{ success: boolean; settings?: Partial<UserSettings>; isDefault?: boolean }>(
      '/settings',
      { signal }
    );
    return { settings: data.settings ?? {}, isDefault: Boolean(data.isDefault) };
  }

  saveSettings(settings: Partial<UserSettings>): Promise<{ success: boolean; settings?: Partial<UserSettings> }> {
    return this.request('/settings', {
      method: 'POST',
      body: JSON.stringify({ settings }),
    });
  }

  // ---------- Admin ----------

  /** Admin-only integration check. The token is sent once and never stored. */
  testIntegrations(adminToken: string, signal?: AbortSignal): Promise<IntegrationTestResponse> {
    return this.request<IntegrationTestResponse>('/test-apis', {
      headers: { 'x-admin-token': adminToken },
      signal,
      timeoutMs: 45000,
    });
  }

  // ---------- AI assistant & threat intel ----------

  chat(message: string, context: ChatTurn[], signal?: AbortSignal): Promise<ChatResponse> {
    return this.request<ChatResponse>('/chat', {
      method: 'POST',
      body: JSON.stringify({ message, context }),
      signal,
      timeoutMs: 45000,
    });
  }

  domainIntel(domain: string, signal?: AbortSignal): Promise<DomainIntelResponse> {
    return this.request<DomainIntelResponse>('/threat-intel/domain', {
      method: 'POST',
      body: JSON.stringify({ domain }),
      signal,
      timeoutMs: 30000,
    });
  }
}

export const BackendService = new BackendServiceClass();
export type BackendServiceType = BackendServiceClass;
