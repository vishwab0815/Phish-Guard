/**
 * VirusTotal API Integration
 * Provides URL scanning using VirusTotal's threat intelligence.
 *
 * Flow: look up an existing report (GET /urls/{id}); only if VirusTotal has
 * never seen the URL, submit it and poll the analysis briefly. If no verdict
 * arrives in time the result is 'pending' — never 'clean'.
 */

import { URLAnalyzer } from '../detection/urlAnalyzer';

const REQUEST_TIMEOUT_MS = 4000;
// One poll after submitting: a scan uses at most 3 requests (lookup, submit, poll).
// The free API tier allows only 4 requests/minute.
const POLL_ATTEMPTS = 1;
const POLL_BUDGET_MS = 6000; // total time allowed for submit + polling
const REQUESTS_PER_MINUTE = Number(process.env.VIRUSTOTAL_REQUESTS_PER_MINUTE) || 4;
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX_ENTRIES = 500;

export type VirusTotalStatus = 'completed' | 'pending' | 'unavailable' | 'error';

export interface VirusTotalResult {
  /** 'completed' = real verdict; 'pending' = submitted, no verdict yet; 'unavailable' = no key / not sent */
  status: VirusTotalStatus;
  isPhishing: boolean;
  isMalware: boolean;
  isSpam: boolean;
  confidence: number; // 0-100, share of engines flagging the URL
  maliciousCount: number; // engines with category "malicious"
  suspiciousCount: number; // engines with category "suspicious"
  detectionCount: number; // malicious + suspicious
  totalEngines: number; // engines that gave a verdict
  threatCategories: string[];
  scanDate: Date;
  message?: string;
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export class VirusTotalService {
  private static readonly API_BASE_URL = 'https://www.virustotal.com/api/v3';

  // Small in-memory cache (per server instance) to save API quota
  private static cache = new Map<string, { at: number; result: VirusTotalResult }>();
  private static usage = { day: '', count: 0 };
  // Wait before polling a fresh submission (bounded by POLL_BUDGET_MS)
  static pollDelaysMs = [4000];
  // Timestamps of recent requests, to stay under the per-minute quota instead of stalling on 429s
  private static recentRequests: number[] = [];

  /** True if `count` more requests fit in the per-minute quota. */
  private static hasQuota(count: number): boolean {
    const cutoff = Date.now() - 60_000;
    this.recentRequests = this.recentRequests.filter(t => t > cutoff);
    return this.recentRequests.length + count <= REQUESTS_PER_MINUTE;
  }

  private static get API_KEY(): string {
    return process.env.VIRUSTOTAL_API_KEY || '';
  }

  /**
   * Analyze URL using VirusTotal
   */
  static async analyzeURL(url: string): Promise<VirusTotalResult> {
    if (!this.API_KEY) {
      return this.emptyResult('unavailable', 'VirusTotal API key not configured');
    }

    // Never send private/internal URLs to a third party
    if (!URLAnalyzer.isPublicWebUrl(url)) {
      return this.emptyResult('unavailable', 'Private/internal URLs are not sent to VirusTotal');
    }

    const cached = this.cache.get(url);
    if (cached && Date.now() - cached.at < CACHE_TTL_MS) {
      return cached.result;
    }

    if (!this.hasQuota(1)) {
      return this.emptyResult('unavailable', 'VirusTotal per-minute quota reached; skipped for this scan');
    }

    try {
      const result = await this.lookupOrSubmit(url);
      if (result.status === 'completed') this.remember(url, result);
      return result;
    } catch (error) {
      console.error('VirusTotal API error:', error);
      return this.emptyResult('error', error instanceof Error ? error.message : 'VirusTotal request failed');
    }
  }

  /**
   * Encode URL for VirusTotal API (URL identifier = base64url without padding)
   */
  private static encodeURL(url: string): string {
    return Buffer.from(url)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  private static async request(path: string, init: RequestInit = {}, timeoutMs: number = REQUEST_TIMEOUT_MS): Promise<Response> {
    this.countUsage();
    this.recentRequests.push(Date.now());
    return fetch(`${this.API_BASE_URL}${path}`, {
      ...init,
      headers: {
        'x-apikey': this.API_KEY,
        'Accept': 'application/json',
        ...(init.headers || {}),
      },
      signal: AbortSignal.timeout(timeoutMs),
    });
  }

  /**
   * Existing report first; submit only when VirusTotal returns 404.
   */
  private static async lookupOrSubmit(url: string): Promise<VirusTotalResult> {
    const report = await this.request(`/urls/${this.encodeURL(url)}`);

    if (report.ok) {
      const data = await report.json();
      const result = this.parseResponse(data);
      // A known URL that has never finished an analysis has no verdict yet
      if (result.status === 'completed') return result;
      return this.emptyResult('pending', 'VirusTotal has no completed analysis for this URL yet');
    }

    if (report.status !== 404) {
      throw new Error(`VirusTotal API error: ${report.status} ${report.statusText}`);
    }

    // Submitting costs 2 more requests (submit + poll)
    if (!this.hasQuota(2)) {
      return this.emptyResult('unavailable', 'VirusTotal has no report for this URL and the per-minute quota is used up');
    }
    return this.submitAndPoll(url);
  }

  /**
   * Submit URL to VirusTotal and poll the analysis a few times (bounded).
   */
  private static async submitAndPoll(url: string): Promise<VirusTotalResult> {
    const deadline = Date.now() + POLL_BUDGET_MS;
    const formData = new URLSearchParams();
    formData.append('url', url);

    const submit = await this.request('/urls', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData,
    });

    if (!submit.ok) {
      throw new Error(`VirusTotal submission error: ${submit.status} ${submit.statusText}`);
    }

    const submitted = await submit.json();
    const analysisId: string | undefined = submitted?.data?.id;
    if (!analysisId) return this.emptyResult('pending', 'Submitted to VirusTotal; no analysis id returned');

    for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
      const wait = this.pollDelaysMs[attempt] ?? 2000;
      if (Date.now() + wait >= deadline) break;
      await sleep(wait);

      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      const response = await this.request(`/analyses/${encodeURIComponent(analysisId)}`, {}, Math.min(REQUEST_TIMEOUT_MS, remaining));
      if (!response.ok) continue;

      const result = this.parseResponse(await response.json());
      if (result.status === 'completed') return result;
    }

    return this.emptyResult('pending', 'Submitted to VirusTotal; analysis not finished yet');
  }

  /**
   * Parse a VirusTotal response. Handles both shapes:
   *  - URL object  (/urls/{id}):     data.attributes.last_analysis_stats / last_analysis_results
   *  - Analysis    (/analyses/{id}): data.attributes.stats / results / status
   */
  static parseResponse(response: any): VirusTotalResult {
    const attributes = response?.data?.attributes || {};
    const isAnalysisObject = response?.data?.type === 'analysis' || 'stats' in attributes || 'status' in attributes;

    const stats = (isAnalysisObject ? attributes.stats : attributes.last_analysis_stats) || {};
    const results = (isAnalysisObject ? attributes.results : attributes.last_analysis_results) || {};

    if (isAnalysisObject && attributes.status && attributes.status !== 'completed') {
      return this.emptyResult('pending', `VirusTotal analysis status: ${attributes.status}`);
    }

    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    const harmless = Number(stats.harmless) || 0;
    const undetected = Number(stats.undetected) || 0;
    const totalEngines = malicious + suspicious + harmless + undetected;

    if (totalEngines === 0) {
      return this.emptyResult('pending', 'VirusTotal returned no engine verdicts');
    }

    const detectionCount = malicious + suspicious;

    // Determine threat types from per-engine results
    const threatCategories = new Set<string>();
    Object.values(results).forEach((entry: any) => {
      if (entry?.category !== 'malicious' && entry?.category !== 'suspicious') return;
      const label = String(entry.result || '').toLowerCase();
      if (label.includes('phish')) threatCategories.add('phishing');
      if (label.includes('malware') || label.includes('trojan')) threatCategories.add('malware');
      if (label.includes('spam')) threatCategories.add('spam');
    });
    if (malicious > 0 && threatCategories.size === 0) threatCategories.add('malicious');

    return {
      status: 'completed',
      isPhishing: threatCategories.has('phishing'),
      isMalware: threatCategories.has('malware') || threatCategories.has('malicious'),
      isSpam: threatCategories.has('spam'),
      confidence: Math.round((detectionCount / totalEngines) * 100),
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      detectionCount,
      totalEngines,
      threatCategories: Array.from(threatCategories),
      scanDate: attributes.last_analysis_date
        ? new Date(attributes.last_analysis_date * 1000)
        : attributes.date ? new Date(attributes.date * 1000) : new Date(),
    };
  }

  /**
   * Result with no verdict (no key, not sent, pending, or error)
   */
  private static emptyResult(status: VirusTotalStatus, message?: string): VirusTotalResult {
    return {
      status,
      isPhishing: false,
      isMalware: false,
      isSpam: false,
      confidence: 0,
      maliciousCount: 0,
      suspiciousCount: 0,
      detectionCount: 0,
      totalEngines: 0,
      threatCategories: [],
      scanDate: new Date(),
      message,
    };
  }

  private static remember(url: string, result: VirusTotalResult) {
    if (this.cache.size >= CACHE_MAX_ENTRIES) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(url, { at: Date.now(), result });
  }

  private static countUsage() {
    const today = new Date().toISOString().slice(0, 10);
    if (this.usage.day !== today) this.usage = { day: today, count: 0 };
    this.usage.count++;
  }

  /** Test helper: forget cached verdicts and usage counters */
  static clearCache() {
    this.cache.clear();
    this.usage = { day: '', count: 0 };
  }

  /**
   * Check API rate limits (approximate, counted per server instance)
   */
  static async checkRateLimit(): Promise<{
    remaining: number;
    limit: number;
    resetTime: Date;
  }> {
    // VirusTotal free tier: 4 requests/minute, 500/day
    const DAILY_LIMIT = 500;
    const resetTime = new Date();
    resetTime.setUTCHours(24, 0, 0, 0); // VirusTotal quotas reset at 00:00 UTC

    const today = new Date().toISOString().slice(0, 10);
    const used = this.usage.day === today ? this.usage.count : 0;

    return {
      remaining: Math.max(0, DAILY_LIMIT - used),
      limit: DAILY_LIMIT,
      resetTime,
    };
  }
}
