/**
 * PhishTank API Integration
 * Checks URLs against PhishTank's community-driven phishing database.
 *
 * NOTE: PhishTank no longer accepts new application/API-key registrations.
 * Existing keys keep working; without PHISHTANK_API_KEY this service is
 * silently skipped (checked: false) — it never pretends a URL is clean.
 */

import { URLAnalyzer } from '../detection/urlAnalyzer';

const REQUEST_TIMEOUT_MS = 4000;

export interface PhishTankResult {
  /** True only for a verified, still-valid phish (in_database && verified && valid) */
  isPhishing: boolean;
  verified: boolean;
  checked?: boolean; // true only when PhishTank actually answered
  inDatabase?: boolean; // submitted but possibly unverified/invalid
  verifiedAt?: Date;
  phishId?: string;
  submissionDate?: Date;
  details?: string;
}

/** PhishTank JSON uses booleans, but older responses used "y"/"n" strings */
function truthy(value: unknown): boolean {
  return value === true || value === 'true' || value === 'y' || value === 'yes' || value === 1;
}

export class PhishTankService {
  private static readonly API_BASE_URL = 'https://checkurl.phishtank.com/checkurl/';

  private static get API_KEY(): string {
    return process.env.PHISHTANK_API_KEY || '';
  }

  /**
   * Check URL against PhishTank database
   */
  static async checkURL(url: string): Promise<PhishTankResult> {
    // No key → degrade silently (registrations are closed, most installs won't have one)
    if (!this.API_KEY) {
      return { isPhishing: false, verified: false, checked: false };
    }

    // Never send private/internal URLs to a third party
    if (!URLAnalyzer.isPublicWebUrl(url)) {
      return { isPhishing: false, verified: false, checked: false };
    }

    try {
      const response = await this.queryAPI(url);
      return { ...this.parseResponse(response), checked: true };
    } catch (error) {
      console.error('PhishTank API error:', error);
      return { isPhishing: false, verified: false, checked: false };
    }
  }

  /**
   * Query PhishTank API
   */
  private static async queryAPI(url: string): Promise<any> {
    const formData = new URLSearchParams();
    formData.append('url', url);
    formData.append('format', 'json');
    formData.append('app_key', this.API_KEY);

    const response = await fetch(this.API_BASE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'phishguard/1.0',
      },
      body: formData,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`PhishTank API error: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Parse PhishTank response
   */
  private static parseResponse(response: any): PhishTankResult {
    const results = response?.results;

    if (!results || !truthy(results.in_database)) {
      return { isPhishing: false, verified: false, inDatabase: false };
    }

    const verified = truthy(results.verified);
    const valid = truthy(results.valid);

    return {
      // Submitted-but-unverified (or verified-as-not-phish) entries are not a verdict
      isPhishing: verified && valid,
      verified,
      inDatabase: true,
      verifiedAt: results.verified_at ? new Date(results.verified_at) : undefined,
      phishId: results.phish_id ? String(results.phish_id) : undefined,
      submissionDate: results.submission_time ? new Date(results.submission_time) : undefined,
      details: results.phish_detail_page,
    };
  }

  /**
   * Download PhishTank database (for offline checking).
   * Requires an existing API key (the feed URL embeds it).
   */
  static async downloadDatabase(): Promise<string[]> {
    if (!this.API_KEY) return [];

    const databaseUrl = `https://data.phishtank.com/data/${encodeURIComponent(this.API_KEY)}/online-valid.json`;

    try {
      const response = await fetch(databaseUrl, { signal: AbortSignal.timeout(30000) });

      if (!response.ok) {
        throw new Error(`Database download error: ${response.statusText}`);
      }

      const data = await response.json();

      // Extract URLs from database
      const urls: string[] = Array.isArray(data) ? data.map((entry: any) => entry.url) : [];

      return urls;
    } catch (error) {
      console.error('Failed to download PhishTank database:', error);
      return [];
    }
  }

  /**
   * Check URL against local database (offline mode)
   */
  static async checkURLOffline(url: string, database: string[]): Promise<boolean> {
    // Normalize URL for comparison
    const normalizedUrl = this.normalizeURL(url);

    return database.some(dbUrl => this.normalizeURL(dbUrl) === normalizedUrl);
  }

  /**
   * Normalize URL for comparison
   */
  private static normalizeURL(url: string): string {
    try {
      const parsed = new URL(url);
      // Remove protocol, www, trailing slash
      return parsed.hostname.replace(/^www\./, '') + parsed.pathname.replace(/\/$/, '');
    } catch {
      return url.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/$/, '');
    }
  }

  /**
   * Submit phishing URL to PhishTank
   */
  static async submitPhishing(url: string, additionalInfo?: string): Promise<boolean> {
    if (!this.API_KEY) {
      return false;
    }

    try {
      const formData = new URLSearchParams();
      formData.append('url', url);
      formData.append('format', 'json');
      formData.append('app_key', this.API_KEY);
      if (additionalInfo) {
        formData.append('additional_info', additionalInfo);
      }

      const response = await fetch('https://www.phishtank.com/add_web_phish.php', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formData,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      return response.ok;
    } catch (error) {
      console.error('Failed to submit to PhishTank:', error);
      return false;
    }
  }

  /**
   * Get PhishTank statistics
   */
  static async getStats(): Promise<{
    totalPhish: number;
    validPhish: number;
    invalidPhish: number;
  }> {
    try {
      const response = await fetch('https://www.phishtank.com/stats.json', {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      if (!response.ok) {
        throw new Error('Failed to fetch stats');
      }

      const data = await response.json();

      return {
        totalPhish: data.stats.total_phish || 0,
        validPhish: data.stats.valid_phish || 0,
        invalidPhish: data.stats.invalid_phish || 0,
      };
    } catch (error) {
      console.error('Failed to fetch PhishTank stats:', error);
      return {
        totalPhish: 0,
        validPhish: 0,
        invalidPhish: 0,
      };
    }
  }
}
