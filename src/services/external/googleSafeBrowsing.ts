/**
 * Google Safe Browsing API Integration
 * Checks URLs against Google's threat intelligence database
 */

import { URLAnalyzer } from '../detection/urlAnalyzer';

const REQUEST_TIMEOUT_MS = 4000;

export interface SafeBrowsingResult {
  isThreat: boolean;
  checked?: boolean; // true only when Google actually answered (key configured, no error)
  threatType?: 'MALWARE' | 'SOCIAL_ENGINEERING' | 'UNWANTED_SOFTWARE' | 'POTENTIALLY_HARMFUL_APPLICATION';
  platformType?: string;
  threatEntryType?: string;
  details?: any;
}

export class GoogleSafeBrowsingService {
  private static readonly API_BASE_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
  private static get API_KEY(): string {
    return process.env.GOOGLE_SAFE_BROWSING_API_KEY || '';
  }

  /**
   * Check URL against Safe Browsing database
   */
  static async checkURL(url: string): Promise<SafeBrowsingResult> {
    // Check if API key is configured
    if (!this.API_KEY) {
      return { isThreat: false, checked: false };
    }

    // Never send private/internal URLs to a third party
    if (!URLAnalyzer.isPublicWebUrl(url)) {
      return { isThreat: false, checked: false };
    }

    try {
      const response = await this.queryAPI(url);
      return { ...this.parseResponse(response), checked: true };
    } catch (error) {
      console.error('Google Safe Browsing API error:', error);
      return { isThreat: false, checked: false };
    }
  }

  /**
   * Query Safe Browsing API
   */
  private static async queryAPI(url: string): Promise<any> {
    const requestBody = {
      client: {
        clientId: 'phishguard-app',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };

    const response = await fetch(`${this.API_BASE_URL}?key=${this.API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) {
      throw new Error(`Safe Browsing API error: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Parse Safe Browsing response
   */
  private static parseResponse(response: any): SafeBrowsingResult {
    // If no matches found, URL is safe
    if (!response.matches || response.matches.length === 0) {
      return { isThreat: false };
    }

    // Get first match (highest priority threat)
    const match = response.matches[0];

    return {
      isThreat: true,
      threatType: match.threatType,
      platformType: match.platformType,
      threatEntryType: match.threatEntryType,
      details: match,
    };
  }

  /**
   * Batch check multiple URLs
   */
  static async checkURLs(urls: string[]): Promise<Map<string, SafeBrowsingResult>> {
    if (!this.API_KEY) {
      return new Map(urls.map(url => [url, { isThreat: false, checked: false }]));
    }

    const publicUrls = urls.filter(url => URLAnalyzer.isPublicWebUrl(url));
    if (publicUrls.length === 0) {
      return new Map(urls.map(url => [url, { isThreat: false, checked: false }]));
    }

    try {
      const requestBody = {
        client: {
          clientId: 'phishguard-app',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION',
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: publicUrls.map(url => ({ url })),
        },
      };

      const response = await fetch(`${this.API_BASE_URL}?key=${this.API_KEY}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      if (!response.ok) {
        throw new Error(`Safe Browsing API error: ${response.statusText}`);
      }

      const data = await response.json();

      // Build results map
      const results = new Map<string, SafeBrowsingResult>();

      // Initialize: public URLs were checked, private ones were not sent
      urls.forEach(url => {
        results.set(url, { isThreat: false, checked: publicUrls.includes(url) });
      });

      // Update with threat matches
      if (data.matches) {
        data.matches.forEach((match: any) => {
          const url = match.threat.url;
          results.set(url, {
            isThreat: true,
            checked: true,
            threatType: match.threatType,
            platformType: match.platformType,
            threatEntryType: match.threatEntryType,
            details: match,
          });
        });
      }

      return results;
    } catch (error) {
      console.error('Google Safe Browsing batch API error:', error);
      return new Map(urls.map(url => [url, { isThreat: false, checked: false }]));
    }
  }

  /**
   * Get threat type description
   */
  static getThreatDescription(threatType: string): string {
    const descriptions: { [key: string]: string } = {
      MALWARE: 'The URL contains malware',
      SOCIAL_ENGINEERING: 'The URL is a phishing or social engineering site',
      UNWANTED_SOFTWARE: 'The URL contains unwanted software',
      POTENTIALLY_HARMFUL_APPLICATION: 'The URL contains potentially harmful applications',
    };

    return descriptions[threatType] || 'Unknown threat type';
  }
}
