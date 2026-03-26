/**
 * VirusTotal API Integration
 * Provides URL and file scanning using VirusTotal's threat intelligence
 */

import { db } from '@/db';
import { scanResults, externalScanResults } from '@/db/schema';
import { eq, and, desc, gte, count } from 'drizzle-orm';

export interface VirusTotalResult {
  isPhishing: boolean;
  isMalware: boolean;
  isSpam: boolean;
  confidence: number; // 0-100
  detectionCount: number; // Engines that detected threat
  totalEngines: number; // Total engines checked
  threatCategories: string[];
  scanDate: Date;
  rawResponse?: any;
}

export class VirusTotalService {
  private static readonly API_BASE_URL = 'https://www.virustotal.com/api/v3';
  private static readonly API_KEY = process.env.VIRUSTOTAL_API_KEY || '';

  /**
   * Analyze URL using VirusTotal
   */
  static async analyzeURL(url: string): Promise<VirusTotalResult> {
    // Check cache first
    const cached = await this.getCachedResult(url, 'virustotal');
    if (cached && this.isCacheValid(cached.scanDate || new Date(0))) {
      return this.buildResultFromCache(cached);
    }

    // Check if API key is configured
    if (!this.API_KEY) {
      console.warn('VirusTotal API key not configured');
      return this.getDefaultResult();
    }

    try {
      // Submit URL for analysis
      const urlId = this.encodeURL(url);
      const response = await this.fetchAnalysis(url, urlId);

      const result = this.parseResponse(response);

      // Cache the result
      await this.cacheResult(url, result);

      return result;
    } catch (error) {
      console.error('VirusTotal API error:', error);
      return this.getDefaultResult();
    }
  }

  /**
   * Encode URL for VirusTotal API
   */
  private static encodeURL(url: string): string {
    // VirusTotal uses base64url encoding without padding
    return Buffer.from(url)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Fetch analysis from VirusTotal
   */
  private static async fetchAnalysis(originalUrl: string, urlId: string): Promise<any> {
    const response = await fetch(`${this.API_BASE_URL}/urls/${urlId}`, {
      method: 'GET',
      headers: {
        'x-apikey': this.API_KEY,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        // URL not in database, submit it with original URL
        return await this.submitURL(originalUrl);
      }
      throw new Error(`VirusTotal API error: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Submit URL to VirusTotal for scanning
   */
  private static async submitURL(url: string): Promise<any> {
    const formData = new URLSearchParams();
    formData.append('url', url);

    const response = await fetch(`${this.API_BASE_URL}/urls`, {
      method: 'POST',
      headers: {
        'x-apikey': this.API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`VirusTotal submission error: ${response.statusText}`);
    }

    const data = await response.json();

    // Wait a bit and fetch the analysis
    await new Promise(resolve => setTimeout(resolve, 5000));

    const analysisId = data.data.id;
    return await this.fetchAnalysisById(analysisId);
  }

  /**
   * Fetch analysis by ID
   */
  private static async fetchAnalysisById(analysisId: string): Promise<any> {
    const response = await fetch(`${this.API_BASE_URL}/analyses/${analysisId}`, {
      method: 'GET',
      headers: {
        'x-apikey': this.API_KEY,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`VirusTotal analysis fetch error: ${response.statusText}`);
    }

    return await response.json();
  }

  /**
   * Parse VirusTotal response
   */
  private static parseResponse(response: any): VirusTotalResult {
    const stats = response.data?.attributes?.last_analysis_stats || {};
    const results = response.data?.attributes?.last_analysis_results || {};

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const totalEngines = malicious + suspicious + harmless + undetected;

    const detectionCount = malicious + suspicious;

    // Determine threat types
    const threatCategories: string[] = [];
    let isPhishing = false;
    let isMalware = false;
    let isSpam = false;

    Object.values(results).forEach((result: any) => {
      if (result.category === 'malicious') {
        const category = result.result?.toLowerCase() || '';

        if (category.includes('phish')) {
          isPhishing = true;
          if (!threatCategories.includes('phishing')) {
            threatCategories.push('phishing');
          }
        }

        if (category.includes('malware') || category.includes('trojan')) {
          isMalware = true;
          if (!threatCategories.includes('malware')) {
            threatCategories.push('malware');
          }
        }

        if (category.includes('spam')) {
          isSpam = true;
          if (!threatCategories.includes('spam')) {
            threatCategories.push('spam');
          }
        }
      }
    });

    // Calculate confidence based on detection ratio
    const confidence = totalEngines > 0
      ? Math.round((detectionCount / totalEngines) * 100)
      : 0;

    return {
      isPhishing,
      isMalware,
      isSpam,
      confidence,
      detectionCount,
      totalEngines,
      threatCategories,
      scanDate: new Date(),
      rawResponse: response,
    };
  }

  /**
   * Get default result when API is unavailable
   */
  private static getDefaultResult(): VirusTotalResult {
    return {
      isPhishing: false,
      isMalware: false,
      isSpam: false,
      confidence: 0,
      detectionCount: 0,
      totalEngines: 0,
      threatCategories: [],
      scanDate: new Date(),
    };
  }

  /**
   * Get cached result
   */
  private static async getCachedResult(url: string, provider: string) {
    try {
      // Find recent scan result
      const recentScan = await db.query.scanResults.findFirst({
        where: and(
          eq(scanResults.target, url),
          eq(scanResults.type, 'URL')
        ),
        orderBy: [desc(scanResults.timestamp)],
      });

      if (!recentScan) return null;

      const externalResult = await db.query.externalScanResults.findFirst({
        where: and(
          eq(externalScanResults.scanResultId, recentScan.id),
          eq(externalScanResults.provider, provider)
        ),
        orderBy: [desc(externalScanResults.createdAt)],
      });

      return externalResult || null;
    } catch {
      return null;
    }
  }

  /**
   * Check if cache is valid (24 hours)
   */
  private static isCacheValid(scanDate: Date): boolean {
    const now = new Date();
    const cacheAge = now.getTime() - scanDate.getTime();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    return cacheAge < maxAge;
  }

  /**
   * Build result from cached data
   */
  private static buildResultFromCache(cached: any): VirusTotalResult {
    return {
      isPhishing: cached.isPhishing,
      isMalware: cached.isMalware,
      isSpam: cached.isSpam,
      confidence: cached.confidence || 0,
      detectionCount: cached.detectionCount,
      totalEngines: cached.totalEngines,
      threatCategories: cached.threatType ? [cached.threatType] : [],
      scanDate: cached.scanDate,
      rawResponse: cached.rawResponse,
    };
  }

  /**
   * Cache scan result
   */
  private static async cacheResult(url: string, result: VirusTotalResult): Promise<void> {
    try {
      // Find recent scan result
      const scanResultData = await db.query.scanResults.findFirst({
        where: and(
          eq(scanResults.target, url),
          eq(scanResults.type, 'URL')
        ),
        orderBy: [desc(scanResults.timestamp)],
      });

      if (!scanResultData) {
        console.warn('No scan result found to attach VirusTotal data');
        return;
      }

      // Create external scan result
      await db.insert(externalScanResults).values({
        id: crypto.randomUUID(),
        scanResultId: scanResultData.id,
        provider: 'virustotal',
        rawResponse: result.rawResponse || {},
        isPhishing: result.isPhishing,
        isMalware: result.isMalware,
        isSpam: result.isSpam,
        threatType: result.threatCategories[0],
        confidence: result.confidence,
        detectionCount: result.detectionCount,
        totalEngines: result.totalEngines,
        scanDate: result.scanDate,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        createdAt: new Date(),
      });
    } catch (error) {
      console.error('Failed to cache VirusTotal result:', error);
    }
  }

  /**
   * Check API rate limits
   */
  static async checkRateLimit(): Promise<{
    remaining: number;
    limit: number;
    resetTime: Date;
  }> {
    // VirusTotal free tier: 4 requests/minute, 500/day
    const DAILY_LIMIT = 500;
    const resetTime = new Date();
    resetTime.setHours(24, 0, 0, 0); // Reset at midnight

    try {
      const todayStart = new Date();
      todayStart.setHours(0, 0, 0, 0);

      const [result] = await db
        .select({ value: count() })
        .from(externalScanResults)
        .where(
          and(
            eq(externalScanResults.provider, 'virustotal'),
            gte(externalScanResults.createdAt, todayStart)
          )
        );

      const todayUsage = result.value;

      return {
        remaining: Math.max(0, DAILY_LIMIT - todayUsage),
        limit: DAILY_LIMIT,
        resetTime,
      };
    } catch {
      // Fallback if DB query fails
      return {
        remaining: DAILY_LIMIT,
        limit: DAILY_LIMIT,
        resetTime,
      };
    }
  }
}
