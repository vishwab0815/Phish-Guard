/**
 * IP Intelligence Service
 * Provides IP geolocation, reputation, and threat analysis
 */

import { db } from '@/db';
import { ipIntelligence } from '@/db/schema';
import { eq, sql } from 'drizzle-orm';

export interface IPAnalysisResult {
  ipAddress: string;
  riskScore: number; // 0-100
  indicators: string[];
  geolocation?: {
    country?: string;
    countryCode?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    timezone?: string;
  };
  network?: {
    asn?: string;
    asnOrg?: string;
    isp?: string;
    organization?: string;
  };
  reputation: {
    abuseScore: number; // 0-100
    threatScore: number; // 0-100
    isProxy: boolean;
    isVPN: boolean;
    isTor: boolean;
    isDataCenter: boolean;
    isHosting: boolean;
    isBlacklisted: boolean;
    blacklistCount: number;
    isBot: boolean;
  };
}

export class IPService {
  /**
   * Analyze IP address
   */
  static async analyze(ipAddress: string): Promise<IPAnalysisResult> {
    if (!this.isValidIP(ipAddress)) {
      return this.createInvalidResult(ipAddress);
    }

    // Check cache first
    const cached = await this.getCachedIntelligence(ipAddress);
    if (cached && this.isCacheValid(cached.lastChecked!)) {
      return this.buildResultFromCache(cached);
    }

    // Perform fresh analysis
    const result = await this.performFreshAnalysis(ipAddress);

    // Cache the result
    await this.cacheIntelligence(ipAddress, result);

    return result;
  }

  private static async performFreshAnalysis(ipAddress: string): Promise<IPAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    const geolocation = await this.fetchGeolocation(ipAddress);
    const network = await this.fetchNetworkInfo(ipAddress);
    const reputation = await this.fetchReputationData(ipAddress);

    if (reputation.isBlacklisted) {
      indicators.push('IP is blacklisted on threat intelligence feeds');
      riskScore += 50;
    }

    if (reputation.blacklistCount > 0) {
      indicators.push(`IP appears on ${reputation.blacklistCount} blacklists`);
      riskScore += Math.min(reputation.blacklistCount * 10, 40);
    }

    if (reputation.abuseScore > 50) {
      indicators.push(`High abuse score: ${reputation.abuseScore}/100`);
      riskScore += 30;
    }

    if (reputation.isProxy || reputation.isVPN) {
      indicators.push('IP is a proxy or VPN service');
      riskScore += 15;
    }

    if (reputation.isTor) {
      indicators.push('IP is a Tor exit node');
      riskScore += 25;
    }

    if (reputation.isDataCenter || reputation.isHosting) {
      indicators.push('IP belongs to a data center or hosting provider');
      riskScore += 10;
    }

    if (reputation.isBot) {
      indicators.push('IP associated with bot activity');
      riskScore += 20;
    }

    riskScore = Math.min(riskScore, 100);

    return {
      ipAddress,
      riskScore,
      indicators,
      geolocation,
      network,
      reputation,
    };
  }

  private static async fetchGeolocation(ipAddress: string) {
    return {};
  }

  private static async fetchNetworkInfo(ipAddress: string) {
    return {};
  }

  private static async fetchReputationData(ipAddress: string) {
    return {
      abuseScore: 0,
      threatScore: 0,
      isProxy: false,
      isVPN: false,
      isTor: false,
      isDataCenter: false,
      isHosting: false,
      isBlacklisted: false,
      blacklistCount: 0,
      isBot: false,
    };
  }

  private static isValidIP(ipAddress: string): boolean {
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Pattern.test(ipAddress)) {
      const octets = ipAddress.split('.');
      return octets.every(octet => {
        const num = parseInt(octet);
        return num >= 0 && num <= 255;
      });
    }
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
    return ipv6Pattern.test(ipAddress);
  }

  private static createInvalidResult(ipAddress: string): IPAnalysisResult {
    return {
      ipAddress,
      riskScore: 0,
      indicators: ['Invalid IP address format'],
      reputation: {
        abuseScore: 0,
        threatScore: 0,
        isProxy: false,
        isVPN: false,
        isTor: false,
        isDataCenter: false,
        isHosting: false,
        isBlacklisted: false,
        blacklistCount: 0,
        isBot: false,
      },
    };
  }

  private static async getCachedIntelligence(ipAddress: string) {
    try {
      return await db.query.ipIntelligence.findFirst({
        where: eq(ipIntelligence.ipAddress, ipAddress),
      });
    } catch {
      return null;
    }
  }

  private static isCacheValid(lastChecked: Date): boolean {
    const now = new Date();
    const maxAge = 24 * 60 * 60 * 1000;
    return (now.getTime() - lastChecked.getTime()) < maxAge;
  }

  private static buildResultFromCache(cached: any): IPAnalysisResult {
    const indicators: string[] = [];
    if (cached.isBlacklisted) indicators.push('IP is blacklisted on threat intelligence feeds');
    if (cached.blacklistCount > 0) indicators.push(`IP appears on ${cached.blacklistCount} blacklists`);
    if (cached.abuseScore > 50) indicators.push(`High abuse score: ${cached.abuseScore}/100`);
    if (cached.isProxy || cached.isVPN) indicators.push('IP is a proxy or VPN service');
    if (cached.isTor) indicators.push('IP is a Tor exit node');
    if (cached.isBot) indicators.push('IP associated with bot activity');

    return {
      ipAddress: cached.ipAddress,
      riskScore: cached.threatScore,
      indicators,
      geolocation: {
        country: cached.country || undefined,
        countryCode: cached.countryCode || undefined,
        region: cached.region || undefined,
        city: cached.city || undefined,
        latitude: cached.latitude || undefined,
        longitude: cached.longitude || undefined,
        timezone: cached.timezone || undefined,
      },
      network: {
        asn: cached.asn || undefined,
        asnOrg: cached.asnOrg || undefined,
        isp: cached.isp || undefined,
        organization: cached.organization || undefined,
      },
      reputation: {
        abuseScore: cached.abuseScore,
        threatScore: cached.threatScore,
        isProxy: cached.isProxy,
        isVPN: cached.isVPN,
        isTor: cached.isTor,
        isDataCenter: cached.isDataCenter,
        isHosting: cached.isHosting,
        isBlacklisted: cached.isBlacklisted,
        blacklistCount: cached.blacklistCount,
        isBot: cached.isBot,
      },
    };
  }

  private static async cacheIntelligence(ipAddress: string, result: IPAnalysisResult) {
    const now = new Date();
    try {
      await db.insert(ipIntelligence).values({
        ipAddress,
        country: result.geolocation?.country,
        countryCode: result.geolocation?.countryCode,
        region: result.geolocation?.region,
        city: result.geolocation?.city,
        latitude: result.geolocation?.latitude,
        longitude: result.geolocation?.longitude,
        timezone: result.geolocation?.timezone,
        asn: result.network?.asn,
        asnOrg: result.network?.asnOrg,
        isp: result.network?.isp,
        organization: result.network?.organization,
        abuseScore: result.reputation.abuseScore,
        threatScore: result.reputation.threatScore,
        isProxy: result.reputation.isProxy,
        isVPN: result.reputation.isVPN,
        isTor: result.reputation.isTor,
        isDataCenter: result.reputation.isDataCenter,
        isHosting: result.reputation.isHosting,
        isBlacklisted: result.reputation.isBlacklisted,
        blacklistCount: result.reputation.blacklistCount,
        isBot: result.reputation.isBot,
        firstSeen: now,
        lastChecked: now,
        checkCount: 1,
      }).onConflictDoUpdate({
        target: ipIntelligence.ipAddress,
        set: {
          country: result.geolocation?.country,
          countryCode: result.geolocation?.countryCode,
          region: result.geolocation?.region,
          city: result.geolocation?.city,
          latitude: result.geolocation?.latitude,
          longitude: result.geolocation?.longitude,
          timezone: result.geolocation?.timezone,
          asn: result.network?.asn,
          asnOrg: result.network?.asnOrg,
          isp: result.network?.isp,
          organization: result.network?.organization,
          abuseScore: result.reputation.abuseScore,
          threatScore: result.reputation.threatScore,
          isProxy: result.reputation.isProxy,
          isVPN: result.reputation.isVPN,
          isTor: result.reputation.isTor,
          isDataCenter: result.reputation.isDataCenter,
          isHosting: result.reputation.isHosting,
          isBlacklisted: result.reputation.isBlacklisted,
          blacklistCount: result.reputation.blacklistCount,
          isBot: result.reputation.isBot,
          lastChecked: now,
          checkCount: sql`${ipIntelligence.checkCount} + 1`,
        },
      });
    } catch (error) {
      console.error('Failed to cache IP intelligence:', error);
    }
  }

  static extractIPFromURL(url: string): string | null {
    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname;
      if (this.isValidIP(hostname)) return hostname;
    } catch {}
    return null;
  }

  static isPrivateIP(ipAddress: string): boolean {
    if (!this.isValidIP(ipAddress)) return false;
    const octets = ipAddress.split('.').map(Number);
    if (octets[0] === 10) return true;
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    if (octets[0] === 192 && octets[1] === 168) return true;
    if (octets[0] === 127) return true;
    return false;
  }
}
