/**
 * Domain Intelligence Service
 * Performs WHOIS lookups, DNS queries, and domain reputation analysis
 */

import { db } from '@/db';
import { blockedDomains, domainIntelligence, threatIntelligence, trustedDomains } from '@/db/schema';
import { eq, and, gte } from 'drizzle-orm';

export interface DomainAnalysisResult {
  domain: string;
  riskScore: number; // 0-100
  indicators: string[];
  whoisData?: {
    registrar?: string;
    createdDate?: Date;
    expiresDate?: Date;
    updatedDate?: Date;
    registrantName?: string;
    registrantOrg?: string;
    domainAge?: number; // days
  };
  dnsData?: {
    ipAddresses: string[];
    mxRecords: string[];
    nsRecords: string[];
    txtRecords: string[];
  };
  reputation: {
    isKnownPhishing: boolean;
    isKnownMalware: boolean;
    reportCount: number;
  };
}

export class DomainService {
  /**
   * Analyze domain with caching
   */
  static async analyze(domain: string): Promise<DomainAnalysisResult> {
    const cleanDomain = this.cleanDomain(domain);

    // Check cache first
    const cached = await this.getCachedIntelligence(cleanDomain);
    if (cached && this.isCacheValid(cached.lastChecked!, cached.cacheExpiry!)) {
      return this.buildResultFromCache(cached);
    }

    // Perform fresh analysis
    const result = await this.performFreshAnalysis(cleanDomain);

    // Cache the result
    await this.cacheIntelligence(cleanDomain, result);

    return result;
  }

  private static async performWHOISLookup(domain: string): Promise<{
    registrar?: string;
    createdDate?: Date;
    expiresDate?: Date;
    updatedDate?: Date;
    registrantName?: string;
    registrantOrg?: string;
    domainAge?: number;
  } | undefined> {
    return undefined;
  }

  /**
   * Perform fresh domain analysis
   */
  private static async performFreshAnalysis(domain: string): Promise<DomainAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    const dnsData = await this.performDNSLookup(domain);
    const whoisData = await this.performWHOISLookup(domain);

    if (whoisData?.domainAge !== undefined) {
      if (whoisData.domainAge < 30) {
        indicators.push('Domain is less than 30 days old');
        riskScore += 30;
      } else if (whoisData.domainAge < 180) {
        indicators.push('Domain is less than 6 months old');
        riskScore += 15;
      }
    }

    if (whoisData?.registrantName?.toLowerCase().includes('privacy')) {
      indicators.push('WHOIS privacy protection enabled');
      riskScore += 10;
    }

    if (dnsData.mxRecords.length === 0) {
      indicators.push('No MX records found (suspicious for legitimate domains)');
      riskScore += 10;
    }

    const reputation = await this.checkReputation(domain);
    if (reputation.isKnownPhishing) {
      indicators.push('Domain flagged as known phishing site');
      riskScore += 50;
    }
    if (reputation.isKnownMalware) {
      indicators.push('Domain flagged as malware distributor');
      riskScore += 50;
    }

    riskScore = Math.min(riskScore, 100);

    return {
      domain,
      riskScore,
      indicators,
      whoisData,
      dnsData,
      reputation,
    };
  }

  private static async performDNSLookup(domain: string) {
    const dns = await import('dns');
    const dnsPromises = dns.promises;

    const result = {
      ipAddresses: [] as string[],
      mxRecords: [] as string[],
      nsRecords: [] as string[],
      txtRecords: [] as string[],
    };

    const [ipResult, mxResult, nsResult, txtResult] = await Promise.allSettled([
      dnsPromises.resolve4(domain),
      dnsPromises.resolveMx(domain),
      dnsPromises.resolveNs(domain),
      dnsPromises.resolveTxt(domain),
    ]);

    if (ipResult.status === 'fulfilled') result.ipAddresses = ipResult.value;
    if (mxResult.status === 'fulfilled') result.mxRecords = mxResult.value.map(mx => `${mx.priority} ${mx.exchange}`);
    if (nsResult.status === 'fulfilled') result.nsRecords = nsResult.value;
    if (txtResult.status === 'fulfilled') result.txtRecords = txtResult.value.map(records => records.join(''));

    return result;
  }

  private static async fetchCertificate(domain: string): Promise<{
    issuer: string;
    subject: string;
    validFrom: Date;
    validUntil: Date;
    serialNumber: string;
    fingerprint: string;
    algorithm: string;
    keySize?: number;
  } | null> {
    return null; // Placeholder
  }

  private static async checkReputation(domain: string) {
    const blocked = await db.query.blockedDomains.findFirst({
      where: eq(blockedDomains.domain, domain),
    });

    if (blocked) {
      return { isKnownPhishing: true, isKnownMalware: false, reportCount: 1 };
    }

    const intel = await db.query.threatIntelligence.findFirst({
      where: eq(threatIntelligence.domain, domain),
    });

    if (intel && intel.reputation < 30) {
      return { isKnownPhishing: true, isKnownMalware: false, reportCount: 1 };
    }

    return { isKnownPhishing: false, isKnownMalware: false, reportCount: 0 };
  }

  private static async getCachedIntelligence(domain: string) {
    try {
      return await db.query.domainIntelligence.findFirst({
        where: eq(domainIntelligence.domain, domain),
      });
    } catch {
      return null;
    }
  }

  private static isCacheValid(lastChecked: Date, cacheExpiry: Date): boolean {
    return new Date() < cacheExpiry;
  }

  private static buildResultFromCache(cached: any): DomainAnalysisResult {
    const indicators: string[] = [];
    if (cached.isKnownPhishing) indicators.push('Domain flagged as known phishing site');
    if (cached.isKnownMalware) indicators.push('Domain flagged as malware distributor');
    if (cached.domainAge !== null && cached.domainAge < 30) indicators.push('Domain is less than 30 days old');

    return {
      domain: cached.domain,
      riskScore: cached.riskScore,
      indicators,
      whoisData: {
        registrar: cached.registrar,
        createdDate: cached.createdDate,
        expiresDate: cached.expiresDate,
        updatedDate: cached.updatedDate,
        registrantName: cached.registrantName,
        registrantOrg: cached.registrantOrg,
        domainAge: cached.domainAge,
      },
      dnsData: {
        ipAddresses: cached.ipAddresses || [],
        mxRecords: cached.mxRecords || [],
        nsRecords: cached.nsRecords || [],
        txtRecords: cached.txtRecords || [],
      },
      reputation: {
        isKnownPhishing: cached.isKnownPhishing,
        isKnownMalware: cached.isKnownMalware,
        reportCount: cached.reportCount,
      },
    };
  }

  private static async cacheIntelligence(domain: string, result: DomainAnalysisResult) {
    const now = new Date();
    const expiry = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes (Ensure live lookups)

    try {
      await db.insert(domainIntelligence).values({
        domain,
        registrar: result.whoisData?.registrar,
        createdDate: result.whoisData?.createdDate,
        expiresDate: result.whoisData?.expiresDate,
        updatedDate: result.whoisData?.updatedDate,
        registrantName: result.whoisData?.registrantName,
        registrantOrg: result.whoisData?.registrantOrg,
        ipAddresses: result.dnsData?.ipAddresses || [],
        mxRecords: result.dnsData?.mxRecords || [],
        nsRecords: result.dnsData?.nsRecords || [],
        txtRecords: result.dnsData?.txtRecords || [],
        riskScore: result.riskScore,
        isKnownPhishing: result.reputation.isKnownPhishing,
        isKnownMalware: result.reputation.isKnownMalware,
        reportCount: result.reputation.reportCount,
        domainAge: result.whoisData?.domainAge,
        lastChecked: now,
        cacheExpiry: expiry,
      }).onConflictDoUpdate({
        target: domainIntelligence.domain,
        set: {
          registrar: result.whoisData?.registrar,
          createdDate: result.whoisData?.createdDate,
          expiresDate: result.whoisData?.expiresDate,
          updatedDate: result.whoisData?.updatedDate,
          registrantName: result.whoisData?.registrantName,
          registrantOrg: result.whoisData?.registrantOrg,
          ipAddresses: result.dnsData?.ipAddresses || [],
          mxRecords: result.dnsData?.mxRecords || [],
          nsRecords: result.dnsData?.nsRecords || [],
          txtRecords: result.dnsData?.txtRecords || [],
          riskScore: result.riskScore,
          isKnownPhishing: result.reputation.isKnownPhishing,
          isKnownMalware: result.reputation.isKnownMalware,
          reportCount: result.reputation.reportCount,
          domainAge: result.whoisData?.domainAge,
          lastChecked: now,
          cacheExpiry: expiry,
        },
      });
    } catch (error) {
      console.error('Failed to cache domain intelligence:', error);
    }
  }

  private static cleanDomain(input: string): string {
    try {
      const url = new URL(input.startsWith('http') ? input : `http://${input}`);
      return url.hostname;
    } catch {
      return input.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0];
    }
  }

  static async isTrustedDomain(domain: string): Promise<boolean> {
    const cleanDomain = this.cleanDomain(domain);
    const trusted = await db.query.trustedDomains.findFirst({
      where: eq(trustedDomains.domain, cleanDomain),
    });
    return !!trusted;
  }

  static async isBlockedDomain(domain: string): Promise<boolean> {
    const cleanDomain = this.cleanDomain(domain);
    const blocked = await db.query.blockedDomains.findFirst({
      where: eq(blockedDomains.domain, cleanDomain),
    });
    return !!blocked;
  }

  static async blockDomain(domain: string, reason: string, addedBy?: string) {
    const cleanDomain = this.cleanDomain(domain);
    await db.insert(blockedDomains).values({
      domain: cleanDomain,
      reason,
      addedBy,
    }).onConflictDoUpdate({
      target: blockedDomains.domain,
      set: { reason, addedBy },
    });
  }

  static async trustDomain(domain: string, reason?: string, addedBy?: string) {
    const cleanDomain = this.cleanDomain(domain);
    await db.insert(trustedDomains).values({
      domain: cleanDomain,
      reason,
      addedBy,
    }).onConflictDoUpdate({
      target: trustedDomains.domain,
      set: { reason, addedBy },
    });
  }
}
