/**
 * Domain Intelligence Service
 * Performs RDAP (modern WHOIS) lookups, DNS queries, and domain reputation analysis
 */

import { db } from '@/db';
import { blockedDomains, domainIntelligence, threatIntelligence, trustedDomains } from '@/db/schema';
import { eq, inArray } from 'drizzle-orm';
import { isIP } from 'net';
import { URLAnalyzer, hostMatchesDomain } from './urlAnalyzer';

export interface DomainAnalysisResult {
  domain: string;
  riskScore: number; // 0-100
  indicators: string[];
  /** True when DNS or RDAP returned real data (false → layer is ignored in scoring) */
  hasData: boolean;
  /** 'known' when RDAP gave a registration date, 'unknown' otherwise (no risk added) */
  domainAgeStatus: 'known' | 'unknown';
  whoisData?: {
    registrar?: string;
    createdDate?: Date;
    expiresDate?: Date;
    updatedDate?: Date;
    registrantName?: string;
    registrantOrg?: string;
    domainAge?: number; // days
    source?: 'rdap';
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

interface DomainFacts {
  domainAge?: number;
  ipAddresses: string[];
  mxRecords: string[];
  isKnownPhishing: boolean;
  isKnownMalware: boolean;
}

const RDAP_TIMEOUT_MS = 4000;
const DNS_TIMEOUT_MS = 2500;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Turn domain facts into score + indicators. Used for both fresh and cached
 * results so the two always agree.
 */
function scoreDomainFacts(facts: DomainFacts): { riskScore: number; indicators: string[] } {
  const indicators: string[] = [];
  let riskScore = 0;

  if (facts.domainAge !== undefined) {
    if (facts.domainAge < 30) {
      indicators.push(`Domain was registered only ${facts.domainAge} day(s) ago (newly registered)`);
      riskScore += 45;
    } else if (facts.domainAge < 180) {
      indicators.push('Domain is less than 6 months old');
      riskScore += 20;
    }
  }

  // Only meaningful when the domain resolves at all (otherwise DNS may simply have failed)
  if (facts.ipAddresses.length > 0 && facts.mxRecords.length === 0) {
    indicators.push('No MX records found (suspicious for legitimate domains)');
    riskScore += 10;
  }

  if (facts.isKnownPhishing) {
    indicators.push('Domain flagged as known phishing site');
    riskScore += 50;
  }
  if (facts.isKnownMalware) {
    indicators.push('Domain flagged as malware distributor');
    riskScore += 50;
  }

  return { riskScore: Math.min(riskScore, 100), indicators };
}

export class DomainService {
  /**
   * Analyze domain with caching
   */
  static async analyze(domain: string): Promise<DomainAnalysisResult> {
    const host = this.cleanDomain(domain);
    const cleanDomain = URLAnalyzer.getRegistrableDomain(host);

    // Check cache first
    const cached = await this.getCachedIntelligence(cleanDomain);
    if (cached && cached.lastChecked && cached.cacheExpiry && this.isCacheValid(cached.lastChecked, cached.cacheExpiry)) {
      return this.buildResultFromCache(cached);
    }

    // Perform fresh analysis
    const result = await this.performFreshAnalysis(cleanDomain);

    // Cache the result
    await this.cacheIntelligence(cleanDomain, result);

    return result;
  }

  /** Domains we must never send to RDAP/DNS (IPs, localhost, internal names) */
  private static isPublicDomainName(domain: string): boolean {
    return !isIP(domain) && /^[a-z0-9.-]+$/i.test(domain) && !URLAnalyzer.isInternalHost(domain);
  }

  private static rdapBootstrap?: { servers: Map<string, string>; fetchedAt: number };

  /**
   * RDAP server for a TLD, from IANA's bootstrap registry (cached for a day).
   * Going straight to the registry avoids rdap.org's redirect hop (~2-3s).
   */
  private static async getRdapServer(tld: string): Promise<string | undefined> {
    const cached = this.rdapBootstrap;
    if (!cached || Date.now() - cached.fetchedAt > DAY_MS) {
      try {
        const response = await fetch('https://data.iana.org/rdap/dns.json', { signal: AbortSignal.timeout(RDAP_TIMEOUT_MS) });
        if (response.ok) {
          const data: any = await response.json();
          const servers = new Map<string, string>();
          for (const [tlds, urls] of Array.isArray(data?.services) ? data.services : []) {
            const base = Array.isArray(urls) ? urls.find((u: string) => u.startsWith('https://')) : undefined;
            if (base) for (const t of tlds) servers.set(String(t).toLowerCase(), base.endsWith('/') ? base : `${base}/`);
          }
          this.rdapBootstrap = { servers, fetchedAt: Date.now() };
        }
      } catch {
        // fall through to rdap.org below
      }
    }
    return this.rdapBootstrap?.servers.get(tld);
  }

  /**
   * Registration data via RDAP: the TLD's registry server from IANA bootstrap,
   * falling back to the rdap.org redirector. Returns undefined when unavailable — never guesses.
   */
  private static async performRDAPLookup(domain: string): Promise<DomainAnalysisResult['whoisData'] | undefined> {
    if (!this.isPublicDomainName(domain)) return undefined;

    try {
      const tld = domain.slice(domain.lastIndexOf('.') + 1).toLowerCase();
      const server = await this.getRdapServer(tld);
      const url = server
        ? `${server}domain/${encodeURIComponent(domain)}`
        : `https://rdap.org/domain/${encodeURIComponent(domain)}`;

      const response = await fetch(url, {
        // rdap.org rejects requests without a User-Agent (403)
        headers: { Accept: 'application/rdap+json, application/json', 'User-Agent': 'PhishGuard/2.1 (domain age check)' },
        redirect: 'follow',
        signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
      });
      if (!response.ok) return undefined;

      const data: any = await response.json();
      const events: any[] = Array.isArray(data?.events) ? data.events : [];
      const eventDate = (action: string): Date | undefined => {
        const ev = events.find(e => e?.eventAction === action && e?.eventDate);
        const date = ev ? new Date(ev.eventDate) : undefined;
        return date && !Number.isNaN(date.getTime()) ? date : undefined;
      };

      const createdDate = eventDate('registration');
      if (!createdDate) return undefined;

      // Registrar name lives in the vCard of the entity with role "registrar"
      let registrar: string | undefined;
      const entities: any[] = Array.isArray(data?.entities) ? data.entities : [];
      const registrarEntity = entities.find(e => Array.isArray(e?.roles) && e.roles.includes('registrar'));
      const vcard: any[] = registrarEntity?.vcardArray?.[1] || [];
      const fn = vcard.find((field: any) => Array.isArray(field) && field[0] === 'fn');
      if (fn && typeof fn[3] === 'string') registrar = fn[3];

      return {
        registrar,
        createdDate,
        expiresDate: eventDate('expiration'),
        updatedDate: eventDate('last changed'),
        domainAge: Math.max(0, Math.floor((Date.now() - createdDate.getTime()) / DAY_MS)),
        source: 'rdap',
      };
    } catch {
      return undefined; // timeout, network error, unsupported TLD
    }
  }

  /**
   * Perform fresh domain analysis
   */
  private static async performFreshAnalysis(domain: string): Promise<DomainAnalysisResult> {
    const isPublic = this.isPublicDomainName(domain);
    const [dnsData, whoisData, reputation] = await Promise.all([
      isPublic ? this.performDNSLookup(domain) : Promise.resolve({ ipAddresses: [], mxRecords: [], nsRecords: [], txtRecords: [] }),
      this.performRDAPLookup(domain),
      this.checkReputation(domain),
    ]);

    const { riskScore, indicators } = scoreDomainFacts({
      domainAge: whoisData?.domainAge,
      ipAddresses: dnsData.ipAddresses,
      mxRecords: dnsData.mxRecords,
      isKnownPhishing: reputation.isKnownPhishing,
      isKnownMalware: reputation.isKnownMalware,
    });

    const hasDns = dnsData.ipAddresses.length + dnsData.mxRecords.length + dnsData.nsRecords.length > 0;

    return {
      domain,
      riskScore,
      indicators,
      hasData: hasDns || whoisData?.domainAge !== undefined || reputation.isKnownPhishing || reputation.isKnownMalware,
      domainAgeStatus: whoisData?.domainAge !== undefined ? 'known' : 'unknown',
      whoisData,
      dnsData,
      reputation,
    };
  }

  private static async performDNSLookup(domain: string) {
    const dnsPromises = await import('dns/promises');

    const result = {
      ipAddresses: [] as string[],
      mxRecords: [] as string[],
      nsRecords: [] as string[],
      txtRecords: [] as string[],
    };

    // The OS resolver can stall for many seconds; a slow lookup counts as no data
    const withTimeout = <T,>(promise: Promise<T>): Promise<T> =>
      Promise.race([
        promise,
        new Promise<T>((_, reject) => setTimeout(() => reject(new Error('DNS lookup timed out')), DNS_TIMEOUT_MS).unref?.()),
      ]);

    const [ipResult, mxResult, nsResult, txtResult] = await Promise.allSettled([
      withTimeout(dnsPromises.resolve4(domain)),
      withTimeout(dnsPromises.resolveMx(domain)),
      withTimeout(dnsPromises.resolveNs(domain)),
      withTimeout(dnsPromises.resolveTxt(domain)),
    ]);

    if (ipResult.status === 'fulfilled') result.ipAddresses = ipResult.value;
    if (mxResult.status === 'fulfilled') result.mxRecords = mxResult.value.map(mx => `${mx.priority} ${mx.exchange}`);
    if (nsResult.status === 'fulfilled') result.nsRecords = nsResult.value;
    if (txtResult.status === 'fulfilled') result.txtRecords = txtResult.value.map(records => records.join(''));

    return result;
  }

  private static async checkReputation(domain: string) {
    try {
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
    } catch (error) {
      console.error('Domain reputation lookup failed:', error);
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
    // Recompute age from the stored creation date so it stays accurate
    const createdDate: Date | undefined = cached.createdDate ? new Date(cached.createdDate) : undefined;
    const domainAge = createdDate
      ? Math.max(0, Math.floor((Date.now() - createdDate.getTime()) / DAY_MS))
      : (typeof cached.domainAge === 'number' ? cached.domainAge : undefined);

    const dnsData = {
      ipAddresses: cached.ipAddresses || [],
      mxRecords: cached.mxRecords || [],
      nsRecords: cached.nsRecords || [],
      txtRecords: cached.txtRecords || [],
    };
    const reputation = {
      isKnownPhishing: !!cached.isKnownPhishing,
      isKnownMalware: !!cached.isKnownMalware,
      reportCount: cached.reportCount || 0,
    };

    // Same scoring function as a fresh scan → same score and indicators
    const { riskScore, indicators } = scoreDomainFacts({
      domainAge,
      ipAddresses: dnsData.ipAddresses,
      mxRecords: dnsData.mxRecords,
      isKnownPhishing: reputation.isKnownPhishing,
      isKnownMalware: reputation.isKnownMalware,
    });

    const hasDns = dnsData.ipAddresses.length + dnsData.mxRecords.length + dnsData.nsRecords.length > 0;

    return {
      domain: cached.domain,
      riskScore,
      indicators,
      hasData: hasDns || domainAge !== undefined || reputation.isKnownPhishing || reputation.isKnownMalware,
      domainAgeStatus: domainAge !== undefined ? 'known' : 'unknown',
      whoisData: domainAge !== undefined ? {
        registrar: cached.registrar || undefined,
        createdDate,
        expiresDate: cached.expiresDate || undefined,
        updatedDate: cached.updatedDate || undefined,
        domainAge,
        source: 'rdap',
      } : undefined,
      dnsData,
      reputation,
    };
  }

  private static async cacheIntelligence(domain: string, result: DomainAnalysisResult) {
    const now = new Date();
    const expiry = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes (Ensure live lookups)

    const values = {
      registrar: result.whoisData?.registrar ?? null,
      createdDate: result.whoisData?.createdDate ?? null,
      expiresDate: result.whoisData?.expiresDate ?? null,
      updatedDate: result.whoisData?.updatedDate ?? null,
      ipAddresses: result.dnsData?.ipAddresses || [],
      mxRecords: result.dnsData?.mxRecords || [],
      nsRecords: result.dnsData?.nsRecords || [],
      txtRecords: result.dnsData?.txtRecords || [],
      riskScore: result.riskScore,
      isKnownPhishing: result.reputation.isKnownPhishing,
      isKnownMalware: result.reputation.isKnownMalware,
      reportCount: result.reputation.reportCount,
      domainAge: result.whoisData?.domainAge ?? null,
      lastChecked: now,
      cacheExpiry: expiry,
    };

    try {
      await db.insert(domainIntelligence).values({ domain, ...values }).onConflictDoUpdate({
        target: domainIntelligence.domain,
        set: values,
      });
    } catch (error) {
      console.error('Failed to cache domain intelligence:', error);
    }
  }

  private static cleanDomain(input: string): string {
    try {
      const url = new URL(input.startsWith('http') ? input : `http://${input}`);
      return url.hostname.toLowerCase().replace(/\.$/, '');
    } catch {
      return input.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0].toLowerCase();
    }
  }

  /** The host itself plus every parent up to (and including) the registrable domain */
  private static candidateDomains(host: string): string[] {
    const registrable = URLAnalyzer.getRegistrableDomain(host);
    const candidates = [host];
    let current = host;
    while (current !== registrable && current.includes('.')) {
      current = current.slice(current.indexOf('.') + 1);
      if (hostMatchesDomain(current, registrable)) candidates.push(current);
    }
    if (host.startsWith('www.')) candidates.push(host.slice(4));
    return Array.from(new Set(candidates));
  }

  /**
   * True if the host, or a parent domain of it, is on the trusted list.
   * Multi-tenant hosting (*.github.io, sites.google.com, …) only matches exactly:
   * trusting "github.io" does not make "attacker.github.io" trusted.
   */
  static async isTrustedDomain(domain: string): Promise<boolean> {
    const host = this.cleanDomain(domain);
    const candidates = URLAnalyzer.isMultiTenantHost(host)
      ? [host, host.replace(/^www\./, '')]
      : this.candidateDomains(host);
    const trusted = await db.query.trustedDomains.findFirst({
      where: inArray(trustedDomains.domain, candidates),
    });
    return !!trusted;
  }

  /** True if the host or any parent domain of it is on the blocklist */
  static async isBlockedDomain(domain: string): Promise<boolean> {
    const host = this.cleanDomain(domain);
    const blocked = await db.query.blockedDomains.findFirst({
      where: inArray(blockedDomains.domain, this.candidateDomains(host)),
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
