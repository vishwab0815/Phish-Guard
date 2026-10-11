/**
 * SSL/TLS Certificate Validation Service
 * Analyzes SSL certificates for security issues and trust indicators.
 *
 * What is checked: chain trust (as Node/OpenSSL sees it), hostname match,
 * expiry, self-signing and key strength. What is NOT checked: revocation
 * (no OCSP/CRL) and EV status — those are reported as unknown, never as "ok".
 */

import { db } from '@/db';
import { certificateInfo } from '@/db/schema';
import { eq, desc } from 'drizzle-orm';
import tls from 'tls';
import { isIP } from 'net';
import { resolvePublicHost, BlockedHostError } from '@/lib/netGuard';

const CONNECT_TIMEOUT_MS = 5000;
const DAY_MS = 24 * 60 * 60 * 1000;

export interface SSLAnalysisResult {
  hostname: string;
  isValid: boolean; // a certificate was retrieved and is trusted for this hostname
  certificateAvailable: boolean; // false → no data (connection failed); not scored
  riskScore: number; // 0-100
  indicators: string[];
  fromCache?: boolean;
  certificateDetails?: {
    issuer: string;
    subject: string;
    validFrom: Date;
    validUntil: Date;
    serialNumber: string;
    fingerprint: string;
    algorithm?: string; // signature algorithm, when the runtime exposes it
    keyType?: 'RSA' | 'EC' | 'unknown';
    keySize?: number;
    subjectAltNames?: string[];
  };
  trustAnalysis: {
    isSelfSigned: boolean;
    isWildcard: boolean;
    chainValid: boolean; // socket.authorized
    authorizationError?: string; // socket.authorizationError (fresh scans only)
    hostnameMatches: boolean;
    isExpired: boolean;
    hasWeakKey: boolean;
    hasWeakSignature: boolean;
    revocationStatus: 'not_checked';
    trustScore: number; // 0-100 (= 100 - riskScore)
  };
}

/** Everything needed to score a certificate; stored in the cache table */
interface CertFacts {
  hostname: string;
  subject: string;
  issuer: string;
  validFrom: Date;
  validUntil: Date;
  chainValid: boolean;
  isSelfSigned: boolean;
  sans: string[]; // e.g. ["DNS:example.com", "IP Address:1.2.3.4"]
  keyType: 'RSA' | 'EC' | 'unknown';
  keySize?: number;
  signatureAlgorithm?: string;
  authorizationError?: string;
}

type FetchedCert = Omit<CertFacts, 'hostname'> & { serialNumber: string; fingerprint: string };

const WEAK_SIGNATURE = /md5|sha1(?!\d)|md2/i;

/** RFC 6125-style hostname match against SAN DNS/IP entries (CN only when no SANs) */
function hostnameMatchesCert(hostname: string, sans: string[], subject: string): boolean {
  const host = hostname.toLowerCase();
  const dnsNames = sans.filter(s => s.startsWith('DNS:')).map(s => s.slice(4).trim().toLowerCase());
  const ipNames = sans.filter(s => s.startsWith('IP Address:')).map(s => s.slice(11).trim().toLowerCase());

  if (isIP(host)) return ipNames.includes(host);

  const names = dnsNames.length > 0 ? dnsNames : (subject.match(/CN=([^,]+)/)?.slice(1, 2).map(s => s.trim().toLowerCase()) ?? []);
  return names.some(name => {
    if (name === host) return true;
    if (name.startsWith('*.')) {
      const suffix = name.slice(1); // ".example.com"
      return host.endsWith(suffix) && !host.slice(0, -suffix.length).includes('.') && host.length > suffix.length;
    }
    return false;
  });
}

/**
 * Score a certificate from its facts. Fresh scans and cached results both go
 * through here, so they always produce the same score.
 */
function scoreCertificate(facts: CertFacts, now: Date = new Date()) {
  const indicators: string[] = [];
  let riskScore = 0;

  const isExpired = now > facts.validUntil || now < facts.validFrom;
  const hostnameMatches = hostnameMatchesCert(facts.hostname, facts.sans, facts.subject);
  const hasWeakKey = facts.keySize !== undefined && (
    (facts.keyType === 'RSA' && facts.keySize < 2048) ||
    (facts.keyType === 'EC' && facts.keySize < 256)
  );
  const hasWeakSignature = !!facts.signatureAlgorithm && WEAK_SIGNATURE.test(facts.signatureAlgorithm);

  if (facts.isSelfSigned) { indicators.push('Self-signed certificate detected'); riskScore += 40; }
  if (isExpired) { indicators.push('Certificate has expired or is not yet valid'); riskScore += 50; }
  if (!hostnameMatches) { indicators.push(`Certificate is not issued for ${facts.hostname}`); riskScore += 30; }
  // Untrusted chain not already explained by the findings above
  if (!facts.chainValid && !facts.isSelfSigned && !isExpired && hostnameMatches) {
    indicators.push(`Certificate chain is not trusted${facts.authorizationError ? ` (${facts.authorizationError})` : ''}`);
    riskScore += 30;
  }
  if (hasWeakKey) { indicators.push(`Weak ${facts.keyType} key size: ${facts.keySize} bits`); riskScore += 25; }
  if (hasWeakSignature) { indicators.push(`Weak signature algorithm: ${facts.signatureAlgorithm}`); riskScore += 20; }

  const ageDays = Math.floor((now.getTime() - facts.validFrom.getTime()) / DAY_MS);
  const remainingDays = Math.floor((facts.validUntil.getTime() - now.getTime()) / DAY_MS);
  if (!isExpired && ageDays < 7) { indicators.push('Certificate was issued in the last 7 days'); riskScore += 5; }
  if (!isExpired && remainingDays < 14) { indicators.push('Certificate expires within 14 days'); riskScore += 5; }

  riskScore = Math.min(riskScore, 100);

  return {
    riskScore,
    indicators,
    isExpired,
    hostnameMatches,
    hasWeakKey,
    hasWeakSignature,
  };
}

export class SSLValidator {
  /**
   * Analyze the TLS certificate served for a hostname (or URL).
   * Throws BlockedHostError for private/internal targets.
   */
  static async analyze(domainOrHost: string): Promise<SSLAnalysisResult> {
    const hostname = this.cleanHost(domainOrHost);

    // SSRF guard first — also for cached hosts, since DNS may have changed.
    // BlockedHostError propagates (routes turn it into a 400).
    let address: string;
    try {
      ({ address } = await resolvePublicHost(hostname));
    } catch (error) {
      if (error instanceof BlockedHostError) throw error;
      return this.unavailableResult(hostname, 'Hostname does not resolve in DNS — no TLS certificate to check');
    }

    // Check cache first
    const cached = await this.getCachedCertificate(hostname);
    if (cached && cached.lastChecked && this.isCacheValid(cached.lastChecked)) {
      return this.buildResultFromCache(hostname, cached);
    }

    // Perform fresh TLS handshake against the vetted IP
    const fetched = await this.fetchCertificate(hostname, address);

    if (!fetched) {
      return this.unavailableResult(hostname, 'Could not retrieve a TLS certificate (connection failed or timed out)');
    }

    const result = this.buildResult({ ...fetched, hostname }, fetched.serialNumber, fetched.fingerprint, false);
    await this.cacheCertificate(hostname, result, fetched);
    return result;
  }

  /** No certificate data: reported, but contributes no risk (the layer is skipped in scoring) */
  private static unavailableResult(hostname: string, reason: string): SSLAnalysisResult {
    return {
      hostname,
      isValid: false,
      certificateAvailable: false,
      riskScore: 0,
      indicators: [reason],
      trustAnalysis: {
        isSelfSigned: false,
        isWildcard: false,
        chainValid: false,
        hostnameMatches: false,
        isExpired: false,
        hasWeakKey: false,
        hasWeakSignature: false,
        revocationStatus: 'not_checked',
        trustScore: 0,
      },
    };
  }

  private static buildResult(facts: CertFacts, serialNumber: string, fingerprint: string, fromCache: boolean): SSLAnalysisResult {
    const scored = scoreCertificate(facts);
    return {
      hostname: facts.hostname,
      isValid: facts.chainValid && scored.hostnameMatches && !scored.isExpired,
      certificateAvailable: true,
      riskScore: scored.riskScore,
      indicators: scored.indicators,
      fromCache,
      certificateDetails: {
        issuer: facts.issuer,
        subject: facts.subject,
        validFrom: facts.validFrom,
        validUntil: facts.validUntil,
        serialNumber,
        fingerprint,
        algorithm: facts.signatureAlgorithm,
        keyType: facts.keyType,
        keySize: facts.keySize,
        subjectAltNames: facts.sans,
      },
      trustAnalysis: {
        isSelfSigned: facts.isSelfSigned,
        isWildcard: facts.sans.some(s => s.includes('*')) || facts.subject.includes('*'),
        chainValid: facts.chainValid,
        authorizationError: facts.authorizationError,
        hostnameMatches: scored.hostnameMatches,
        isExpired: scored.isExpired,
        hasWeakKey: scored.hasWeakKey,
        hasWeakSignature: scored.hasWeakSignature,
        revocationStatus: 'not_checked',
        trustScore: 100 - scored.riskScore,
      },
    };
  }

  private static fetchCertificate(hostname: string, address: string): Promise<FetchedCert | null> {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (value: FetchedCert | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(value);
      };

      // rejectUnauthorized:false only so we can still read a bad certificate;
      // trust comes from socket.authorized / socket.authorizationError.
      const socket = tls.connect({
        host: address,
        port: 443,
        servername: isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: false,
        // Hostname check against the name the user asked about, not the IP we dialed
        checkServerIdentity: (_host, cert) => tls.checkServerIdentity(hostname, cert),
      }, () => {
        try {
          const certificate = socket.getPeerCertificate(false) as any;

          if (!certificate || !certificate.valid_from || !certificate.valid_to || !certificate.issuer || !certificate.subject) {
            finish(null);
            return;
          }

          const formatName = (name: Record<string, any> | undefined) => {
            if (!name) return '';
            return Object.entries(name)
              .filter(([, value]) => value !== undefined && value !== null)
              .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : value}`)
              .join(', ');
          };

          const validFrom = new Date(certificate.valid_from);
          const validUntil = new Date(certificate.valid_to);
          if (Number.isNaN(validFrom.getTime()) || Number.isNaN(validUntil.getTime())) {
            finish(null);
            return;
          }

          const issuer = formatName(certificate.issuer);
          const subject = formatName(certificate.subject);
          const authError = socket.authorizationError ? String(socket.authorizationError) : undefined;
          const keyType: CertFacts['keyType'] = certificate.modulus ? 'RSA'
            : (certificate.asn1Curve || certificate.nistCurve) ? 'EC' : 'unknown';

          finish({
            issuer,
            subject,
            validFrom,
            validUntil,
            serialNumber: certificate.serialNumber || 'unknown',
            fingerprint: certificate.fingerprint256 || certificate.fingerprint || 'unknown',
            chainValid: socket.authorized === true,
            authorizationError: authError,
            isSelfSigned: authError === 'DEPTH_ZERO_SELF_SIGNED_CERT' || authError === 'SELF_SIGNED_CERT_IN_CHAIN',
            sans: typeof certificate.subjectaltname === 'string'
              ? certificate.subjectaltname.split(',').map((s: string) => s.trim()).filter(Boolean)
              : [],
            keyType,
            keySize: typeof certificate.bits === 'number' ? certificate.bits : undefined,
            signatureAlgorithm: typeof certificate.signatureAlgorithm === 'string' ? certificate.signatureAlgorithm : undefined,
          });
        } catch {
          finish(null);
        }
      });

      const timer = setTimeout(() => finish(null), CONNECT_TIMEOUT_MS);
      socket.setTimeout(CONNECT_TIMEOUT_MS, () => finish(null));
      socket.on('error', () => finish(null));
    });
  }

  private static cleanHost(input: string): string {
    const raw = (input || '').trim();
    try {
      const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
      return url.hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
    } catch {
      return raw.toLowerCase();
    }
  }

  private static async getCachedCertificate(hostname: string) {
    try {
      const certs = await db.select().from(certificateInfo)
        .where(eq(certificateInfo.domain, hostname))
        .orderBy(desc(certificateInfo.lastChecked))
        .limit(1);
      return certs[0] || null;
    } catch {
      return null;
    }
  }

  private static isCacheValid(lastChecked: Date): boolean {
    return (new Date().getTime() - lastChecked.getTime()) < (7 * DAY_MS);
  }

  private static buildResultFromCache(hostname: string, cached: any): SSLAnalysisResult {
    const facts: CertFacts = {
      hostname,
      subject: cached.subject,
      issuer: cached.issuer,
      validFrom: new Date(cached.validFrom),
      validUntil: new Date(cached.validUntil),
      chainValid: !!cached.chainValid,
      isSelfSigned: !!cached.isSelfSigned,
      sans: cached.sanDomains || [],
      keyType: cached.algorithm === 'RSA' || cached.algorithm === 'EC' ? cached.algorithm : 'unknown',
      keySize: cached.keySize ?? undefined,
      signatureAlgorithm: undefined,
    };
    return this.buildResult(facts, cached.serialNumber, cached.fingerprint, true);
  }

  private static async cacheCertificate(hostname: string, result: SSLAnalysisResult, fetched: FetchedCert) {
    if (!result.certificateDetails) return;
    const now = new Date();

    // Store the facts (not just a score) so a cached result re-scores identically.
    // `algorithm` holds the key type (RSA/EC) — the signature algorithm is rarely exposed by Node.
    const facts = {
      domain: hostname,
      issuer: fetched.issuer,
      subject: fetched.subject,
      validFrom: fetched.validFrom,
      validUntil: fetched.validUntil,
      serialNumber: fetched.serialNumber,
      algorithm: fetched.keyType,
      keySize: fetched.keySize ?? null,
      isSelfSigned: fetched.isSelfSigned,
      isWildcard: result.trustAnalysis.isWildcard,
      chainValid: fetched.chainValid,
      hasWeakCipher: result.trustAnalysis.hasWeakKey || result.trustAnalysis.hasWeakSignature,
      trustScore: result.trustAnalysis.trustScore,
      sanDomains: fetched.sans,
      lastChecked: now,
    };

    try {
      await db.insert(certificateInfo).values({
        ...facts,
        fingerprint: fetched.fingerprint,
        checkCount: 1,
      }).onConflictDoUpdate({
        target: certificateInfo.fingerprint,
        set: facts,
      });
    } catch (error) {
      console.error('Failed to cache certificate:', error);
    }
  }

  /**
   * Quick yes/no: is the certificate for this URL's host trusted and current?
   * Throws BlockedHostError for private/internal targets.
   */
  static async verifyCertificate(url: string): Promise<boolean> {
    let hostname: string;
    try {
      hostname = new URL(url).hostname;
    } catch {
      return false;
    }
    try {
      const result = await this.analyze(hostname);
      return result.isValid && result.riskScore < 50;
    } catch (error) {
      if (error instanceof BlockedHostError) throw error;
      return false;
    }
  }
}
