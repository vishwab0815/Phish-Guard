/**
 * SSL/TLS Certificate Validation Service
 * Analyzes SSL certificates for security issues and trust indicators
 */

import { db } from '@/db';
import { certificateInfo } from '@/db/schema';
import { eq, desc, sql } from 'drizzle-orm';

export interface SSLAnalysisResult {
  isValid: boolean;
  riskScore: number; // 0-100
  indicators: string[];
  certificateDetails?: {
    issuer: string;
    subject: string;
    validFrom: Date;
    validUntil: Date;
    serialNumber: string;
    fingerprint: string;
    algorithm: string;
    keySize?: number;
  };
  trustAnalysis: {
    isSelfSigned: boolean;
    isWildcard: boolean;
    isEV: boolean;
    chainValid: boolean;
    isExpired: boolean;
    isRevoked: boolean;
    hasWeakCipher: boolean;
    trustScore: number; // 0-100
  };
}

export class SSLValidator {
  /**
   * Analyze SSL certificate for a domain
   */
  static async analyze(domain: string): Promise<SSLAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    // Check cache first
    const cached = await this.getCachedCertificate(domain);
    if (cached && this.isCacheValid(cached.lastChecked!)) {
      return this.buildResultFromCache(cached);
    }

    // Perform fresh SSL analysis
    const certificateDetails = await this.fetchCertificate(domain);

    if (!certificateDetails) {
      return {
        isValid: false,
        riskScore: 100,
        indicators: ['No valid SSL certificate found'],
        trustAnalysis: {
          isSelfSigned: false,
          isWildcard: false,
          isEV: false,
          chainValid: false,
          isExpired: false,
          isRevoked: false,
          hasWeakCipher: false,
          trustScore: 0,
        },
      };
    }

    const trustAnalysis = await this.analyzeTrust(certificateDetails, domain);

    if (trustAnalysis.isSelfSigned) { indicators.push('Self-signed certificate detected'); riskScore += 40; }
    if (trustAnalysis.isExpired) { indicators.push('Certificate has expired'); riskScore += 50; }
    if (trustAnalysis.isRevoked) { indicators.push('Certificate has been revoked'); riskScore += 50; }
    if (!trustAnalysis.chainValid) { indicators.push('Certificate chain validation failed'); riskScore += 30; }
    if (trustAnalysis.hasWeakCipher) { indicators.push('Weak cryptographic algorithm detected'); riskScore += 20; }
    if (certificateDetails.keySize && certificateDetails.keySize < 2048) { indicators.push(`Weak key size: ${certificateDetails.keySize} bits`); riskScore += 25; }
    if (this.getCertificateAge(certificateDetails.validFrom) < 7) { indicators.push('Certificate is very new (less than 7 days old)'); riskScore += 15; }
    if (this.getRemainingValidity(certificateDetails.validUntil) < 30) { indicators.push('Certificate expires soon'); riskScore += 10; }
    if (trustAnalysis.isEV) { riskScore = Math.max(0, riskScore - 20); }

    riskScore = Math.min(riskScore, 100);

    const result: SSLAnalysisResult = {
      isValid: true,
      riskScore,
      indicators,
      certificateDetails,
      trustAnalysis,
    };

    await this.cacheCertificate(domain, result);

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
    // In production, use Node's tls module. 
    // This is a placeholder for the integrated detection engine.
    return null;
  }

  private static async analyzeTrust(cert: any, domain: string) {
    const now = new Date();
    const isSelfSigned = cert.issuer === cert.subject;
    const isWildcard = cert.subject.includes('*');
    const isExpired = now > cert.validUntil || now < cert.validFrom;
    const isRevoked = false;
    const isEV = cert.issuer.toLowerCase().includes('extended validation');
    const chainValid = !isSelfSigned;
    const weakAlgorithms = ['md5', 'sha1', 'des'];
    const hasWeakCipher = weakAlgorithms.some((alg: string) => cert.algorithm.toLowerCase().includes(alg));

    let trustScore = 100;
    if (isSelfSigned) trustScore -= 40;
    if (isExpired) trustScore -= 50;
    if (isRevoked) trustScore -= 50;
    if (!chainValid) trustScore -= 30;
    if (hasWeakCipher) trustScore -= 20;
    if (isEV) trustScore = Math.min(100, trustScore + 20);

    return {
      isSelfSigned,
      isWildcard,
      isEV,
      chainValid,
      isExpired,
      isRevoked,
      hasWeakCipher,
      trustScore: Math.max(0, trustScore),
    };
  }

  private static getCertificateAge(validFrom: Date): number {
    return Math.floor((new Date().getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24));
  }

  private static getRemainingValidity(validUntil: Date): number {
    return Math.floor((validUntil.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24));
  }

  private static async getCachedCertificate(domain: string) {
    try {
      const certs = await db.select().from(certificateInfo)
        .where(eq(certificateInfo.domain, domain))
        .orderBy(desc(certificateInfo.lastChecked))
        .limit(1);
      return certs[0] || null;
    } catch {
      return null;
    }
  }

  private static isCacheValid(lastChecked: Date): boolean {
    return (new Date().getTime() - lastChecked.getTime()) < (7 * 24 * 60 * 60 * 1000);
  }

  private static buildResultFromCache(cached: any): SSLAnalysisResult {
    const indicators: string[] = [];
    if (cached.isSelfSigned) indicators.push('Self-signed certificate detected');
    if (cached.isRevoked) indicators.push('Certificate has been revoked');
    if (!cached.chainValid) indicators.push('Certificate chain validation failed');
    if (cached.hasWeakCipher) indicators.push('Weak cryptographic algorithm detected');
    
    const now = new Date();
    if (now > cached.validUntil || now < cached.validFrom) indicators.push('Certificate has expired');

    return {
      isValid: true,
      riskScore: 100 - (cached.trustScore || 0),
      indicators,
      certificateDetails: {
        issuer: cached.issuer,
        subject: cached.subject,
        validFrom: cached.validFrom,
        validUntil: cached.validUntil,
        serialNumber: cached.serialNumber,
        fingerprint: cached.fingerprint,
        algorithm: cached.algorithm,
        keySize: cached.keySize || undefined,
      },
      trustAnalysis: {
        isSelfSigned: cached.isSelfSigned,
        isWildcard: cached.isWildcard,
        isEV: cached.isEV,
        chainValid: cached.chainValid,
        isExpired: now > cached.validUntil || now < cached.validFrom,
        isRevoked: cached.isRevoked,
        hasWeakCipher: cached.hasWeakCipher,
        trustScore: cached.trustScore,
      },
    };
  }

  private static async cacheCertificate(domain: string, result: SSLAnalysisResult) {
    if (!result.certificateDetails) return;
    const now = new Date();

    try {
      await db.insert(certificateInfo).values({
        domain,
        issuer: result.certificateDetails.issuer,
        subject: result.certificateDetails.subject,
        validFrom: result.certificateDetails.validFrom,
        validUntil: result.certificateDetails.validUntil,
        serialNumber: result.certificateDetails.serialNumber,
        fingerprint: result.certificateDetails.fingerprint,
        algorithm: result.certificateDetails.algorithm,
        keySize: result.certificateDetails.keySize,
        isSelfSigned: result.trustAnalysis.isSelfSigned,
        isWildcard: result.trustAnalysis.isWildcard,
        isEV: result.trustAnalysis.isEV,
        chainValid: result.trustAnalysis.chainValid,
        isRevoked: result.trustAnalysis.isRevoked,
        hasWeakCipher: result.trustAnalysis.hasWeakCipher,
        trustScore: result.trustAnalysis.trustScore,
        lastChecked: now,
        checkCount: 1,
      }).onConflictDoUpdate({
        target: certificateInfo.fingerprint,
        set: {
          lastChecked: now,
          checkCount: sql`${certificateInfo.checkCount} + 1`,
        },
      });
    } catch (error) {
      console.error('Failed to cache certificate:', error);
    }
  }

  static async verifyCertificate(url: string): Promise<boolean> {
    try {
      const domain = new URL(url).hostname;
      const result = await this.analyze(domain);
      return result.isValid && result.riskScore < 50;
    } catch {
      return false;
    }
  }
}
