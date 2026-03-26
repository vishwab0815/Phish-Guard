/**
 * Master Detection Service
 * Orchestrates all detection layers for comprehensive threat analysis
 */

import { URLAnalyzer } from './urlAnalyzer';
import { DomainService } from './domainService';
import { SSLValidator } from './sslValidator';
import { IPService } from './ipService';
import { VirusTotalService } from '../external/virusTotal';
import { GoogleSafeBrowsingService } from '../external/googleSafeBrowsing';
import { PhishTankService } from '../external/phishTank';
import { db } from '@/db';
import { scanResults, users } from '@/db/schema';
import { eq } from 'drizzle-orm';

export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ScanType = 'URL' | 'EMAIL' | 'MESSAGE' | 'FILE';

export interface RiskBreakdown {
  layer: string;
  riskContribution: number;
  weight: number;
  details: string;
}

export interface ComprehensiveAnalysisResult {
  target: string;
  type: ScanType;
  confidence: number; // 0-100
  threatLevel: ThreatLevel;
  riskScore: number; // 0-100
  indicators: string[];
  recommendations: string[];
  riskBreakdown?: RiskBreakdown[];
  layers: {
    staticAnalysis?: any;
    domainIntelligence?: any;
    sslAnalysis?: any;
    ipIntelligence?: any;
    externalScans?: {
      virusTotal?: any;
      safeBrowsing?: any;
      phishTank?: any;
    };
  };
  scanDuration: number;
  timestamp: Date;
}

export class MasterDetector {
  static async analyzeURL(url: string, userId?: string): Promise<ComprehensiveAnalysisResult> {
    const startTime = Date.now();
    const indicators: string[] = [];
    const recommendations: string[] = [];
    const layers: any = {};

    try {
      const staticAnalysis = await URLAnalyzer.analyze(url);
      layers.staticAnalysis = staticAnalysis;
      indicators.push(...staticAnalysis.indicators);
    } catch (error) {
      console.error('Static analysis failed:', error);
    }

    const domain = URLAnalyzer.extractDomain(url);

    if (domain) {
      try {
        const isTrusted = await DomainService.isTrustedDomain(domain);
        const isBlocked = await DomainService.isBlockedDomain(domain);

        if (isTrusted) {
          const scanDuration = Date.now() - startTime;
          const trustedResult = this.buildTrustedResult(url, scanDuration);
          await this.saveScanResult(trustedResult, userId);
          return trustedResult;
        }

        if (isBlocked) {
          const scanDuration = Date.now() - startTime;
          const blockedResult = this.buildBlockedResult(url, scanDuration);
          await this.saveScanResult(blockedResult, userId);
          return blockedResult;
        }

        const domainAnalysis = await DomainService.analyze(domain);
        layers.domainIntelligence = domainAnalysis;
        indicators.push(...domainAnalysis.indicators);
      } catch (error) {
        console.error('Domain intelligence failed:', error);
      }

      if (url.startsWith('https://')) {
        try {
          const sslAnalysis = await SSLValidator.analyze(domain);
          layers.sslAnalysis = sslAnalysis;
          indicators.push(...sslAnalysis.indicators);
        } catch (error) {
          console.error('SSL analysis failed:', error);
        }
      } else {
        indicators.push('URL does not use HTTPS encryption');
      }
    }

    const ipAddress = IPService.extractIPFromURL(url);
    if (ipAddress) {
      try {
        const ipAnalysis = await IPService.analyze(ipAddress);
        layers.ipIntelligence = ipAnalysis;
        indicators.push(...ipAnalysis.indicators);
      } catch (error) {
        console.error('IP intelligence failed:', error);
      }
    }

    const externalScans: any = {};
    const externalPromises = [
      GoogleSafeBrowsingService.checkURL(url).then(r => { externalScans.safeBrowsing = r; }).catch(() => {}),
      PhishTankService.checkURL(url).then(r => { externalScans.phishTank = r; }).catch(() => {}),
      VirusTotalService.analyzeURL(url).then(r => { externalScans.virusTotal = r; }).catch(() => {}),
    ];

    await Promise.allSettled(externalPromises);
    
    if (externalScans.safeBrowsing?.isThreat) indicators.push(`Google Safe Browsing: ${externalScans.safeBrowsing.threatType}`);
    if (externalScans.phishTank?.isPhishing) indicators.push('PhishTank: URL identified as phishing site');
    if (externalScans.virusTotal?.isPhishing || externalScans.virusTotal?.isMalware) {
      indicators.push(`VirusTotal: ${externalScans.virusTotal.detectionCount}/${externalScans.virusTotal.totalEngines} engines detected threats`);
    }

    layers.externalScans = externalScans;

    const { riskScore, breakdown } = this.calculateRiskScoreWithBreakdown(layers);
    const threatLevel = this.determineThreatLevel(riskScore, indicators);
    const confidence = this.calculateConfidence(layers);
    recommendations.push(...this.generateRecommendations(riskScore, layers));

    const result: ComprehensiveAnalysisResult = {
      target: url,
      type: 'URL',
      confidence: Math.min(100, Math.max(0, confidence)),
      threatLevel,
      riskScore: Math.max(0, riskScore),
      indicators,
      recommendations,
      riskBreakdown: breakdown,
      layers,
      scanDuration: Date.now() - startTime,
      timestamp: new Date(),
    };

    await this.saveScanResult(result, userId);
    return result;
  }

  private static calculateRiskScoreWithBreakdown(layers: any) {
    let riskScore = 0;
    const breakdown: RiskBreakdown[] = [];

    if (layers.staticAnalysis) {
      const contribution = Math.round(layers.staticAnalysis.riskScore * 0.2);
      riskScore += contribution;
      breakdown.push({ layer: 'Static Analysis', riskContribution: contribution, weight: 20, details: 'URL structure analysis completed' });
    }

    if (layers.domainIntelligence) {
      const contribution = Math.round(layers.domainIntelligence.riskScore * 0.25);
      riskScore += contribution;
      breakdown.push({ layer: 'Domain Intelligence', riskContribution: contribution, weight: 25, details: 'Domain reputation check completed' });
    }

    if (layers.sslAnalysis) {
      const contribution = Math.round(layers.sslAnalysis.riskScore * 0.15);
      riskScore += contribution;
      breakdown.push({ layer: 'SSL/TLS Certificate', riskContribution: contribution, weight: 15, details: 'SSL/TLS certificate check completed' });
    }

    if (layers.ipIntelligence) {
      const contribution = Math.round(layers.ipIntelligence.riskScore * 0.1);
      riskScore += contribution;
      breakdown.push({ layer: 'IP Intelligence', riskContribution: contribution, weight: 10, details: 'IP reputation analysis completed' });
    }

    if (layers.externalScans) {
      let externalTotal = 0;
      if (layers.externalScans.safeBrowsing?.isThreat) externalTotal += 33;
      if (layers.externalScans.phishTank?.isPhishing) externalTotal += 33;
      if (layers.externalScans.virusTotal) externalTotal += (layers.externalScans.virusTotal.confidence || 0) * 0.33;
      
      const contribution = Math.round(externalTotal * 0.3);
      riskScore += contribution;
      breakdown.push({ layer: 'External Intelligence', riskContribution: contribution, weight: 30, details: 'External threat scans completed' });
    }

    return { riskScore: Math.min(Math.round(riskScore), 100), breakdown };
  }

  private static determineThreatLevel(riskScore: number, indicators: string[]): ThreatLevel {
    if (riskScore >= 70) return 'CRITICAL';
    if (riskScore >= 50) return 'HIGH';
    if (riskScore >= 30) return 'MEDIUM';
    if (riskScore >= 15) return 'LOW';
    return 'SAFE';
  }

  private static calculateConfidence(layers: any): number {
    let confidence = 50;
    if (layers.staticAnalysis) confidence += 10;
    if (layers.domainIntelligence) confidence += 15;
    if (layers.sslAnalysis) confidence += 10;
    if (layers.ipIntelligence) confidence += 5;
    return Math.min(confidence, 100);
  }

  private static generateRecommendations(riskScore: number, layers: any): string[] {
    if (riskScore >= 50) return ['DO NOT visit this URL', 'Block this domain in your firewall'];
    if (riskScore >= 20) return ['Exercise caution', 'Verify the sender'];
    return ['URL appears safe'];
  }

  private static buildTrustedResult(url: string, scanDuration: number): ComprehensiveAnalysisResult {
    return {
      target: url, type: 'URL', confidence: 100, threatLevel: 'SAFE', riskScore: 0,
      indicators: ['Domain is verified as a trusted provider'], recommendations: ['URL is verified legitimate'],
      layers: { staticAnalysis: 'completed', domainIntelligence: 'completed' }, scanDuration, timestamp: new Date(),
    };
  }

  private static buildBlockedResult(url: string, scanDuration: number): ComprehensiveAnalysisResult {
    return {
      target: url, type: 'URL', confidence: 100, threatLevel: 'CRITICAL', riskScore: 100,
      indicators: ['Domain is blocked'], recommendations: ['DO NOT access this URL'],
      layers: {}, scanDuration, timestamp: new Date(),
    };
  }

  private static async saveScanResult(result: ComprehensiveAnalysisResult, userId?: string): Promise<void> {
    try {
      let validUserId = null;
      if (userId) {
        const userExists = await db.query.users.findFirst({ where: eq(users.id, userId) });
        if (!userExists) {
          try {
            await db.insert(users).values({ id: userId, name: 'Demo User' }).onConflictDoNothing();
            validUserId = userId;
          } catch { validUserId = null; }
        } else {
          validUserId = userId;
        }
      }

      await db.insert(scanResults).values({
        userId: validUserId,
        type: result.type as any,
        target: result.target,
        status: 'COMPLETED',
        confidence: result.confidence,
        threatLevel: result.threatLevel as any,
        riskScore: result.riskScore,
        indicators: result.indicators,
        recommendations: result.recommendations,
        scanDuration: result.scanDuration,
        timestamp: result.timestamp,
        metadata: result.layers,
      });
    } catch (error) {
      console.error('Failed to save scan result:', error);
    }
  }
}
