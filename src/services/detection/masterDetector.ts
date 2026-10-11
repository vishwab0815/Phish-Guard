/**
 * Master Detection Service
 * Orchestrates all detection layers for comprehensive threat analysis.
 *
 * Scoring (see scoreLayers):
 *   1. Weighted average over ONLY the layers that actually produced data
 *      (weights are renormalized, so a missing layer never caps the score).
 *   2. Hard overrides on top: blocklist, threat-feed hits and strong static
 *      findings (lookalike domains, private addresses…) set a minimum score.
 */

import { URLAnalyzer, URLAnalysisResult } from './urlAnalyzer';
import { DomainService, DomainAnalysisResult } from './domainService';
import { SSLValidator, SSLAnalysisResult } from './sslValidator';
import { IPService } from './ipService';
import { VirusTotalService, VirusTotalResult } from '../external/virusTotal';
import { GoogleSafeBrowsingService, SafeBrowsingResult } from '../external/googleSafeBrowsing';
import { PhishTankService, PhishTankResult } from '../external/phishTank';
import { BlockedHostError } from '@/lib/netGuard';
import { db } from '@/db';
import { scanResults } from '@/db/schema';

export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ScanType = 'URL' | 'EMAIL' | 'MESSAGE' | 'FILE';

export interface RiskBreakdown {
  layer: string;
  riskContribution: number;
  weight: number;
  details: string;
}

export interface ComprehensiveAnalysisResult {
  scanId?: string; // id of the saved scan_results row (undefined if saving failed)
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

// ---------------------------------------------------------------------------
// Pure scoring (no DB / network) — unit-tested in masterDetector.test.ts
// ---------------------------------------------------------------------------

/** Base weights of the heuristic layers (renormalized over layers with data) */
export const LAYER_WEIGHTS = {
  static: 35,
  domain: 30,
  ssl: 20,
  ip: 15,
} as const;

export interface ScoreFloor {
  min: number; // final score is at least this
  reason: string;
}

export interface LayerScoresInput {
  /** 0-100 per layer; leave undefined when the layer produced no real data */
  static?: number;
  domain?: number;
  ssl?: number;
  ip?: number;
  /** Admin-trusted domain: heuristic layers are ignored, threat feeds still apply */
  trusted?: boolean;
  /** Admin-blocked domain → 100 */
  blocked?: boolean;
  external?: {
    safeBrowsingThreat?: string | null; // threat type when GSB matched
    phishTankVerified?: boolean; // in database AND verified valid phish
    virusTotalMalicious?: number; // engines flagging as malicious
    virusTotalTotal?: number;
  };
  /** Extra minimums from strong static findings (see heuristicFloors) */
  floors?: ScoreFloor[];
}

export interface LayerScoresOutput {
  riskScore: number; // final, 0-100
  preOverrideScore: number; // weighted average before overrides
  breakdown: RiskBreakdown[];
  overrideReasons: string[];
}

/**
 * Combine layer scores into one 0-100 risk score.
 * Breakdown: layer entries sum to preOverrideScore; an "Override" entry (if any)
 * carries the difference, so all entries together sum to riskScore.
 */
export function scoreLayers(input: LayerScoresInput): LayerScoresOutput {
  const breakdown: RiskBreakdown[] = [];
  const clamp = (n: number) => Math.max(0, Math.min(100, n));

  const layerDefs: Array<{ key: keyof typeof LAYER_WEIGHTS; name: string; details: string }> = [
    { key: 'static', name: 'Static Analysis', details: 'URL structure, brand and lookalike checks' },
    { key: 'domain', name: 'Domain Intelligence', details: 'Domain age (RDAP), DNS and local reputation' },
    { key: 'ssl', name: 'SSL/TLS Certificate', details: 'Certificate chain, hostname and expiry' },
    { key: 'ip', name: 'IP Intelligence', details: 'IP address checks' },
  ];

  let preOverrideScore = 0;

  if (input.trusted) {
    breakdown.push({
      layer: 'Trusted Domain', riskContribution: 0, weight: 100,
      details: 'Domain is on the trusted list; heuristic layers are not scored',
    });
  } else {
    const present = layerDefs.filter(l => typeof input[l.key] === 'number' && Number.isFinite(input[l.key] as number));
    const totalWeight = present.reduce((sum, l) => sum + LAYER_WEIGHTS[l.key], 0);

    for (const l of present) {
      const share = LAYER_WEIGHTS[l.key] / totalWeight;
      const contribution = Math.round(clamp(input[l.key] as number) * share);
      preOverrideScore += contribution;
      breakdown.push({ layer: l.name, riskContribution: contribution, weight: Math.round(share * 100), details: l.details });
    }
  }
  preOverrideScore = clamp(preOverrideScore);

  // ---- Hard overrides ----
  const floors: ScoreFloor[] = [];
  const ext = input.external || {};

  if (input.blocked) floors.push({ min: 100, reason: 'Domain is on the blocklist' });
  if (ext.safeBrowsingThreat) floors.push({ min: 90, reason: `Google Safe Browsing lists this URL (${ext.safeBrowsingThreat})` });
  if (ext.phishTankVerified) floors.push({ min: 90, reason: 'PhishTank lists this URL as a verified phish' });

  const vtMal = ext.virusTotalMalicious || 0;
  if (vtMal >= 3) floors.push({ min: 80, reason: `VirusTotal: ${vtMal} engines flag this URL as malicious` });
  // A lone engine is a common false positive, so 1-2 detections only raise caution
  else if (vtMal === 2) floors.push({ min: 30, reason: 'VirusTotal: 2 engines flag this URL as malicious' });
  else if (vtMal === 1) floors.push({ min: 15, reason: 'VirusTotal: 1 engine flags this URL as malicious (often a false positive)' });

  // Static floors only apply when the domain isn't admin-trusted
  if (!input.trusted) floors.push(...(input.floors || []));

  const applicable = floors.filter(f => f.min > preOverrideScore);
  const riskScore = clamp(Math.max(preOverrideScore, ...floors.map(f => f.min)));

  if (riskScore > preOverrideScore) {
    breakdown.push({
      layer: 'Override',
      riskContribution: riskScore - preOverrideScore,
      weight: 0,
      details: applicable.map(f => `${f.reason} (minimum ${f.min})`).join('; '),
    });
  }

  return { riskScore, preOverrideScore, breakdown, overrideReasons: applicable.map(f => f.reason) };
}

/** Strong static findings that should never be averaged away */
export function heuristicFloors(staticAnalysis?: URLAnalysisResult, domainAgeDays?: number): ScoreFloor[] {
  const floors: ScoreFloor[] = [];
  const d = staticAnalysis?.details;

  if (d?.isDangerousScheme) floors.push({ min: 100, reason: 'Not a web link (runs code or embeds content)' });
  if (d?.isPrivateAddress) floors.push({ min: 55, reason: 'Points to a private/internal network address' });

  const brand = d?.brandFinding;
  if (brand?.kind === 'homograph') floors.push({ min: 80, reason: `Unicode lookalike of ${brand.brand}` });
  else if (brand?.kind === 'lookalike') floors.push({ min: 60, reason: `Typosquatted lookalike of ${brand.brand}` });
  else if (brand?.kind === 'impersonation') {
    // Brand name on an unrelated domain plus other red flags → HIGH, alone → MEDIUM
    const strong = (staticAnalysis?.riskScore || 0) >= 55;
    floors.push({ min: strong ? 55 : 35, reason: `Uses the ${brand.brand} name on a domain ${brand.brand} does not own` });
  }

  if (typeof domainAgeDays === 'number' && domainAgeDays < 30) {
    floors.push({ min: brand ? 75 : 30, reason: `Domain registered only ${domainAgeDays} day(s) ago` });
  }

  return floors;
}

export function threatLevelForScore(riskScore: number): ThreatLevel {
  if (riskScore >= 70) return 'CRITICAL';
  if (riskScore >= 50) return 'HIGH';
  if (riskScore >= 30) return 'MEDIUM';
  if (riskScore >= 15) return 'LOW';
  return 'SAFE';
}

export interface ConfidenceInput {
  staticData: boolean;
  domainData: boolean; // DNS records or RDAP age actually retrieved
  sslData: boolean; // a certificate was actually retrieved
  feedsConsulted: number; // threat feeds that returned a real verdict (0-3)
  feedHit: boolean; // a feed flagged it, or blocklist
  trusted: boolean;
  definitive: boolean; // e.g. javascript: link — nothing to doubt
}

/** Confidence reflects how much real evidence we actually have */
export function computeConfidence(c: ConfidenceInput): number {
  if (c.definitive || c.feedHit) return 95;
  let confidence = c.trusted ? 70 : 25;
  if (c.staticData) confidence += 20;
  if (c.domainData) confidence += 15;
  if (c.sslData) confidence += 10;
  confidence += Math.min(c.feedsConsulted, 3) * 10;
  return Math.max(0, Math.min(confidence, 95));
}

// ---------------------------------------------------------------------------

export class MasterDetector {
  static async analyzeURL(url: string, userId?: string): Promise<ComprehensiveAnalysisResult> {
    const startTime = Date.now();
    const indicators: string[] = [];
    const layers: ComprehensiveAnalysisResult['layers'] = {};

    // ---- Layer 1: static analysis (offline) ----
    let staticAnalysis: URLAnalysisResult | undefined;
    try {
      staticAnalysis = await URLAnalyzer.analyze(url);
      layers.staticAnalysis = staticAnalysis;
      indicators.push(...staticAnalysis.indicators);
    } catch (error) {
      console.error('Static analysis failed:', error);
    }

    const details = staticAnalysis?.details;
    const analyzable = !!staticAnalysis?.isValid && !details?.isDangerousScheme && !!details?.hostname;
    const host = details?.hostname || '';
    const isPrivate = !!details?.isPrivateAddress;
    const isIpHost = !!details?.hasIPAddress;
    let pathname = '/';
    try { pathname = new URL(url).pathname; } catch { /* invalid URL, handled by static layer */ }

    let trusted = false;
    let blocked = false;
    let domainAnalysis: DomainAnalysisResult | undefined;
    let sslAnalysis: SSLAnalysisResult | undefined;
    const externalScans: { virusTotal?: VirusTotalResult; safeBrowsing?: SafeBrowsingResult; phishTank?: PhishTankResult } = {};

    if (analyzable) {
      // ---- Allow/block lists ----
      try {
        blocked = await DomainService.isBlockedDomain(host);
        // Multi-tenant hosting never inherits trust (anyone can publish on *.github.io etc.)
        trusted = !blocked && !URLAnalyzer.isMultiTenantHost(host, pathname) && await DomainService.isTrustedDomain(host);
      } catch (error) {
        console.error('Domain list lookup failed:', error);
      }

      const tasks: Promise<unknown>[] = [];

      // ---- Layers 2-3: domain intelligence + TLS (skipped for trusted/blocked/private) ----
      if (!trusted && !blocked && !isPrivate) {
        if (!isIpHost) {
          tasks.push(
            DomainService.analyze(URLAnalyzer.getRegistrableDomain(host))
              .then(r => { domainAnalysis = r; })
              .catch(error => console.error('Domain intelligence failed:', error))
          );
        }
        if (details?.scheme === 'https:') {
          tasks.push(
            SSLValidator.analyze(host)
              .then(r => { sslAnalysis = r; })
              .catch(error => {
                if (error instanceof BlockedHostError) {
                  indicators.push('Points to a private/internal network address (hostname resolves to a non-public IP)');
                } else {
                  console.error('SSL analysis failed:', error);
                }
              })
          );
        }
      }

      // ---- Layer 5: external threat feeds (never for private/internal URLs) ----
      if (!isPrivate && URLAnalyzer.isPublicWebUrl(url)) {
        tasks.push(
          GoogleSafeBrowsingService.checkURL(url).then(r => { externalScans.safeBrowsing = r; }).catch(() => {}),
          PhishTankService.checkURL(url).then(r => { externalScans.phishTank = r; }).catch(() => {}),
          VirusTotalService.analyzeURL(url).then(r => { externalScans.virusTotal = r; }).catch(() => {}),
        );
      }

      await Promise.allSettled(tasks);
    }

    // Layers are attached only when they produced real data (routes report attached layers as "completed")
    if (domainAnalysis) {
      if (domainAnalysis.hasData) layers.domainIntelligence = domainAnalysis;
      indicators.push(...domainAnalysis.indicators);
    }
    if (sslAnalysis) {
      if (sslAnalysis.certificateAvailable) layers.sslAnalysis = sslAnalysis;
      indicators.push(...sslAnalysis.indicators);
    }

    // ---- Layer 4: IP intelligence (only for IP-literal hosts) ----
    let ipScore: number | undefined;
    if (analyzable && isIpHost) {
      try {
        const ipAnalysis = await IPService.analyze(host);
        // Private-address indicator already comes from the static layer
        indicators.push(...ipAnalysis.indicators.filter(i => !indicators.includes(i)));
        if (ipAnalysis.dataAvailable) {
          layers.ipIntelligence = ipAnalysis;
          ipScore = ipAnalysis.riskScore;
        }
      } catch (error) {
        console.error('IP intelligence failed:', error);
      }
    }

    // ---- Threat feed verdicts ----
    const gsb = externalScans.safeBrowsing;
    const pt = externalScans.phishTank;
    const vt = externalScans.virusTotal;
    if (gsb?.isThreat) indicators.push(`Google Safe Browsing: ${gsb.threatType || 'listed as unsafe'}`);
    if (pt?.isPhishing) indicators.push('PhishTank: verified phishing site');
    if (vt?.status === 'completed' && vt.maliciousCount > 0) {
      indicators.push(`VirusTotal: ${vt.maliciousCount}/${vt.totalEngines} engines flag this URL as malicious`);
    }
    if (blocked) indicators.push('Domain is blocked');
    if (trusted) indicators.push('Domain is on the trusted list');
    const feedsConsulted = [gsb?.checked, pt?.checked, vt?.status === 'completed'].filter(Boolean).length;
    if (feedsConsulted > 0 || vt?.status === 'pending') layers.externalScans = externalScans;

    // ---- Score ----
    const domainHasData = !!domainAnalysis?.hasData;
    const sslHasData = !!sslAnalysis?.certificateAvailable;
    const scoring = scoreLayers({
      static: staticAnalysis ? staticAnalysis.riskScore : undefined,
      domain: domainHasData ? domainAnalysis!.riskScore : undefined,
      ssl: sslHasData ? sslAnalysis!.riskScore : undefined,
      ip: ipScore,
      trusted,
      blocked,
      external: {
        safeBrowsingThreat: gsb?.isThreat ? (gsb.threatType || 'THREAT') : null,
        phishTankVerified: !!pt?.isPhishing,
        virusTotalMalicious: vt?.status === 'completed' ? vt.maliciousCount : 0,
        virusTotalTotal: vt?.totalEngines,
      },
      floors: heuristicFloors(staticAnalysis, domainAnalysis?.whoisData?.domainAge),
    });

    const riskScore = scoring.riskScore;
    const feedHit = blocked || !!gsb?.isThreat || !!pt?.isPhishing || (vt?.status === 'completed' && vt.maliciousCount >= 3);
    const confidence = computeConfidence({
      staticData: !!staticAnalysis?.isValid,
      domainData: domainHasData,
      sslData: sslHasData,
      feedsConsulted,
      feedHit,
      trusted,
      definitive: !!details?.isDangerousScheme,
    });

    const result: ComprehensiveAnalysisResult = {
      target: url,
      type: 'URL',
      confidence,
      threatLevel: threatLevelForScore(riskScore),
      riskScore,
      indicators: Array.from(new Set(indicators)),
      recommendations: this.generateRecommendations(riskScore, { trusted, feedsConsulted }),
      riskBreakdown: scoring.breakdown,
      layers,
      scanDuration: Date.now() - startTime,
      timestamp: new Date(),
    };

    result.scanId = await this.saveScanResult(result, userId);
    return result;
  }

  private static generateRecommendations(riskScore: number, ctx: { trusted: boolean; feedsConsulted: number }): string[] {
    if (riskScore >= 50) return ['DO NOT visit this URL', 'Do not enter passwords, OTPs or payment details', 'Block this domain in your firewall'];
    if (riskScore >= 15) return ['Exercise caution', 'Verify the sender', 'Open the official site directly instead of using this link'];
    if (ctx.trusted) return ['Domain is on your trusted list'];
    return ctx.feedsConsulted > 0
      ? ['No threats found by our checks or threat feeds']
      : ['No threats found by our local checks (threat feeds not configured)'];
  }

  /** Insert the scan row and return its id. Routes create the user row beforehand. */
  private static async saveScanResult(result: ComprehensiveAnalysisResult, userId?: string): Promise<string | undefined> {
    try {
      const [row] = await db.insert(scanResults).values({
        userId: userId ?? null,
        type: result.type,
        target: result.target,
        status: 'COMPLETED',
        confidence: result.confidence,
        threatLevel: result.threatLevel,
        riskScore: result.riskScore,
        indicators: result.indicators,
        recommendations: result.recommendations,
        scanDuration: result.scanDuration,
        timestamp: result.timestamp,
        metadata: { ...result.layers, riskBreakdown: result.riskBreakdown },
      }).returning({ id: scanResults.id });
      return row?.id;
    } catch (error) {
      console.error('Failed to save scan result:', error);
      return undefined;
    }
  }
}
