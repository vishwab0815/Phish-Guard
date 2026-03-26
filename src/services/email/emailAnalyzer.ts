/**
 * Advanced Email Security Analysis
 * Comprehensive email threat detection including headers, attachments, and content
 */

import { ThreatLevel } from '@/db/schema';

export interface EmailAnalysisResult {
  isPhishing: boolean;
  isSpam: boolean;
  isSpoofed: boolean;
  threatLevel: ThreatLevel;
  riskScore: number;
  confidence: number;
  indicators: string[];
  recommendations: string[];
  headerAnalysis: {
    spfResult?: 'pass' | 'fail' | 'neutral' | 'softfail';
    dkimResult?: 'pass' | 'fail';
    dmarcResult?: 'pass' | 'fail';
    hasSpoofedSender: boolean;
    suspiciousHeaders: string[];
  };
  contentAnalysis: {
    hasPhishingKeywords: boolean;
    hasUrgentLanguage: boolean;
    hasSuspiciousLinks: number;
    hasSuspiciousAttachments: number;
    suspiciousPatterns: string[];
  };
  senderReputation: {
    domain: string;
    isKnownPhisher: boolean;
    trustScore: number;
  };
}

export class EmailAnalyzer {
  /**
   * Analyze email for phishing and threats
   */
  static async analyzeEmail(emailData: {
    headers: { [key: string]: string };
    from: string;
    to: string;
    subject: string;
    body: string;
    bodyHtml?: string;
    attachments?: Array<{ filename: string; contentType: string; size: number }>;
  }): Promise<EmailAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    // Analyze email headers (SPF, DKIM, DMARC)
    const headerAnalysis = this.analyzeHeaders(emailData.headers, emailData.from);
    if (headerAnalysis.hasSpoofedSender) {
      indicators.push('Email sender appears to be spoofed');
      riskScore += 40;
    }
    if (headerAnalysis.spfResult === 'fail') {
      indicators.push('SPF validation failed');
      riskScore += 25;
    }
    if (headerAnalysis.dkimResult === 'fail') {
      indicators.push('DKIM signature validation failed');
      riskScore += 20;
    }
    if (headerAnalysis.dmarcResult === 'fail') {
      indicators.push('DMARC policy check failed');
      riskScore += 20;
    }

    // Analyze email content
    const contentAnalysis = this.analyzeContent(
      emailData.subject,
      emailData.body,
      emailData.bodyHtml,
      emailData.attachments
    );

    if (contentAnalysis.hasPhishingKeywords) {
      indicators.push('Email contains phishing keywords');
      riskScore += 30;
    }

    if (contentAnalysis.hasUrgentLanguage) {
      indicators.push('Email uses urgent or threatening language');
      riskScore += 15;
    }

    if (contentAnalysis.hasSuspiciousLinks > 0) {
      indicators.push(`Email contains ${contentAnalysis.hasSuspiciousLinks} suspicious links`);
      riskScore += Math.min(contentAnalysis.hasSuspiciousLinks * 10, 30);
    }

    if (contentAnalysis.hasSuspiciousAttachments > 0) {
      indicators.push(`Email has ${contentAnalysis.hasSuspiciousAttachments} suspicious attachments`);
      riskScore += Math.min(contentAnalysis.hasSuspiciousAttachments * 20, 40);
    }

    // Analyze sender reputation
    const senderReputation = await this.analyzeSenderReputation(emailData.from);
    if (senderReputation.isKnownPhisher) {
      indicators.push('Sender domain is known for phishing');
      riskScore += 50;
    }

    // Determine threat classification
    const isPhishing = riskScore >= 60 || senderReputation.isKnownPhisher;
    const isSpam = riskScore >= 40 && riskScore < 60;
    const isSpoofed = headerAnalysis.hasSpoofedSender;

    const threatLevel = this.determineThreatLevel(riskScore);
    const confidence = this.calculateConfidence(headerAnalysis, contentAnalysis);

    const recommendations = this.generateRecommendations(
      threatLevel,
      isPhishing,
      isSpoofed,
      contentAnalysis
    );

    return {
      isPhishing,
      isSpam,
      isSpoofed,
      threatLevel,
      riskScore: Math.min(riskScore, 100),
      confidence,
      indicators,
      recommendations,
      headerAnalysis,
      contentAnalysis,
      senderReputation,
    };
  }

  /**
   * Analyze email headers
   */
  private static analyzeHeaders(
    headers: { [key: string]: string },
    fromAddress: string
  ) {
    const suspiciousHeaders: string[] = [];
    let hasSpoofedSender = false;

    // Extract and validate SPF
    const spfResult = this.extractSPFResult(headers);

    // Extract and validate DKIM
    const dkimResult = this.extractDKIMResult(headers);

    // Extract and validate DMARC
    const dmarcResult = this.extractDMARCResult(headers);

    // Check for sender spoofing
    const receivedFrom = headers['Received'] || headers['received'];
    const returnPath = headers['Return-Path'] || headers['return-path'];

    if (returnPath && !fromAddress.includes(this.extractDomain(returnPath))) {
      hasSpoofedSender = true;
      suspiciousHeaders.push('Return-Path mismatch');
    }

    // Check for suspicious X-headers
    if (headers['X-Mailer']?.includes('Unknown') || headers['X-Mailer']?.includes('PHP')) {
      suspiciousHeaders.push('Suspicious mailer detected');
    }

    // Check for missing standard headers
    if (!headers['Message-ID'] && !headers['message-id']) {
      suspiciousHeaders.push('Missing Message-ID header');
    }

    return {
      spfResult,
      dkimResult,
      dmarcResult,
      hasSpoofedSender,
      suspiciousHeaders,
    };
  }

  /**
   * Extract SPF result from headers
   */
  private static extractSPFResult(
    headers: { [key: string]: string }
  ): 'pass' | 'fail' | 'neutral' | 'softfail' | undefined {
    const received = headers['Received-SPF'] || headers['received-spf'];
    if (!received) return undefined;

    if (received.toLowerCase().includes('pass')) return 'pass';
    if (received.toLowerCase().includes('fail')) return 'fail';
    if (received.toLowerCase().includes('softfail')) return 'softfail';
    if (received.toLowerCase().includes('neutral')) return 'neutral';

    return undefined;
  }

  /**
   * Extract DKIM result
   */
  private static extractDKIMResult(
    headers: { [key: string]: string }
  ): 'pass' | 'fail' | undefined {
    const auth = headers['Authentication-Results'] || headers['authentication-results'];
    if (!auth) return undefined;

    if (auth.toLowerCase().includes('dkim=pass')) return 'pass';
    if (auth.toLowerCase().includes('dkim=fail')) return 'fail';

    return undefined;
  }

  /**
   * Extract DMARC result
   */
  private static extractDMARCResult(
    headers: { [key: string]: string }
  ): 'pass' | 'fail' | undefined {
    const auth = headers['Authentication-Results'] || headers['authentication-results'];
    if (!auth) return undefined;

    if (auth.toLowerCase().includes('dmarc=pass')) return 'pass';
    if (auth.toLowerCase().includes('dmarc=fail')) return 'fail';

    return undefined;
  }

  /**
   * Analyze email content
   */
  private static analyzeContent(
    subject: string,
    body: string,
    bodyHtml?: string,
    attachments?: Array<{ filename: string; contentType: string; size: number }>
  ) {
    const combinedText = (subject + ' ' + body + ' ' + (bodyHtml || '')).toLowerCase();
    const suspiciousPatterns: string[] = [];

    // Phishing keywords
    const phishingKeywords = [
      'verify your account',
      'confirm your identity',
      'urgent action required',
      'suspend your account',
      'unusual activity',
      'click here immediately',
      'update payment',
      'prize winner',
      'claim your reward',
      'reset your password',
      'billing problem',
      'account will be closed',
    ];

    const hasPhishingKeywords = phishingKeywords.some(keyword =>
      combinedText.includes(keyword)
    );

    // Urgent/threatening language
    const urgentKeywords = [
      'urgent',
      'immediate',
      'act now',
      'limited time',
      'expires',
      'suspended',
      'locked',
      'within 24 hours',
      'final notice',
      'last chance',
    ];

    const hasUrgentLanguage = urgentKeywords.some(keyword => combinedText.includes(keyword));

    // Extract and analyze links
    const urlPattern = /(https?:\/\/[^\s<>"]+)/gi;
    const urls = (combinedText.match(urlPattern) || []);
    let hasSuspiciousLinks = 0;

    urls.forEach(url => {
      // Check for IP addresses instead of domains
      if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
        hasSuspiciousLinks++;
        suspiciousPatterns.push('Link uses IP address');
      }

      // Check for URL shorteners
      const shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl'];
      if (shorteners.some(s => url.includes(s))) {
        hasSuspiciousLinks++;
        suspiciousPatterns.push('URL shortener detected');
      }

      // Check for suspicious TLDs
      if (/\.(tk|ml|ga|cf|gq)/.test(url)) {
        hasSuspiciousLinks++;
        suspiciousPatterns.push('High-risk TLD in link');
      }
    });

    // Analyze attachments
    let hasSuspiciousAttachments = 0;
    if (attachments) {
      const dangerousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi', '.ps1'];

      attachments.forEach(att => {
        if (dangerousExtensions.some(ext => att.filename.toLowerCase().endsWith(ext))) {
          hasSuspiciousAttachments++;
          suspiciousPatterns.push(`Dangerous attachment: ${att.filename}`);
        }

        // Double extension check
        if (/\.[a-z]{3,4}\.[a-z]{3,4}$/i.test(att.filename)) {
          hasSuspiciousAttachments++;
          suspiciousPatterns.push(`Double extension: ${att.filename}`);
        }

        // Office files with macros
        if (/\.(doc|xls|ppt)m$/i.test(att.filename)) {
          hasSuspiciousAttachments++;
          suspiciousPatterns.push(`Macro-enabled document: ${att.filename}`);
        }
      });
    }

    return {
      hasPhishingKeywords,
      hasUrgentLanguage,
      hasSuspiciousLinks,
      hasSuspiciousAttachments,
      suspiciousPatterns,
    };
  }

  /**
   * Analyze sender reputation
   */
  private static async analyzeSenderReputation(fromAddress: string) {
    const domain = this.extractDomain(fromAddress);

    // In production, check against blocklists and reputation databases
    // For now, basic check
    const isKnownPhisher = false; // Would check database

    const trustScore = isKnownPhisher ? 0 : 50;

    return {
      domain,
      isKnownPhisher,
      trustScore,
    };
  }

  /**
   * Extract domain from email address
   */
  private static extractDomain(email: string): string {
    const match = email.match(/@(.+)/);
    return match ? match[1].toLowerCase() : '';
  }

  /**
   * Determine threat level
   */
  private static determineThreatLevel(riskScore: number): ThreatLevel {
    if (riskScore >= 80) return 'CRITICAL';
    if (riskScore >= 60) return 'HIGH';
    if (riskScore >= 40) return 'MEDIUM';
    if (riskScore >= 20) return 'LOW';
    return 'SAFE';
  }

  /**
   * Calculate confidence
   */
  private static calculateConfidence(headerAnalysis: any, contentAnalysis: any): number {
    let confidence = 50;

    // Email authentication boosts confidence
    if (headerAnalysis.spfResult) confidence += 15;
    if (headerAnalysis.dkimResult) confidence += 15;
    if (headerAnalysis.dmarcResult) confidence += 10;

    // Content analysis adds confidence
    if (contentAnalysis.hasPhishingKeywords) confidence += 10;

    return Math.min(confidence, 95);
  }

  /**
   * Generate recommendations
   */
  private static generateRecommendations(
    threatLevel: ThreatLevel,
    isPhishing: boolean,
    isSpoofed: boolean,
    contentAnalysis: any
  ): string[] {
    const recommendations: string[] = [];

    if (threatLevel === 'CRITICAL') {
      recommendations.push('DO NOT click any links or download attachments');
      recommendations.push('Report this email as phishing immediately');
      recommendations.push('Delete this email');
      recommendations.push('Block the sender');
    } else if (threatLevel === 'HIGH') {
      recommendations.push('Exercise extreme caution with this email');
      recommendations.push('Do not click links or download attachments');
      recommendations.push('Verify sender through official channels');
      recommendations.push('Consider reporting as suspicious');
    } else if (threatLevel === 'MEDIUM') {
      recommendations.push('Verify email authenticity before taking action');
      recommendations.push('Contact sender through known channels if unsure');
      recommendations.push('Be cautious with links and attachments');
    } else if (threatLevel === 'LOW') {
      recommendations.push('Email appears mostly legitimate');
      recommendations.push('Still verify sender if requesting sensitive actions');
    } else {
      recommendations.push('Email appears safe');
      recommendations.push('Follow standard email security practices');
    }

    if (isSpoofed) {
      recommendations.push('ALERT: Sender email may be forged');
    }

    if (contentAnalysis.hasSuspiciousAttachments > 0) {
      recommendations.push('Scan attachments with antivirus before opening');
    }

    return recommendations;
  }
}
