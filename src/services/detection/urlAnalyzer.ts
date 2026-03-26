/**
 * Advanced URL Analysis Service
 * Performs static analysis on URLs to detect phishing indicators
 */

export interface URLAnalysisResult {
  isValid: boolean;
  riskScore: number; // 0-100
  indicators: string[];
  details: {
    hasIPAddress: boolean;
    hasSuspiciousKeywords: boolean;
    hasHomograph: boolean;
    hasUnusualPort: boolean;
    hasShortener: boolean;
    tldRisk: 'low' | 'medium' | 'high';
    lengthAnalysis: {
      isExcessivelyLong: boolean;
      hasMultipleSubdomains: boolean;
    };
    encodingIssues: string[];
  };
}

// Suspicious keywords commonly found in phishing URLs
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
  'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
  'password', 'wallet', 'crypto', 'suspended', 'locked', 'urgent',
  'validate', 'authenticate', 'billing', 'payment', 'refund', 'prize',
  'winner', 'claim', 'expired', 'renew', 'security-check', 'verification'
];

// Known malicious/phishing domains and patterns
const KNOWN_MALICIOUS_PATTERNS = [
  'free-', 'get-free', 'download-', 'click-here', 'verify-account',
  'secure-login', 'account-update', 'password-reset', 'confirm-identity',
  'suspended-account', 'unlock-account', 'billing-problem', 'unusual-activity'
];

// Brand impersonation patterns
const BRAND_KEYWORDS = [
  'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook',
  'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe'
];

// High-risk TLDs commonly used in phishing
const HIGH_RISK_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
  '.link', '.download', '.win', '.loan', '.racing', '.review'
];

// Common URL shorteners
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
  'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'shorte.st', 'mcaf.ee'
];

// Homograph characters that look like ASCII but aren't
const HOMOGRAPH_PATTERNS = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ӏ': 'l', 'ԁ': 'd', 'ԍ': 'g'
};

export class URLAnalyzer {
  /**
   * Perform comprehensive analysis on a URL
   */
  static async analyze(url: string): Promise<URLAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;

    // Validate URL format
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch (error) {
      return {
        isValid: false,
        riskScore: 100,
        indicators: ['Invalid URL format'],
        details: {
          hasIPAddress: false,
          hasSuspiciousKeywords: false,
          hasHomograph: false,
          hasUnusualPort: false,
          hasShortener: false,
          tldRisk: 'low',
          lengthAnalysis: {
            isExcessivelyLong: false,
            hasMultipleSubdomains: false,
          },
          encodingIssues: [],
        },
      };
    }

    // Check for IP address as hostname
    const hasIPAddress = this.checkIPAddress(parsedUrl.hostname);
    if (hasIPAddress) {
      indicators.push('URL uses IP address instead of domain name');
      riskScore += 25;
    }

    // Check for brand impersonation first
    const brandImpersonation = this.checkBrandImpersonation(parsedUrl.hostname);
    if (brandImpersonation.isImpersonating) {
      indicators.push(`Potential ${brandImpersonation.brand} impersonation - Domain mismatch detected`);
      riskScore += 45;
    }

    // Check for suspicious keywords (but not if it's a legitimate brand domain)
    const suspiciousKeywords = this.checkSuspiciousKeywords(url);
    // Filter out brand names if this is the legitimate domain
    const filteredKeywords = brandImpersonation.isImpersonating
      ? suspiciousKeywords
      : suspiciousKeywords.filter(keyword => !BRAND_KEYWORDS.includes(keyword));

    if (filteredKeywords.length > 0) {
      indicators.push(`Suspicious keywords detected: ${filteredKeywords.join(', ')}`);
      riskScore += 15 * filteredKeywords.length;
    }

    // Check for malicious patterns
    const maliciousPatterns = this.checkMaliciousPatterns(url);
    if (maliciousPatterns.length > 0) {
      indicators.push(`Known phishing patterns detected: ${maliciousPatterns.join(', ')}`);
      riskScore += 35 * maliciousPatterns.length;
    }

    // Check for homograph attacks
    const hasHomograph = this.checkHomograph(parsedUrl.hostname);
    if (hasHomograph) {
      indicators.push('URL contains homograph characters (IDN spoofing)');
      riskScore += 30;
    }

    // Check for unusual port
    const hasUnusualPort = this.checkUnusualPort(parsedUrl);
    if (hasUnusualPort) {
      indicators.push(`Unusual port detected: ${parsedUrl.port}`);
      riskScore += 10;
    }

    // Check if it's a URL shortener
    const hasShortener = this.checkURLShortener(parsedUrl.hostname);
    if (hasShortener) {
      indicators.push('URL shortener detected (hides real destination)');
      riskScore += 20;
    }

    // Check TLD risk
    const tldRisk = this.checkTLDRisk(parsedUrl.hostname);
    if (tldRisk === 'high') {
      indicators.push('High-risk top-level domain');
      riskScore += 20;
    } else if (tldRisk === 'medium') {
      indicators.push('Medium-risk top-level domain');
      riskScore += 10;
    }

    // Length analysis
    const lengthAnalysis = this.analyzeLengthAndStructure(url, parsedUrl);
    if (lengthAnalysis.isExcessivelyLong) {
      indicators.push('Excessively long URL (possible obfuscation)');
      riskScore += 10;
    }
    if (lengthAnalysis.hasMultipleSubdomains) {
      indicators.push('Multiple subdomains detected');
      riskScore += 5;
    }

    // Check for encoding issues
    const encodingIssues = this.checkEncodingIssues(url);
    if (encodingIssues.length > 0) {
      indicators.push(...encodingIssues);
      riskScore += encodingIssues.length * 5;
    }

    // Check for HTTPS
    if (parsedUrl.protocol === 'http:') {
      indicators.push('Insecure HTTP protocol (not HTTPS)');
      riskScore += 15;
    }

    // Check for @ symbol (authentication credentials in URL)
    if (url.includes('@')) {
      indicators.push('URL contains @ symbol (possible credential theft)');
      riskScore += 20;
    }

    // Cap risk score at 100
    riskScore = Math.min(riskScore, 100);

    return {
      isValid: true,
      riskScore,
      indicators,
      details: {
        hasIPAddress,
        hasSuspiciousKeywords: suspiciousKeywords.length > 0,
        hasHomograph,
        hasUnusualPort,
        hasShortener,
        tldRisk,
        lengthAnalysis,
        encodingIssues,
      },
    };
  }

  /**
   * Check if hostname is an IP address
   */
  private static checkIPAddress(hostname: string): boolean {
    // IPv4 pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    // IPv6 pattern (simplified)
    const ipv6Pattern = /^[0-9a-fA-F:]+$/;

    return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname);
  }

  /**
   * Check for suspicious keywords - returns array of found keywords
   */
  private static checkSuspiciousKeywords(url: string): string[] {
    const lowerUrl = url.toLowerCase();
    return SUSPICIOUS_KEYWORDS.filter(keyword => lowerUrl.includes(keyword));
  }

  /**
   * Check for known malicious patterns
   */
  private static checkMaliciousPatterns(url: string): string[] {
    const lowerUrl = url.toLowerCase();
    return KNOWN_MALICIOUS_PATTERNS.filter(pattern => lowerUrl.includes(pattern));
  }

  /**
   * Check for brand impersonation
   */
  private static checkBrandImpersonation(hostname: string): { isImpersonating: boolean; brand?: string } {
    const lowerHostname = hostname.toLowerCase();

    for (const brand of BRAND_KEYWORDS) {
      // Check if brand name is in hostname but not as the main domain
      if (lowerHostname.includes(brand)) {
        // Valid brand domains
        const validDomains = [
          `${brand}.com`,
          `www.${brand}.com`,
          `${brand}.net`,
          `${brand}.org`
        ];

        // If hostname contains brand but doesn't match valid domains
        if (!validDomains.some(valid => lowerHostname.endsWith(valid))) {
          return { isImpersonating: true, brand: brand.charAt(0).toUpperCase() + brand.slice(1) };
        }
      }
    }

    return { isImpersonating: false };
  }

  /**
   * Check for homograph attacks (IDN spoofing)
   */
  private static checkHomograph(hostname: string): boolean {
    for (const char of hostname) {
      if (char in HOMOGRAPH_PATTERNS) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for unusual ports
   */
  private static checkUnusualPort(url: URL): boolean {
    if (!url.port) return false;

    const port = parseInt(url.port);
    const standardPorts = [80, 443, 8080, 8443];

    return !standardPorts.includes(port);
  }

  /**
   * Check if URL is a shortener
   */
  private static checkURLShortener(hostname: string): boolean {
    return URL_SHORTENERS.some(shortener => hostname.includes(shortener));
  }

  /**
   * Check TLD risk level
   */
  private static checkTLDRisk(hostname: string): 'low' | 'medium' | 'high' {
    const hostnameUpper = hostname.toLowerCase();

    if (HIGH_RISK_TLDS.some(tld => hostnameUpper.endsWith(tld))) {
      return 'high';
    }

    // Medium risk TLDs
    const mediumRiskTLDs = ['.info', '.biz', '.ws', '.cc', '.pw'];
    if (mediumRiskTLDs.some(tld => hostnameUpper.endsWith(tld))) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Analyze URL length and structure
   */
  private static analyzeLengthAndStructure(url: string, parsedUrl: URL) {
    const isExcessivelyLong = url.length > 150;

    // Count subdomains
    const hostnameParts = parsedUrl.hostname.split('.');
    const hasMultipleSubdomains = hostnameParts.length > 3;

    return {
      isExcessivelyLong,
      hasMultipleSubdomains,
    };
  }

  /**
   * Check for encoding issues and obfuscation
   */
  private static checkEncodingIssues(url: string): string[] {
    const issues: string[] = [];

    // Check for excessive URL encoding
    const encodedChars = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    if (encodedChars > 5) {
      issues.push('Excessive URL encoding detected');
    }

    // Check for mixed encoding
    if (url.includes('%') && url.includes('\\x')) {
      issues.push('Mixed encoding schemes detected');
    }

    // Check for Unicode/Punycode
    if (url.includes('xn--')) {
      issues.push('Punycode encoding detected');
    }

    return issues;
  }

  /**
   * Extract domain from URL
   */
  static extractDomain(url: string): string | null {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.hostname.replace(/^www\./, '');
    } catch {
      return null;
    }
  }

  /**
   * Extract all URLs from text content
   */
  static extractURLs(text: string): string[] {
    const urlPattern = /(https?:\/\/[^\s]+)/g;
    const matches = text.match(urlPattern);
    return matches || [];
  }
}
