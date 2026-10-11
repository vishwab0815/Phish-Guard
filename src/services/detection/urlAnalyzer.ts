/**
 * Advanced URL Analysis Service
 * Performs static analysis on URLs to detect phishing indicators.
 *
 * Everything here is offline: no DNS, no network. It looks only at the
 * text of the URL (scheme, host, path) and compares it against brand
 * domain lists, lookalike rules and known phishing patterns.
 */

import { domainToUnicode } from 'url';
import { isIP } from 'net';
import { isNonPublicIp } from '@/lib/netGuard';

export interface BrandFinding {
  brand: string;
  kind: 'impersonation' | 'lookalike' | 'homograph';
  matched: string; // the label/word that triggered the finding
}

export interface URLAnalysisResult {
  isValid: boolean;
  riskScore: number; // 0-100
  indicators: string[];
  details: {
    scheme?: string;
    hostname?: string;
    hasIPAddress: boolean;
    hasObfuscatedIP?: boolean;
    isPrivateAddress?: boolean; // loopback / private / link-local / localhost
    isDangerousScheme?: boolean; // javascript:, data:, vbscript:, file:
    hasSuspiciousKeywords: boolean;
    hasHomograph: boolean;
    hasUnusualPort: boolean;
    hasShortener: boolean;
    hasEmbeddedCredentials?: boolean;
    isBrandOwnDomain?: boolean; // host belongs to a known brand's real domain
    brandFinding?: BrandFinding;
    tldRisk: 'low' | 'medium' | 'high';
    lengthAnalysis: {
      isExcessivelyLong: boolean;
      hasMultipleSubdomains: boolean;
    };
    encodingIssues: string[];
  };
}

// Suspicious keywords commonly found in phishing URLs.
// Brand names are NOT here: brands are handled by the impersonation checks.
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
  'banking', 'password', 'wallet', 'suspended', 'locked', 'urgent',
  'validate', 'authenticate', 'billing', 'payment', 'refund', 'prize',
  'winner', 'claim', 'expired', 'renew', 'security-check', 'verification',
  'kyc', 'reward', 'unblock',
];

// Known phishing phrases (hyphenated forms seen in phishing hostnames/paths)
const KNOWN_MALICIOUS_PATTERNS = [
  'get-free', 'click-here', 'verify-account', 'secure-login', 'account-update',
  'password-reset', 'confirm-identity', 'suspended-account', 'unlock-account',
  'billing-problem', 'unusual-activity', 'kyc-update', 'update-kyc',
];

/**
 * Brand → tokens to look for in hostnames, and the brand's real domains.
 * A host is the brand's own if it equals one of the domains or is a true
 * subdomain of one ("x.paypal.com" yes, "secure-paypal.com" no).
 */
interface BrandDef { name: string; tokens: string[]; domains: string[] }

const META_DOMAINS = ['facebook.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'messenger.com', 'fbcdn.net', 'fb.me'];

const BRANDS: BrandDef[] = [
  { name: 'Microsoft', tokens: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'hotmail'],
    domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'hotmail.com',
      'azure.com', 'msn.com', 'bing.com', 'windows.net', 'sharepoint.com', 'onedrive.com', 'microsoft365.com', 'skype.com'] },
  { name: 'Google', tokens: ['google', 'gmail', 'youtube'],
    domains: ['google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.com.au', 'google.de', 'google.fr',
      'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 'youtu.be', 'gmail.com', 'goo.gl', 'g.co'] },
  { name: 'Amazon', tokens: ['amazon'],
    domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.com.au', 'amazon.co.jp',
      'amazonaws.com', 'amzn.to', 'amzn.in'] },
  { name: 'Apple', tokens: ['apple', 'icloud', 'itunes'], domains: ['apple.com', 'icloud.com', 'itunes.com', 'me.com'] },
  { name: 'PayPal', tokens: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  { name: 'Facebook', tokens: ['facebook'], domains: META_DOMAINS },
  { name: 'Instagram', tokens: ['instagram'], domains: META_DOMAINS },
  { name: 'WhatsApp', tokens: ['whatsapp'], domains: META_DOMAINS },
  { name: 'Netflix', tokens: ['netflix'], domains: ['netflix.com', 'nflxext.com'] },
  { name: 'LinkedIn', tokens: ['linkedin'], domains: ['linkedin.com', 'lnkd.in'] },
  { name: 'Twitter', tokens: ['twitter'], domains: ['twitter.com', 'x.com', 't.co'] },
  { name: 'Dropbox', tokens: ['dropbox'], domains: ['dropbox.com', 'dropboxusercontent.com'] },
  { name: 'Adobe', tokens: ['adobe'], domains: ['adobe.com'] },
  // Indian brands (frequent targets of SMS/WhatsApp phishing)
  { name: 'SBI', tokens: ['sbi', 'onlinesbi', 'yonosbi'], domains: ['sbi.co.in', 'onlinesbi.sbi', 'sbi.bank.in', 'sbi'] },
  { name: 'HDFC Bank', tokens: ['hdfc', 'hdfcbank'], domains: ['hdfcbank.com', 'hdfc.bank.in', 'hdfc.com'] },
  { name: 'ICICI Bank', tokens: ['icici', 'icicibank'], domains: ['icicibank.com', 'icici.bank.in', 'icicidirect.com'] },
  { name: 'Axis Bank', tokens: ['axisbank'], domains: ['axisbank.com', 'axis.bank.in'] },
  { name: 'Paytm', tokens: ['paytm'], domains: ['paytm.com', 'paytm.in', 'paytmbank.com'] },
  { name: 'PhonePe', tokens: ['phonepe'], domains: ['phonepe.com'] },
  { name: 'IRCTC', tokens: ['irctc'], domains: ['irctc.co.in', 'irctc.com'] },
  { name: 'India Post', tokens: ['indiapost'], domains: ['indiapost.gov.in'] },
  { name: 'Income Tax Department', tokens: ['incometax'], domains: ['incometax.gov.in', 'incometaxindia.gov.in'] },
  { name: 'UIDAI (Aadhaar)', tokens: ['uidai', 'aadhaar', 'aadhar'], domains: ['uidai.gov.in'] },
  { name: 'NPCI', tokens: ['npci'], domains: ['npci.org.in'] },
  { name: 'Flipkart', tokens: ['flipkart'], domains: ['flipkart.com'] },
];

// Words phishers glue onto a brand name ("securepaypal", "myamazon", "appleidsupport")
const BRAND_GLUE_WORDS = /^(?:my|e|i|m|the|get|go|www|secure|security|login|signin|verify|verification|account|accounts|support|help|service|services|online|web|mail|update|net|bank|banking|pay|id|app|official|customer|care|team|auth|kyc|reward|rewards|offer|offers|portal|center|centre)*\d*$/;

// Ordinary words that are one edit away from a brand name — never call these lookalikes
const LOOKALIKE_EXEMPT_WORDS = new Set(['apply', 'apples', 'ample', 'maple', 'adobo', 'abode', 'aerial']);

// High-risk TLDs commonly used in phishing
const HIGH_RISK_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
  '.link', '.download', '.win', '.loan', '.racing', '.review',
  '.zip', '.mov', '.icu', '.cyou', '.sbs', '.cfd', '.rest', '.buzz',
];

const MEDIUM_RISK_TLDS = ['.info', '.biz', '.ws', '.cc', '.pw', '.online', '.site', '.shop', '.live'];

// Common URL shorteners (matched as exact host or subdomain)
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly',
  'bl.ink', 'lnkd.in', 'shorte.st', 'mcaf.ee', 'cutt.ly', 'rb.gy', 'tiny.cc',
  'shorturl.at', 'rebrand.ly', 'v.gd', 's.id', 't.ly', 'surl.li',
];

// Schemes that are not web pages: they run code or embed content directly
const DANGEROUS_SCHEMES: Record<string, string> = {
  'javascript:': 'this runs code',
  'vbscript:': 'this runs code',
  'data:': 'this embeds content directly in the link',
  'file:': 'this opens a file on your device or network',
};

// Multi-part public suffixes we care about (registrable domain = label + suffix)
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'edu.in', 'nic.in', 'res.in', 'bank.in', 'firm.in', 'gen.in', 'ind.in',
  'co.jp', 'ne.jp', 'or.jp', 'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  'co.nz', 'org.nz', 'com.br', 'com.cn', 'com.tw', 'com.hk', 'co.kr', 'co.za',
  'com.sg', 'com.my', 'co.id', 'com.mx', 'com.ar', 'com.tr', 'co.th', 'com.ph', 'com.pk', 'com.ng', 'com.vn', 'com.sa',
]);

/**
 * Hosts where anyone can publish content under a subdomain or path.
 * Trust/brand reputation of the parent must never be inherited by these.
 */
const MULTI_TENANT_SUFFIXES = [
  'github.io', 'vercel.app', 'netlify.app', 'web.app', 'firebaseapp.com', 'blogspot.com',
  'weebly.com', 'wixsite.com', 'pages.dev', 'workers.dev', 'herokuapp.com', 'glitch.me',
  'repl.co', 'onrender.com', 'azurewebsites.net', 'web.core.windows.net', 'appspot.com',
  'sharepoint.com', 'myshopify.com', 'square.site', 'godaddysites.com', 'webflow.io',
];
const MULTI_TENANT_EXACT_HOSTS = ['sites.google.com', 'forms.gle'];
const MULTI_TENANT_HOST_PATHS: Array<[string, string]> = [
  ['docs.google.com', '/forms'],
  ['drive.google.com', '/'],
  ['storage.googleapis.com', '/'],
];

// Confusable characters (Cyrillic / Greek / others) → Latin skeleton
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c',
  'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'һ': 'h', 'ӏ': 'l', 'ԁ': 'd',
  'ԍ': 'g', 'ԛ': 'q', 'ԝ': 'w', 'ү': 'y', 'ɡ': 'g', 'ɑ': 'a',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u',
  'χ': 'x', 'ω': 'w', 'γ': 'y',
  // Armenian / misc
  'օ': 'o', 'ս': 'u', 'ց': 'g', 'ո': 'n', 'ı': 'i', 'ł': 'l', 'ß': 'b',
};

/** Exact host or true subdomain: host === d || host.endsWith('.' + d) */
export function hostMatchesDomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain);
}

/** Levenshtein edit distance (small strings only) */
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 1) return 2; // we only care about ≤1
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** Undo common digit/letter substitutions (paypa1 → paypal, amaz0n → amazon, rnicrosoft → microsoft) */
function substitutionSkeletons(word: string): string[] {
  const base = word.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/3/g, 'e')
    .replace(/5/g, 's').replace(/4/g, 'a').replace(/7/g, 't');
  return Array.from(new Set([base.replace(/1/g, 'l'), base.replace(/1/g, 'i')]));
}

export class URLAnalyzer {
  /**
   * Perform comprehensive analysis on a URL
   */
  static async analyze(url: string): Promise<URLAnalysisResult> {
    const indicators: string[] = [];
    let riskScore = 0;
    const input = (url || '').trim();

    // Validate URL format
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(input);
    } catch {
      return this.invalidResult(['Invalid URL format'], 100);
    }

    const scheme = parsedUrl.protocol.toLowerCase();

    // Non-web schemes: javascript:, data:, vbscript:, file: are never safe to "visit"
    if (scheme in DANGEROUS_SCHEMES) {
      return {
        ...this.invalidResult([`Not a web link — ${DANGEROUS_SCHEMES[scheme]} (${scheme} scheme)`], 100),
        isValid: true,
        details: { ...this.emptyDetails(), scheme, isDangerousScheme: true },
      };
    }

    if (scheme !== 'http:' && scheme !== 'https:') {
      return this.invalidResult([`Unsupported URL scheme "${scheme}" — only http and https links can be analyzed`], 0);
    }

    const hostname = parsedUrl.hostname.toLowerCase().replace(/\.$/, '');
    const bareHost = hostname.replace(/^\[(.*)\]$/, '$1');
    if (!bareHost) return this.invalidResult(['Invalid URL format'], 100);

    // ---- IP address host (incl. hex/decimal/octal forms that WHATWG normalizes) ----
    const hasIPAddress = this.checkIPAddress(bareHost);
    let hasObfuscatedIP = false;
    if (hasIPAddress) {
      indicators.push('URL uses IP address instead of domain name');
      riskScore += 25;

      const rawHost = this.extractRawHost(input);
      if (isIP(bareHost) === 4 && rawHost && rawHost !== bareHost) {
        hasObfuscatedIP = true;
        indicators.push(`IP address is written in an obfuscated form ("${rawHost}" = ${bareHost})`);
        riskScore += 20;
      }
    }

    // ---- Private / internal destinations ----
    const isPrivateAddress = this.isInternalHost(bareHost);
    if (isPrivateAddress) {
      indicators.push('Points to a private/internal network address');
      riskScore += 40;
    }

    // ---- Brand impersonation, typosquatting and IDN homographs ----
    const brandCheck = this.checkBrands(bareHost, hasIPAddress);
    // Content on multi-tenant hosts (sites.google.com, *.sharepoint.com…) is user-made: no brand benefit
    const isBrandOwnDomain = brandCheck.isOwnDomain && !this.isMultiTenantHost(bareHost, parsedUrl.pathname);
    const brandFinding = brandCheck.finding;
    let hasHomograph = false;

    if (brandFinding?.kind === 'homograph') {
      hasHomograph = true;
      indicators.push(`Lookalike of ${brandFinding.brand} using look-alike Unicode characters (IDN homograph: "${brandFinding.matched}")`);
      riskScore += 70;
    } else if (brandFinding?.kind === 'lookalike') {
      indicators.push(`Lookalike of ${brandFinding.brand} (typosquatting: "${brandFinding.matched}")`);
      riskScore += 55;
    } else if (brandFinding?.kind === 'impersonation') {
      indicators.push(`Potential ${brandFinding.brand} impersonation - Domain mismatch detected (not a real ${brandFinding.brand} domain)`);
      riskScore += 45;
    }

    if (!hasHomograph && this.checkHomograph(hostname)) {
      hasHomograph = true;
      indicators.push('Hostname mixes alphabets (e.g. Latin + Cyrillic) — possible IDN spoofing');
      riskScore += 30;
    }

    // Brand mentioned in the path of an unrelated site (e.g. evil.com/paypal/login)
    if (!brandFinding && !isBrandOwnDomain) {
      const pathBrand = this.findBrandInPath(parsedUrl.pathname);
      if (pathBrand) {
        indicators.push(`Mentions ${pathBrand} in the link path but is not on a ${pathBrand} domain`);
        riskScore += 15;
      }
    }

    // ---- Keywords & known phishing phrases (hostname + path only, never query) ----
    let hasSuspiciousKeywords = false;
    if (!isBrandOwnDomain) {
      const hostText = hostname;
      const pathText = this.safeDecode(parsedUrl.pathname).toLowerCase();

      const hostKeywords = this.checkSuspiciousKeywords(hostText);
      const pathKeywords = this.checkSuspiciousKeywords(pathText).filter(k => !hostKeywords.includes(k));
      const hostPatterns = this.checkMaliciousPatterns(hostText);
      const pathPatterns = this.checkMaliciousPatterns(pathText).filter(p => !hostPatterns.includes(p));

      const keywords = [...hostKeywords, ...pathKeywords];
      hasSuspiciousKeywords = keywords.length > 0;

      if (keywords.length > 0) {
        indicators.push(`Suspicious keywords detected: ${keywords.join(', ')}`);
      }
      const patterns = [...hostPatterns, ...pathPatterns];
      if (patterns.length > 0) {
        indicators.push(`Known phishing patterns detected: ${patterns.join(', ')}`);
      }

      // Keywords in the hostname are part of the domain's identity → weigh more
      let hostWords = Math.min(hostKeywords.length * 10, 30);
      if (hostPatterns.length > 0) hostWords += Math.min(25 + (hostPatterns.length - 1) * 10, 45);
      // Keywords only in the path are weak evidence on their own → capped low
      const pathWords = Math.min(pathKeywords.length * 8 + pathPatterns.length * 10, 20);
      riskScore += hostWords + pathWords;
    }

    // ---- Unusual port ----
    const hasUnusualPort = this.checkUnusualPort(parsedUrl);
    if (hasUnusualPort) {
      indicators.push(`Unusual port detected: ${parsedUrl.port}`);
      riskScore += 10;
    }

    // ---- URL shortener ----
    const hasShortener = this.checkURLShortener(bareHost);
    if (hasShortener) {
      indicators.push('URL shortener detected (hides real destination)');
      riskScore += 20;
    }

    // ---- TLD risk ----
    const tldRisk = hasIPAddress ? 'low' : this.checkTLDRisk(bareHost);
    if (tldRisk === 'high') {
      indicators.push('high-risk top-level domain');
      riskScore += 20;
    } else if (tldRisk === 'medium') {
      indicators.push('medium-risk top-level domain');
      riskScore += 10;
    }

    // ---- Length & structure ----
    const lengthAnalysis = this.analyzeLengthAndStructure(input, bareHost, hasIPAddress);
    if (lengthAnalysis.isExcessivelyLong) {
      indicators.push('Excessively long URL (possible obfuscation)');
      riskScore += 10;
    }
    if (lengthAnalysis.hasMultipleSubdomains && !isBrandOwnDomain) {
      indicators.push('Multiple subdomains detected');
      riskScore += 5;
    }

    // ---- Encoding tricks ----
    const encodingIssues = this.checkEncodingIssues(input);
    if (encodingIssues.length > 0) {
      indicators.push(...encodingIssues);
      riskScore += encodingIssues.length * 5;
    }

    // ---- Plain HTTP ----
    if (scheme === 'http:') {
      indicators.push('Insecure HTTP protocol (not HTTPS)');
      riskScore += 15;
    }

    // ---- user:pass@host trick (https://paypal.com@evil.com) ----
    const hasEmbeddedCredentials = parsedUrl.username !== '' || parsedUrl.password !== '';
    if (hasEmbeddedCredentials) {
      indicators.push(`URL hides its real destination with "@" (the actual site is ${hostname})`);
      riskScore += 25;
    }

    return {
      isValid: true,
      riskScore: Math.max(0, Math.min(100, Math.round(riskScore))),
      indicators,
      details: {
        scheme,
        hostname: bareHost,
        hasIPAddress,
        hasObfuscatedIP,
        isPrivateAddress,
        isDangerousScheme: false,
        hasSuspiciousKeywords,
        hasHomograph,
        hasUnusualPort,
        hasShortener,
        hasEmbeddedCredentials,
        isBrandOwnDomain,
        brandFinding,
        tldRisk,
        lengthAnalysis,
        encodingIssues,
      },
    };
  }

  private static emptyDetails(): URLAnalysisResult['details'] {
    return {
      hasIPAddress: false,
      hasSuspiciousKeywords: false,
      hasHomograph: false,
      hasUnusualPort: false,
      hasShortener: false,
      tldRisk: 'low',
      lengthAnalysis: { isExcessivelyLong: false, hasMultipleSubdomains: false },
      encodingIssues: [],
    };
  }

  private static invalidResult(indicators: string[], riskScore: number): URLAnalysisResult {
    return { isValid: false, riskScore, indicators, details: this.emptyDetails() };
  }

  private static safeDecode(text: string): string {
    try { return decodeURIComponent(text); } catch { return text; }
  }

  /** Host part exactly as typed (before WHATWG normalization), for spotting 0x7f000001 etc. */
  private static extractRawHost(input: string): string | null {
    const m = input.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/i);
    return m ? m[1].toLowerCase().replace(/\.$/, '') : null;
  }

  /**
   * Check if hostname is an IP address (IPv4 or IPv6, brackets allowed)
   */
  private static checkIPAddress(hostname: string): boolean {
    return isIP(hostname.replace(/^\[(.*)\]$/, '$1')) !== 0;
  }

  /**
   * True for loopback/private/link-local IPs, localhost, and single-label or
   * reserved internal names (.local, .internal, .lan, .home.arpa).
   */
  static isInternalHost(host: string): boolean {
    const bare = host.toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
    if (!bare) return true;
    if (isIP(bare)) return isNonPublicIp(bare);
    if (bare === 'localhost' || !bare.includes('.')) return true;
    return /\.(localhost|local|internal|intranet|lan|home\.arpa|corp)$/.test(bare);
  }

  /**
   * True only for http(s) URLs whose host is public — the only URLs that
   * may be sent to third-party reputation APIs.
   */
  static isPublicWebUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
      return !this.isInternalHost(parsed.hostname);
    } catch {
      return false;
    }
  }

  /**
   * Check for suspicious keywords - returns array of found keywords
   */
  private static checkSuspiciousKeywords(text: string): string[] {
    const lower = text.toLowerCase();
    return SUSPICIOUS_KEYWORDS.filter(keyword => lower.includes(keyword));
  }

  /**
   * Check for known malicious patterns
   */
  private static checkMaliciousPatterns(text: string): string[] {
    const lower = text.toLowerCase();
    return KNOWN_MALICIOUS_PATTERNS.filter(pattern => lower.includes(pattern));
  }

  /** Is the host one of the brand's real domains (or a true subdomain of one)? */
  private static isBrandDomain(host: string, brand: BrandDef): boolean {
    return brand.domains.some(d => hostMatchesDomain(host, d));
  }

  /**
   * Does a hostname label contain this brand token? Short tokens (sbi, hdfc) must be a
   * whole hyphen-separated word. Longer tokens may start a word ("paypalsecure") or be
   * glued to a typical phishing word ("securepaypal", "myamazon") — but "pineapple" is not Apple.
   */
  private static labelHasToken(label: string, token: string): boolean {
    const words = label.split('-');
    if (token.length < 5) return words.includes(token);
    return words.some(word => {
      if (word.startsWith(token)) return true;
      const at = word.indexOf(token);
      if (at < 0) return false;
      const leftover = word.slice(0, at) + word.slice(at + token.length);
      return BRAND_GLUE_WORDS.test(leftover);
    });
  }

  /**
   * Brand checks on the hostname: impersonation (brand token on a non-brand
   * domain), typosquatting (paypa1, amaz0n, rnicrosoft, edit distance 1) and
   * IDN homographs (Cyrillic "а" in аpple.com).
   */
  private static checkBrands(host: string, isIpHost: boolean): { isOwnDomain: boolean; finding?: BrandFinding } {
    if (isIpHost) return { isOwnDomain: false };

    const ownBrands = BRANDS.filter(b => this.isBrandDomain(host, b));
    const isOwnDomain = ownBrands.length > 0;
    const candidates = BRANDS.filter(b => !ownBrands.some(o => o.domains === b.domains));

    // Labels to inspect: everything except the public suffix
    const registrable = this.getRegistrableDomain(host);
    const suffixLabels = registrable.split('.').length - 1;
    const allLabels = host.split('.');
    const labels = allLabels.slice(0, Math.max(1, allLabels.length - suffixLabels));

    // 1. IDN homograph → decode punycode and compare a Latin skeleton
    const unicodeHost = domainToUnicode(host) || host;
    const unicodeLabels = unicodeHost.split('.').slice(0, labels.length);
    for (const uLabel of unicodeLabels) {
      if (/^[\x00-\x7f]*$/.test(uLabel)) continue;
      const skeleton = Array.from(uLabel).map(ch => CONFUSABLES[ch] ?? ch).join('');
      if (!/^[a-z0-9-]+$/.test(skeleton)) continue;
      for (const brand of BRANDS) {
        if (brand.tokens.some(t => this.labelHasToken(skeleton, t))) {
          return { isOwnDomain: false, finding: { brand: brand.name, kind: 'homograph', matched: uLabel } };
        }
      }
    }

    // 2. Literal brand token on a domain that is not the brand's
    for (const brand of candidates) {
      if (labels.some(label => brand.tokens.some(t => this.labelHasToken(label, t)))) {
        return { isOwnDomain, finding: { brand: brand.name, kind: 'impersonation', matched: host } };
      }
    }

    // 3. Typosquatting: digit/letter swaps and edit distance 1
    for (const brand of candidates) {
      for (const label of labels) {
        const words = Array.from(new Set([...label.split('-'), label.replace(/-/g, '')])).filter(Boolean);
        for (const word of words) {
          for (const token of brand.tokens) {
            if (token.length < 5 || word.includes(token)) continue;
            const swapped = substitutionSkeletons(word).some(s => s !== word && (s === token || s.includes(token)));
            const oneEdit = word.length >= 5 && !LOOKALIKE_EXEMPT_WORDS.has(word) && levenshtein(word, token) === 1;
            if (swapped || oneEdit) {
              return { isOwnDomain, finding: { brand: brand.name, kind: 'lookalike', matched: word } };
            }
          }
        }
      }
    }

    return { isOwnDomain };
  }

  /** Brand name appearing as a path segment word (e.g. /paypal/login, /sbi-kyc) */
  private static findBrandInPath(pathname: string): string | null {
    const words = this.safeDecode(pathname).toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    for (const brand of BRANDS) {
      if (brand.tokens.some(t => t.length >= 5 && words.includes(t))) return brand.name;
    }
    return null;
  }

  /**
   * Check for homograph attacks (IDN spoofing): any label that mixes Latin
   * with Cyrillic/Greek/Armenian letters after punycode decoding.
   */
  private static checkHomograph(hostname: string): boolean {
    const unicode = domainToUnicode(hostname) || hostname;
    return unicode.split('.').some(label => {
      const hasLatin = /[a-z]/i.test(label);
      const hasOther = /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}]/u.test(label);
      return hasLatin && hasOther;
    });
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
   * Check if URL is a shortener (exact host or subdomain match)
   */
  private static checkURLShortener(hostname: string): boolean {
    const host = hostname.toLowerCase().replace(/^www\./, '');
    return URL_SHORTENERS.some(shortener => hostMatchesDomain(host, shortener));
  }

  /**
   * Check TLD risk level
   */
  private static checkTLDRisk(hostname: string): 'low' | 'medium' | 'high' {
    const host = hostname.toLowerCase();

    if (HIGH_RISK_TLDS.some(tld => host.endsWith(tld))) {
      return 'high';
    }

    if (MEDIUM_RISK_TLDS.some(tld => host.endsWith(tld))) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Analyze URL length and structure
   */
  private static analyzeLengthAndStructure(url: string, hostname: string, isIpHost: boolean) {
    const isExcessivelyLong = url.length > 150;

    // Count subdomain labels in front of the registrable domain
    let hasMultipleSubdomains = false;
    if (!isIpHost) {
      const registrable = this.getRegistrableDomain(hostname);
      const subLabels = hostname.split('.').length - registrable.split('.').length;
      hasMultipleSubdomains = subLabels >= 3;
    }

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

    // Check for Unicode/Punycode in the host
    if (/(^|[./])xn--/i.test(url) || /[^\x00-\x7f]/.test(url.split(/[/?#]/)[2] || '')) {
      issues.push('Punycode encoding detected');
    }

    return issues;
  }

  /**
   * Registrable domain for a hostname ("login.microsoftonline.com" → "microsoftonline.com",
   * "www.amazon.co.uk" → "amazon.co.uk"). IPs are returned unchanged.
   */
  static getRegistrableDomain(hostname: string): string {
    const host = hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
    if (isIP(host) || !host.includes('.')) return host;

    const parts = host.split('.');
    if (parts.length <= 2) return host;

    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo)) return parts.slice(-3).join('.');
    return lastTwo;
  }

  /**
   * True when the host (optionally with path) is on a platform where anyone can
   * publish content: github.io, vercel.app, sites.google.com, docs.google.com/forms, …
   */
  static isMultiTenantHost(hostname: string, pathname: string = '/'): boolean {
    const host = hostname.toLowerCase().replace(/\.$/, '');
    if (MULTI_TENANT_EXACT_HOSTS.includes(host)) return true;
    if (MULTI_TENANT_SUFFIXES.some(s => hostMatchesDomain(host, s))) return true;
    return MULTI_TENANT_HOST_PATHS.some(([h, p]) => host === h && pathname.toLowerCase().startsWith(p));
  }

  /**
   * Extract domain from URL
   */
  static extractDomain(url: string): string | null {
    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.replace(/^www\./, '');
      if (!hostname) return null;

      if (this.checkIPAddress(hostname) || hostname === 'localhost') {
        return hostname.replace(/^\[(.*)\]$/, '$1');
      }

      return this.getRegistrableDomain(hostname);
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
