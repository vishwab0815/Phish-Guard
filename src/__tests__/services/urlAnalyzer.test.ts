/** @jest-environment node */
/**
 * URLAnalyzer Unit Tests
 *
 * Tests for the static URL analysis service.
 * Tests pattern matching, suspicious keyword detection, homograph detection, etc.
 * Fully offline: URLAnalyzer does no network or DNS work.
 */

import { URLAnalyzer } from '@/services/detection/urlAnalyzer'

const hasIndicator = (indicators: string[], text: string) =>
  indicators.some(i => i.toLowerCase().includes(text.toLowerCase()))

describe('URLAnalyzer', () => {
  describe('analyze', () => {
    it('should identify valid URLs', async () => {
      const result = await URLAnalyzer.analyze('https://www.google.com')
      expect(result.isValid).toBe(true)
      expect(result.riskScore).toBeLessThan(15) // Brand's own domain, HTTPS → no findings
    })

    it('should reject invalid URL format', async () => {
      const result = await URLAnalyzer.analyze('not a url')
      expect(result.isValid).toBe(false)
      expect(result.riskScore).toBe(100)
      expect(result.indicators).toContain('Invalid URL format')
    })

    it('should not analyze unsupported schemes', async () => {
      const result = await URLAnalyzer.analyze('ftp://files.example.com/a.txt')
      expect(result.isValid).toBe(false)
      expect(hasIndicator(result.indicators, 'Unsupported URL scheme')).toBe(true)
    })

    it('should detect IP addresses as high risk', async () => {
      const result = await URLAnalyzer.analyze('http://192.168.1.1/')
      expect(result.riskScore).toBeGreaterThan(20)
      expect(result.indicators.some(i => i.includes('IP address'))).toBe(true)
    })

    it('should detect high-risk TLDs', async () => {
      const result = await URLAnalyzer.analyze('https://phishing-site.tk')
      expect(result.indicators.some(i => i.includes('.tk web address ending'))).toBe(true)
      expect(result.riskScore).toBeGreaterThan(10)
    })

    it('should detect suspicious keywords', async () => {
      const result = await URLAnalyzer.analyze('https://verify-paypal-login.com')
      expect(result.indicators.some(i => i.includes('Suspicious keywords'))).toBe(true)
      expect(result.riskScore).toBeGreaterThan(15)
    })

    it('should detect URL shorteners as suspicious', async () => {
      const result = await URLAnalyzer.analyze('https://bit.ly/abc123')
      expect(result.indicators.some(i => i.includes('shortener'))).toBe(true)
      expect(result.riskScore).toBeGreaterThan(10)
    })

    it('should flag HTTP URLs that should use HTTPS', async () => {
      const result = await URLAnalyzer.analyze('http://example.com')
      expect(result.indicators.some(i => i.includes('HTTP'))).toBe(true)
      expect(result.riskScore).toBeGreaterThan(10)
    })

    it('should detect brand impersonation', async () => {
      const result = await URLAnalyzer.analyze('https://amazon-verify.com/login')
      expect(hasIndicator(result.indicators, 'Amazon impersonation')).toBe(true)
      expect(result.riskScore).toBeGreaterThan(30)
    })

    it('should cap risk score at 100', async () => {
      const result = await URLAnalyzer.analyze('http://192.168.1.1:9999/verify-login-paypal?param=123')
      expect(result.riskScore).toBeLessThanOrEqual(100)
      expect(result.riskScore).toBeGreaterThanOrEqual(0)
    })

    it('should detect @ symbol (credential injection)', async () => {
      const result = await URLAnalyzer.analyze('https://real-site.com@fake-site.com')
      expect(result.indicators.some(i => i.includes('@'))).toBe(true)
      expect(result.indicators.some(i => i.includes('fake-site.com'))).toBe(true)
      expect(result.riskScore).toBeGreaterThan(15)
    })

    it('should not treat "@" in the path or query as credentials', async () => {
      const result = await URLAnalyzer.analyze('https://example.com/contact?email=a@b.com')
      expect(result.details.hasEmbeddedCredentials).toBe(false)
      expect(result.indicators.some(i => i.includes('@'))).toBe(false)
    })
  })

  describe('legitimate brand domains are not flagged (regressions)', () => {
    const legit = [
      'https://login.microsoftonline.com/common/oauth2/authorize',
      'https://accounts.google.com/signin',
      'https://www.reddit.com/r/netsec',
      'https://www.amazon.co.uk/gp/your-account',
      'https://www.google.co.in/search?q=login+verify+account',
      'https://onlinesbi.sbi/',
      'https://www.hdfcbank.com/personal/login',
      'https://www.microsoft.com/en-in',
    ]

    it.each(legit)('%s → no impersonation, shortener or keyword findings', async (url) => {
      const result = await URLAnalyzer.analyze(url)
      expect(result.isValid).toBe(true)
      expect(result.details.brandFinding).toBeUndefined()
      expect(result.details.hasShortener).toBe(false)
      expect(hasIndicator(result.indicators, 'impersonation')).toBe(false)
      expect(hasIndicator(result.indicators, 'Lookalike')).toBe(false)
      expect(hasIndicator(result.indicators, 'Suspicious keywords')).toBe(false)
      expect(result.riskScore).toBeLessThan(15)
    })

    it('does not match brand names inside unrelated words (pineapple ≠ Apple)', async () => {
      const result = await URLAnalyzer.analyze('https://pineapple.com')
      expect(result.details.brandFinding).toBeUndefined()
    })

    it('keyword-only evidence in the path of a clean domain stays low', async () => {
      const result = await URLAnalyzer.analyze('https://example.com/account/verify-account/login')
      expect(hasIndicator(result.indicators, 'Suspicious keywords')).toBe(true)
      expect(result.riskScore).toBeLessThan(30)
    })

    it('ignores keywords in the query string', async () => {
      const result = await URLAnalyzer.analyze('https://example.com/search?q=verify+login+password')
      expect(result.details.hasSuspiciousKeywords).toBe(false)
      expect(result.riskScore).toBe(0)
    })
  })

  describe('phishing lookalikes are flagged (regressions)', () => {
    it('secure-paypal.com → PayPal impersonation (endsWith bug)', async () => {
      const result = await URLAnalyzer.analyze('https://secure-paypal.com')
      expect(result.details.brandFinding).toMatchObject({ brand: 'PayPal', kind: 'impersonation' })
      expect(result.riskScore).toBeGreaterThanOrEqual(45)
    })

    it('paypa1-secure-login.xyz → lookalike of PayPal', async () => {
      const result = await URLAnalyzer.analyze('http://paypa1-secure-login.xyz')
      expect(hasIndicator(result.indicators, 'Lookalike of PayPal')).toBe(true)
      expect(result.riskScore).toBeGreaterThanOrEqual(70)
    })

    it('amaz0n.in → lookalike of Amazon', async () => {
      const result = await URLAnalyzer.analyze('https://amaz0n.in')
      expect(hasIndicator(result.indicators, 'Lookalike of Amazon')).toBe(true)
    })

    it('rnicrosoft.com → lookalike of Microsoft (rn → m)', async () => {
      const result = await URLAnalyzer.analyze('https://rnicrosoft.com')
      expect(hasIndicator(result.indicators, 'Lookalike of Microsoft')).toBe(true)
    })

    it('xn--pple-43d.com (Cyrillic "а" + "pple") → Unicode lookalike of Apple', async () => {
      const result = await URLAnalyzer.analyze('https://xn--pple-43d.com/')
      expect(result.details.hasHomograph).toBe(true)
      expect(result.details.brandFinding).toMatchObject({ brand: 'Apple', kind: 'homograph' })
      expect(result.riskScore).toBeGreaterThanOrEqual(70)
    })

    it('flags mixed-script hostnames even without a brand match', async () => {
      // "exаmple.com" with a Cyrillic "а"
      const result = await URLAnalyzer.analyze('https://ex\u0430mple.com/')
      expect(result.details.hasHomograph).toBe(true)
    })

    it('sbi-kyc-update.top → SBI impersonation', async () => {
      const result = await URLAnalyzer.analyze('https://sbi-kyc-update.top/')
      expect(result.details.brandFinding).toMatchObject({ brand: 'SBI', kind: 'impersonation' })
      expect(result.riskScore).toBeGreaterThanOrEqual(70)
    })
  })

  describe('non-web schemes', () => {
    it('javascript: → risk 100', async () => {
      const result = await URLAnalyzer.analyze('javascript:alert(1)')
      expect(result.riskScore).toBe(100)
      expect(result.details.isDangerousScheme).toBe(true)
      expect(hasIndicator(result.indicators, 'Not a web link')).toBe(true)
    })

    it('data: → risk 100', async () => {
      const result = await URLAnalyzer.analyze('data:text/html,<script>alert(1)</script>')
      expect(result.riskScore).toBe(100)
      expect(hasIndicator(result.indicators, 'Not a web link')).toBe(true)
    })

    it('vbscript: and file: → risk 100', async () => {
      expect((await URLAnalyzer.analyze('vbscript:msgbox(1)')).riskScore).toBe(100)
      expect((await URLAnalyzer.analyze('file:///C:/Windows/system.ini')).riskScore).toBe(100)
    })
  })

  describe('shorteners', () => {
    it('bit.ly/x → shortener', async () => {
      const result = await URLAnalyzer.analyze('https://bit.ly/x')
      expect(result.details.hasShortener).toBe(true)
    })

    it('t.co matches only t.co, not reddit.com or microsoft.com', async () => {
      expect((await URLAnalyzer.analyze('https://t.co/abc')).details.hasShortener).toBe(true)
      expect((await URLAnalyzer.analyze('https://www.reddit.com')).details.hasShortener).toBe(false)
      expect((await URLAnalyzer.analyze('https://www.microsoft.com')).details.hasShortener).toBe(false)
    })
  })

  describe('IP hosts', () => {
    it('http://192.168.1.1 → IP + private network', async () => {
      const result = await URLAnalyzer.analyze('http://192.168.1.1')
      expect(result.details.hasIPAddress).toBe(true)
      expect(result.details.isPrivateAddress).toBe(true)
      expect(hasIndicator(result.indicators, 'private/internal network')).toBe(true)
    })

    it('http://0x7f000001 (hex loopback) → IP flagged as obfuscated + private', async () => {
      const result = await URLAnalyzer.analyze('http://0x7f000001')
      expect(result.details.hasIPAddress).toBe(true)
      expect(result.details.hasObfuscatedIP).toBe(true)
      expect(result.details.isPrivateAddress).toBe(true)
    })

    it('http://2130706433 (decimal loopback) → IP flagged', async () => {
      const result = await URLAnalyzer.analyze('http://2130706433/')
      expect(result.details.hasIPAddress).toBe(true)
      expect(result.details.hasObfuscatedIP).toBe(true)
    })

    it('localhost is internal', async () => {
      const result = await URLAnalyzer.analyze('http://localhost:3000/admin')
      expect(result.details.isPrivateAddress).toBe(true)
    })

    it('public IPs are flagged as IPs but not private', async () => {
      const result = await URLAnalyzer.analyze('https://8.8.8.8/')
      expect(result.details.hasIPAddress).toBe(true)
      expect(result.details.isPrivateAddress).toBe(false)
    })
  })

  describe('isPublicWebUrl', () => {
    it('allows only public http(s) URLs', () => {
      expect(URLAnalyzer.isPublicWebUrl('https://example.com')).toBe(true)
      expect(URLAnalyzer.isPublicWebUrl('http://127.0.0.1')).toBe(false)
      expect(URLAnalyzer.isPublicWebUrl('http://[::1]/')).toBe(false)
      expect(URLAnalyzer.isPublicWebUrl('http://localhost')).toBe(false)
      expect(URLAnalyzer.isPublicWebUrl('http://169.254.169.254/latest/meta-data')).toBe(false)
      expect(URLAnalyzer.isPublicWebUrl('javascript:alert(1)')).toBe(false)
    })
  })

  describe('isMultiTenantHost', () => {
    it('recognises shared hosting platforms', () => {
      expect(URLAnalyzer.isMultiTenantHost('evil.github.io')).toBe(true)
      expect(URLAnalyzer.isMultiTenantHost('sites.google.com')).toBe(true)
      expect(URLAnalyzer.isMultiTenantHost('docs.google.com', '/forms/d/abc/viewform')).toBe(true)
      expect(URLAnalyzer.isMultiTenantHost('docs.google.com', '/document/d/abc')).toBe(false)
      expect(URLAnalyzer.isMultiTenantHost('accounts.google.com')).toBe(false)
    })
  })

  describe('extractDomain', () => {
    it('should extract domain from standard URL', () => {
      const domain = URLAnalyzer.extractDomain('https://www.example.com/path')
      expect(domain).toBe('example.com')
    })

    it('should extract domain from subdomain', () => {
      const domain = URLAnalyzer.extractDomain('https://api.service.example.com')
      expect(domain).toBe('example.com')
    })

    it('should handle URLs with ports', () => {
      const domain = URLAnalyzer.extractDomain('https://example.com:8443')
      expect(domain).toBe('example.com')
    })

    it('should handle multi-part public suffixes', () => {
      expect(URLAnalyzer.extractDomain('https://www.amazon.co.uk/x')).toBe('amazon.co.uk')
      expect(URLAnalyzer.extractDomain('https://retail.sbi.bank.in')).toBe('sbi.bank.in')
    })

    it('should return null for invalid URLs', () => {
      const domain = URLAnalyzer.extractDomain('not a url')
      expect(domain).toBeNull()
    })
  })

  describe('checkIPAddress', () => {
    it('should identify IPv4 addresses', () => {
      const isIP = URLAnalyzer['checkIPAddress']('192.168.1.1')
      expect(isIP).toBe(true)
    })

    it('should identify IPv6 addresses', () => {
      const isIP = URLAnalyzer['checkIPAddress']('[2001:db8::1]')
      expect(isIP).toBe(true)
    })

    it('should not identify domains as IPs', () => {
      const isIP = URLAnalyzer['checkIPAddress']('example.com')
      expect(isIP).toBe(false)
    })

    it('should not treat hex-looking words as IPv6', () => {
      expect(URLAnalyzer['checkIPAddress']('deadbeef')).toBe(false)
      expect(URLAnalyzer['checkIPAddress']('cafe')).toBe(false)
    })
  })

  describe('checkTLDRisk', () => {
    it('should identify high-risk TLDs', () => {
      const risk = URLAnalyzer['checkTLDRisk']('malicious.tk')
      expect(risk).toBe('high')
    })

    it('should identify safe TLDs', () => {
      const risk = URLAnalyzer['checkTLDRisk']('example.com')
      expect(risk).toBe('low')
    })

    it('should handle multiple subdomains', () => {
      const risk = URLAnalyzer['checkTLDRisk']('api.v2.service.xyz')
      expect(risk).toMatch(/low|medium|high/)
    })
  })
})
