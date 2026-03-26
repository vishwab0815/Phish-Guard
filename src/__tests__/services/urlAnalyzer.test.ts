/**
 * URLAnalyzer Unit Tests
 *
 * Tests for the static URL analysis service.
 * Tests pattern matching, suspicious keyword detection, homograph detection, etc.
 */

import { URLAnalyzer } from '@/services/detection/urlAnalyzer'

describe('URLAnalyzer', () => {
  describe('analyze', () => {
    it('should identify valid URLs', async () => {
      const result = await URLAnalyzer.analyze('https://www.google.com')
      expect(result.isValid).toBe(true)
      expect(result.riskScore).toBeLessThan(30) // Safe URL should have low risk
    })

    it('should reject invalid URL format', async () => {
      const result = await URLAnalyzer.analyze('not a url')
      expect(result.isValid).toBe(false)
      expect(result.riskScore).toBe(100)
      expect(result.indicators).toContain('Invalid URL format')
    })

    it('should detect IP addresses as high risk', async () => {
      const result = await URLAnalyzer.analyze('http://192.168.1.1/')
      expect(result.riskScore).toBeGreaterThan(20)
      expect(result.indicators.some(i => i.includes('IP address'))).toBe(true)
    })

    it('should detect high-risk TLDs', async () => {
      const result = await URLAnalyzer.analyze('https://phishing-site.tk')
      expect(result.indicators.some(i => i.includes('high-risk') || i.includes('TLD'))).toBe(true)
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
      // Check for impersonation indicators
      expect(result.riskScore).toBeGreaterThan(30)
    })

    it('should cap risk score at 100', async () => {
      const result = await URLAnalyzer.analyze('http://192.168.1.1:9999/verify-login-paypal?param=123')
      expect(result.riskScore).toBeLessThanOrEqual(100)
    })

    it('should detect @ symbol (credential injection)', async () => {
      const result = await URLAnalyzer.analyze('https://real-site.com@fake-site.com')
      expect(result.indicators.some(i => i.includes('@'))).toBe(true)
      expect(result.riskScore).toBeGreaterThan(15)
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
