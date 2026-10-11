/** @jest-environment node */
/**
 * MasterDetector tests
 *  - scoreLayers / heuristicFloors / computeConfidence are pure functions
 *  - analyzeURL is exercised with the DB, network layers and threat feeds mocked
 */

const mockReturning = jest.fn()
const mockValues = jest.fn(() => ({ returning: mockReturning }))
const mockInsert = jest.fn(() => ({ values: mockValues }))

jest.mock('@/db', () => ({ db: { insert: (...args: unknown[]) => (mockInsert as any)(...args) } }))
jest.mock('@/services/detection/domainService', () => ({
  DomainService: {
    isTrustedDomain: jest.fn(),
    isBlockedDomain: jest.fn(),
    analyze: jest.fn(),
  },
}))
jest.mock('@/services/detection/sslValidator', () => ({ SSLValidator: { analyze: jest.fn() } }))
jest.mock('@/services/external/googleSafeBrowsing', () => ({ GoogleSafeBrowsingService: { checkURL: jest.fn() } }))
jest.mock('@/services/external/phishTank', () => ({ PhishTankService: { checkURL: jest.fn() } }))
jest.mock('@/services/external/virusTotal', () => ({ VirusTotalService: { analyzeURL: jest.fn() } }))

import {
  MasterDetector,
  scoreLayers,
  heuristicFloors,
  computeConfidence,
  threatLevelForScore,
  RiskBreakdown,
} from '@/services/detection/masterDetector'
import { URLAnalyzer } from '@/services/detection/urlAnalyzer'
import { DomainService } from '@/services/detection/domainService'
import { SSLValidator } from '@/services/detection/sslValidator'
import { GoogleSafeBrowsingService } from '@/services/external/googleSafeBrowsing'
import { PhishTankService } from '@/services/external/phishTank'
import { VirusTotalService } from '@/services/external/virusTotal'

const sum = (b: RiskBreakdown[]) => b.reduce((s, e) => s + e.riskContribution, 0)
const layerEntries = (b: RiskBreakdown[]) => b.filter(e => e.layer !== 'Override')

describe('scoreLayers', () => {
  it('renormalizes weights over the layers that produced data', () => {
    // Only static analysis has data → it carries 100% of the weight
    const onlyStatic = scoreLayers({ static: 80 })
    expect(onlyStatic.riskScore).toBe(80)
    expect(onlyStatic.breakdown).toHaveLength(1)
    expect(onlyStatic.breakdown[0].weight).toBe(100)

    // All heuristic layers at 100 → 100 (old code capped around 70 here)
    expect(scoreLayers({ static: 100, domain: 100, ssl: 100, ip: 100 }).riskScore).toBe(100)

    // static 35 / domain 30 → static 60 & domain 0 = 60 * 35/65 ≈ 32
    const two = scoreLayers({ static: 60, domain: 0 })
    expect(two.riskScore).toBe(32)
  })

  it('a missing layer does not dilute the score like a 0 would', () => {
    const withoutSsl = scoreLayers({ static: 60, domain: 60 }).riskScore
    const withCleanSsl = scoreLayers({ static: 60, domain: 60, ssl: 0 }).riskScore
    expect(withoutSsl).toBe(60)
    expect(withCleanSsl).toBeLessThan(withoutSsl)
  })

  it('breakdown layer contributions sum to the pre-override score', () => {
    const inputs = [
      { static: 37, domain: 11, ssl: 53 },
      { static: 99, domain: 1, ssl: 1, ip: 70 },
      { static: 13 },
      { static: 45, ssl: 30 },
    ]
    for (const input of inputs) {
      const out = scoreLayers(input)
      expect(sum(layerEntries(out.breakdown))).toBe(out.preOverrideScore)
      expect(sum(out.breakdown)).toBe(out.riskScore)
    }
  })

  it('Google Safe Browsing hit → at least 90 (CRITICAL) with an override entry', () => {
    const out = scoreLayers({ static: 0, domain: 0, ssl: 0, external: { safeBrowsingThreat: 'SOCIAL_ENGINEERING' } })
    expect(out.preOverrideScore).toBe(0)
    expect(out.riskScore).toBeGreaterThanOrEqual(90)
    expect(threatLevelForScore(out.riskScore)).toBe('CRITICAL')
    const override = out.breakdown.find(e => e.layer === 'Override')
    expect(override).toBeDefined()
    expect(override!.details).toMatch(/Safe Browsing/)
    expect(sum(layerEntries(out.breakdown))).toBe(out.preOverrideScore)
    expect(sum(out.breakdown)).toBe(out.riskScore)
  })

  it('PhishTank verified phish → at least 90', () => {
    expect(scoreLayers({ static: 5, external: { phishTankVerified: true } }).riskScore).toBeGreaterThanOrEqual(90)
  })

  it('VirusTotal thresholds: ≥3 malicious → ≥80, 2 → ≥30, 1 → ≥15 (LOW only), 0 → no override', () => {
    expect(scoreLayers({ static: 0, external: { virusTotalMalicious: 3 } }).riskScore).toBeGreaterThanOrEqual(80)
    expect(scoreLayers({ static: 0, external: { virusTotalMalicious: 7 } }).riskScore).toBeGreaterThanOrEqual(80)

    const one = scoreLayers({ static: 0, external: { virusTotalMalicious: 1 } })
    expect(one.riskScore).toBeGreaterThanOrEqual(15)
    expect(one.riskScore).toBeLessThan(30)
    const two = scoreLayers({ static: 0, external: { virusTotalMalicious: 2 } })
    expect(two.riskScore).toBeGreaterThanOrEqual(30)
    expect(two.riskScore).toBeLessThan(50)

    const none = scoreLayers({ static: 0, external: { virusTotalMalicious: 0 } })
    expect(none.riskScore).toBe(0)
    expect(none.breakdown.find(e => e.layer === 'Override')).toBeUndefined()
  })

  it('overrides never lower a higher weighted score', () => {
    const out = scoreLayers({ static: 95, domain: 95, external: { virusTotalMalicious: 1 } })
    expect(out.riskScore).toBe(out.preOverrideScore)
    expect(out.riskScore).toBeGreaterThan(45)
  })

  it('blocklist → 100', () => {
    const out = scoreLayers({ static: 0, blocked: true })
    expect(out.riskScore).toBe(100)
    expect(threatLevelForScore(out.riskScore)).toBe('CRITICAL')
  })

  it('trusted domain ignores heuristics but a feed hit still wins', () => {
    const trusted = scoreLayers({ static: 80, domain: 50, trusted: true, floors: [{ min: 60, reason: 'x' }] })
    expect(trusted.riskScore).toBe(0)

    const trustedButListed = scoreLayers({ static: 0, trusted: true, external: { safeBrowsingThreat: 'MALWARE' } })
    expect(trustedButListed.riskScore).toBeGreaterThanOrEqual(90)
  })

  it('clamps out-of-range layer input', () => {
    const out = scoreLayers({ static: 250, domain: -40 })
    expect(out.riskScore).toBeGreaterThanOrEqual(0)
    expect(out.riskScore).toBeLessThanOrEqual(100)
  })
})

describe('threatLevelForScore', () => {
  it('keeps the documented thresholds', () => {
    expect(threatLevelForScore(70)).toBe('CRITICAL')
    expect(threatLevelForScore(69)).toBe('HIGH')
    expect(threatLevelForScore(50)).toBe('HIGH')
    expect(threatLevelForScore(30)).toBe('MEDIUM')
    expect(threatLevelForScore(15)).toBe('LOW')
    expect(threatLevelForScore(14)).toBe('SAFE')
  })
})

describe('heuristicFloors', () => {
  it('lookalike and homograph domains are not averaged away', async () => {
    const homograph = await URLAnalyzer.analyze('https://xn--pple-43d.com')
    const floors = heuristicFloors(homograph)
    const out = scoreLayers({ static: homograph.riskScore, domain: 0, ssl: 0, floors })
    expect(threatLevelForScore(out.riskScore)).toBe('CRITICAL')

    const typo = await URLAnalyzer.analyze('https://amaz0n.in')
    const typoOut = scoreLayers({ static: typo.riskScore, domain: 0, ssl: 0, floors: heuristicFloors(typo) })
    expect(typoOut.riskScore).toBeGreaterThanOrEqual(50)
  })

  it('newly registered domain adds a floor', () => {
    expect(heuristicFloors(undefined, 3).some(f => f.min >= 30)).toBe(true)
    expect(heuristicFloors(undefined, 400)).toHaveLength(0)
  })
})

describe('computeConfidence', () => {
  const base = { staticData: true, domainData: false, sslData: false, feedsConsulted: 0, feedHit: false, trusted: false, definitive: false }

  it('does not grow for layers that returned nothing', () => {
    const staticOnly = computeConfidence(base)
    expect(staticOnly).toBeLessThan(60)
    expect(computeConfidence({ ...base, domainData: true, sslData: true })).toBeGreaterThan(staticOnly)
  })

  it('increases when threat feeds were consulted', () => {
    expect(computeConfidence({ ...base, feedsConsulted: 2 })).toBeGreaterThan(computeConfidence(base))
  })

  it('is high for definitive findings', () => {
    expect(computeConfidence({ ...base, feedHit: true })).toBeGreaterThanOrEqual(90)
    expect(computeConfidence({ ...base, definitive: true })).toBeGreaterThanOrEqual(90)
  })
})

describe('MasterDetector.analyzeURL', () => {
  const mocked = {
    isTrusted: DomainService.isTrustedDomain as jest.Mock,
    isBlocked: DomainService.isBlockedDomain as jest.Mock,
    domain: DomainService.analyze as jest.Mock,
    ssl: SSLValidator.analyze as jest.Mock,
    gsb: GoogleSafeBrowsingService.checkURL as jest.Mock,
    pt: PhishTankService.checkURL as jest.Mock,
    vt: VirusTotalService.analyzeURL as jest.Mock,
  }

  const cleanDomain = { domain: 'x', riskScore: 0, indicators: [], hasData: true, domainAgeStatus: 'known', whoisData: { domainAge: 3000 }, reputation: { isKnownPhishing: false, isKnownMalware: false, reportCount: 0 } }
  const cleanSsl = { hostname: 'x', isValid: true, certificateAvailable: true, riskScore: 0, indicators: [], trustAnalysis: {} }
  const vtNone = { status: 'unavailable', maliciousCount: 0, totalEngines: 0 }

  beforeEach(() => {
    jest.clearAllMocks()
    jest.spyOn(console, 'error').mockImplementation(() => {})
    mockReturning.mockResolvedValue([{ id: 'scan-123' }])
    mocked.isTrusted.mockResolvedValue(false)
    mocked.isBlocked.mockResolvedValue(false)
    mocked.domain.mockResolvedValue(cleanDomain)
    mocked.ssl.mockResolvedValue(cleanSsl)
    mocked.gsb.mockResolvedValue({ isThreat: false, checked: false })
    mocked.pt.mockResolvedValue({ isPhishing: false, verified: false, checked: false })
    mocked.vt.mockResolvedValue(vtNone)
  })

  it('returns scanId from the inserted row and does not create users', async () => {
    const result = await MasterDetector.analyzeURL('https://www.example.com/', 'user-1')
    expect(result.scanId).toBe('scan-123')
    expect(mockInsert).toHaveBeenCalledTimes(1) // scan_results only
    expect((mockValues.mock.calls[0] as any[])[0]).toMatchObject({ userId: 'user-1', target: 'https://www.example.com/' })
    expect(result.threatLevel).toBe('SAFE')
  })

  it('saves anonymous scans with a null userId', async () => {
    await MasterDetector.analyzeURL('https://www.example.com/')
    expect((mockValues.mock.calls[0] as any[])[0]).toMatchObject({ userId: null })
  })

  it('still returns a result when saving fails (scanId undefined)', async () => {
    mockReturning.mockRejectedValue(new Error('db down'))
    const result = await MasterDetector.analyzeURL('https://www.example.com/')
    expect(result.scanId).toBeUndefined()
    expect(result.riskScore).toBeGreaterThanOrEqual(0)
  })

  it('Safe Browsing hit → CRITICAL even when every heuristic is clean', async () => {
    mocked.gsb.mockResolvedValue({ isThreat: true, checked: true, threatType: 'SOCIAL_ENGINEERING' })
    const result = await MasterDetector.analyzeURL('https://www.example.com/')
    expect(result.riskScore).toBeGreaterThanOrEqual(90)
    expect(result.threatLevel).toBe('CRITICAL')
    expect(result.riskBreakdown!.some(e => e.layer === 'Override')).toBe(true)
  })

  it('trusted domain still runs the threat feeds, and a feed hit wins over trust', async () => {
    mocked.isTrusted.mockResolvedValue(true)
    mocked.vt.mockResolvedValue({ status: 'completed', maliciousCount: 5, totalEngines: 90 })
    const result = await MasterDetector.analyzeURL('https://login.example.com/')
    expect(mocked.vt).toHaveBeenCalled()
    expect(mocked.domain).not.toHaveBeenCalled()
    expect(result.riskScore).toBeGreaterThanOrEqual(80)
    expect(result.threatLevel).toBe('CRITICAL')
  })

  it('trusted domain with clean feeds → SAFE', async () => {
    mocked.isTrusted.mockResolvedValue(true)
    mocked.gsb.mockResolvedValue({ isThreat: false, checked: true })
    const result = await MasterDetector.analyzeURL('https://www.example.com/')
    expect(result.riskScore).toBe(0)
    expect(result.threatLevel).toBe('SAFE')
    expect(result.confidence).toBeLessThan(100)
  })

  it('multi-tenant hosts never inherit trust', async () => {
    mocked.isTrusted.mockResolvedValue(true)
    await MasterDetector.analyzeURL('https://attacker.github.io/login')
    expect(mocked.isTrusted).not.toHaveBeenCalled()
    expect(mocked.domain).toHaveBeenCalled()
  })

  it('blocked domain → 100', async () => {
    mocked.isBlocked.mockResolvedValue(true)
    const result = await MasterDetector.analyzeURL('https://evil.example.com/')
    expect(result.riskScore).toBe(100)
    expect(result.threatLevel).toBe('CRITICAL')
  })

  it('never sends private/internal URLs to external APIs', async () => {
    for (const url of ['http://192.168.1.1/admin', 'http://0x7f000001/', 'http://localhost:3000/']) {
      const result = await MasterDetector.analyzeURL(url)
      expect(result.indicators.some(i => i.includes('private/internal network'))).toBe(true)
      expect(['HIGH', 'CRITICAL']).toContain(result.threatLevel)
    }
    expect(mocked.gsb).not.toHaveBeenCalled()
    expect(mocked.pt).not.toHaveBeenCalled()
    expect(mocked.vt).not.toHaveBeenCalled()
    expect(mocked.ssl).not.toHaveBeenCalled()
  })

  it('javascript: links are CRITICAL without any network calls', async () => {
    const result = await MasterDetector.analyzeURL('javascript:alert(document.cookie)')
    expect(result.riskScore).toBe(100)
    expect(result.threatLevel).toBe('CRITICAL')
    expect(mocked.gsb).not.toHaveBeenCalled()
    expect(mocked.domain).not.toHaveBeenCalled()
  })

  it('SSL layer with no certificate data is not scored', async () => {
    mocked.ssl.mockResolvedValue({ ...cleanSsl, certificateAvailable: false, isValid: false, riskScore: 0, indicators: ['Could not retrieve a TLS certificate'] })
    const result = await MasterDetector.analyzeURL('https://www.example.com/')
    expect(result.riskBreakdown!.some(e => e.layer === 'SSL/TLS Certificate')).toBe(false)
  })

  it('PhishTank unverified submissions are not treated as phishing', async () => {
    mocked.pt.mockResolvedValue({ isPhishing: false, verified: false, inDatabase: true, checked: true })
    const result = await MasterDetector.analyzeURL('https://www.example.com/')
    expect(result.threatLevel).toBe('SAFE')
  })
})
