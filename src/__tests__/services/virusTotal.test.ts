/** @jest-environment node */
/**
 * VirusTotal (and other threat-feed) client tests — offline: fetch is mocked.
 */

import { VirusTotalService } from '@/services/external/virusTotal'
import { PhishTankService } from '@/services/external/phishTank'
import { GoogleSafeBrowsingService } from '@/services/external/googleSafeBrowsing'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const urlReport = (stats: Record<string, number>, results: Record<string, unknown> = {}) => ({
  data: { type: 'url', id: 'x', attributes: { last_analysis_stats: stats, last_analysis_results: results, last_analysis_date: 1700000000 } },
})

const analysis = (status: string, stats: Record<string, number> = {}, results: Record<string, unknown> = {}) => ({
  data: { type: 'analysis', id: 'u-abc', attributes: { status, stats, results, date: 1700000000 } },
})

const b64url = (s: string) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

let fetchMock: jest.SpyInstance

beforeEach(() => {
  process.env.VIRUSTOTAL_API_KEY = 'test-key'
  VirusTotalService.clearCache()
  VirusTotalService.pollDelaysMs = [0]
  ;(VirusTotalService as unknown as { recentRequests: number[] }).recentRequests = []
  fetchMock = jest.spyOn(global, 'fetch')
  jest.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(() => {
  jest.restoreAllMocks()
  delete process.env.VIRUSTOTAL_API_KEY
  delete process.env.PHISHTANK_API_KEY
  delete process.env.GOOGLE_SAFE_BROWSING_API_KEY
})

describe('VirusTotalService.analyzeURL', () => {
  it('without an API key → unavailable, no request', async () => {
    delete process.env.VIRUSTOTAL_API_KEY
    const result = await VirusTotalService.analyzeURL('https://example.com/')
    expect(result.status).toBe('unavailable')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('never sends private/internal URLs', async () => {
    for (const url of ['http://127.0.0.1/', 'http://192.168.0.1/admin', 'http://localhost:3000/', 'http://[::1]/']) {
      const result = await VirusTotalService.analyzeURL(url)
      expect(result.status).toBe('unavailable')
    }
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('uses an existing report first (GET /urls/{base64url-no-padding}) and does not submit', async () => {
    const url = 'https://phish.example.com/login?a=1'
    fetchMock.mockResolvedValueOnce(json(urlReport(
      { malicious: 4, suspicious: 1, harmless: 60, undetected: 25, timeout: 0 },
      { EngineA: { category: 'malicious', result: 'phishing' }, EngineB: { category: 'malicious', result: 'malware site' } },
    )))

    const result = await VirusTotalService.analyzeURL(url)

    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [calledUrl, init] = fetchMock.mock.calls[0]
    expect(calledUrl).toBe(`https://www.virustotal.com/api/v3/urls/${b64url(url)}`)
    expect(String(calledUrl)).not.toMatch(/=$/)
    expect(init.headers['x-apikey']).toBe('test-key')
    expect(init.signal).toBeDefined()

    expect(result.status).toBe('completed')
    expect(result.maliciousCount).toBe(4)
    expect(result.suspiciousCount).toBe(1)
    expect(result.detectionCount).toBe(5)
    expect(result.totalEngines).toBe(90)
    expect(result.isPhishing).toBe(true)
    expect(result.isMalware).toBe(true)
  })

  it('submits only on 404, then parses the /analyses shape (stats/results)', async () => {
    fetchMock
      .mockResolvedValueOnce(json({ error: { code: 'NotFoundError' } }, 404)) // GET /urls/{id}
      .mockResolvedValueOnce(json({ data: { type: 'analysis', id: 'u-abc' } })) // POST /urls
      .mockResolvedValueOnce(json(analysis('completed', { malicious: 2, suspicious: 0, harmless: 70, undetected: 18 }, {
        E1: { category: 'malicious', result: 'phishing' },
      }))) // single poll

    const result = await VirusTotalService.analyzeURL('https://new.example.com/')

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock.mock.calls[1][0]).toBe('https://www.virustotal.com/api/v3/urls')
    expect(fetchMock.mock.calls[1][1].method).toBe('POST')
    expect(fetchMock.mock.calls[2][0]).toBe('https://www.virustotal.com/api/v3/analyses/u-abc')
    for (const call of fetchMock.mock.calls) expect(call[1].signal).toBeDefined()

    expect(result.status).toBe('completed')
    expect(result.maliciousCount).toBe(2)
    expect(result.totalEngines).toBe(90)
    expect(result.isPhishing).toBe(true)
  })

  it('no verdict in time → pending (never clean), at most 3 requests per scan', async () => {
    fetchMock
      .mockResolvedValueOnce(json({}, 404))
      .mockResolvedValueOnce(json({ data: { type: 'analysis', id: 'u-abc' } }))
      .mockImplementation(async () => json(analysis('queued'))) // fresh body per call

    const result = await VirusTotalService.analyzeURL('https://slow.example.com/')

    expect(result.status).toBe('pending')
    expect(result.maliciousCount).toBe(0)
    expect(result.totalEngines).toBe(0)
    expect(fetchMock.mock.calls.length).toBeLessThanOrEqual(3)
  })

  it('skips VirusTotal instead of stalling once the per-minute quota is used', async () => {
    fetchMock.mockImplementation(async () => json(urlReport({ malicious: 0, suspicious: 0, harmless: 80, undetected: 10 })))
    for (let i = 0; i < 4; i++) await VirusTotalService.analyzeURL(`https://q${i}.example.com/`)
    expect(fetchMock).toHaveBeenCalledTimes(4)

    const fifth = await VirusTotalService.analyzeURL('https://q5.example.com/')
    expect(fifth.status).toBe('unavailable')
    expect(fetchMock).toHaveBeenCalledTimes(4)
  })

  it('does not submit when a submission would exceed the quota', async () => {
    fetchMock.mockImplementation(async () => json(urlReport({ malicious: 0, suspicious: 0, harmless: 80, undetected: 10 })))
    for (let i = 0; i < 2; i++) await VirusTotalService.analyzeURL(`https://r${i}.example.com/`)
    fetchMock.mockReset().mockResolvedValueOnce(json({}, 404)) // 3rd request: lookup → not found

    const result = await VirusTotalService.analyzeURL('https://unseen.example.com/')
    expect(result.status).toBe('unavailable')
    expect(fetchMock).toHaveBeenCalledTimes(1) // no POST /urls
  })

  it('known URL with no finished analysis → pending', async () => {
    fetchMock.mockResolvedValueOnce(json(urlReport({ malicious: 0, suspicious: 0, harmless: 0, undetected: 0 })))
    const result = await VirusTotalService.analyzeURL('https://fresh.example.com/')
    expect(result.status).toBe('pending')
  })

  it('API errors → error status, not clean', async () => {
    fetchMock.mockResolvedValueOnce(json({ error: { code: 'QuotaExceededError' } }, 429))
    const result = await VirusTotalService.analyzeURL('https://example.com/')
    expect(result.status).toBe('error')
  })

  it('caches completed verdicts briefly', async () => {
    fetchMock.mockImplementation(async () => json(urlReport({ malicious: 0, suspicious: 0, harmless: 80, undetected: 10 })))
    await VirusTotalService.analyzeURL('https://cached.example.com/')
    const second = await VirusTotalService.analyzeURL('https://cached.example.com/')
    expect(second.status).toBe('completed')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('VirusTotalService.parseResponse', () => {
  it('reads last_analysis_* for URL objects', () => {
    const r = VirusTotalService.parseResponse(urlReport({ malicious: 1, suspicious: 0, harmless: 9, undetected: 0 }))
    expect(r.status).toBe('completed')
    expect(r.maliciousCount).toBe(1)
    expect(r.totalEngines).toBe(10)
  })

  it('reads stats/results for analysis objects', () => {
    const r = VirusTotalService.parseResponse(analysis('completed', { malicious: 3, harmless: 7 }, { E: { category: 'malicious', result: 'malicious' } }))
    expect(r.maliciousCount).toBe(3)
    expect(r.totalEngines).toBe(10)
    expect(r.threatCategories).toContain('malicious')
  })

  it('an unfinished analysis is pending', () => {
    expect(VirusTotalService.parseResponse(analysis('in-progress')).status).toBe('pending')
  })
})

describe('PhishTankService', () => {
  it('without a key → silently unchecked', async () => {
    const result = await PhishTankService.checkURL('https://example.com/')
    expect(result).toMatchObject({ isPhishing: false, checked: false })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('only verified + valid entries count as phishing', async () => {
    process.env.PHISHTANK_API_KEY = 'pt-key'

    fetchMock.mockResolvedValueOnce(json({ results: { in_database: true, verified: false, valid: false } }))
    const unverified = await PhishTankService.checkURL('https://a.example.com/')
    expect(unverified.isPhishing).toBe(false)
    expect(unverified.inDatabase).toBe(true)

    fetchMock.mockResolvedValueOnce(json({ results: { in_database: true, verified: true, valid: false } }))
    expect((await PhishTankService.checkURL('https://b.example.com/')).isPhishing).toBe(false)

    fetchMock.mockResolvedValueOnce(json({ results: { in_database: true, verified: true, valid: true, phish_id: 123 } }))
    const verified = await PhishTankService.checkURL('https://c.example.com/')
    expect(verified.isPhishing).toBe(true)
    expect(verified.checked).toBe(true)
    expect(fetchMock.mock.calls[0][1].signal).toBeDefined()
  })
})

describe('GoogleSafeBrowsingService', () => {
  it('without a key → unchecked, no request', async () => {
    const result = await GoogleSafeBrowsingService.checkURL('https://example.com/')
    expect(result).toMatchObject({ isThreat: false, checked: false })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('reports matches, uses a timeout, and skips private URLs', async () => {
    process.env.GOOGLE_SAFE_BROWSING_API_KEY = 'gsb-key'
    fetchMock.mockResolvedValueOnce(json({ matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: 'x' } }] }))

    const hit = await GoogleSafeBrowsingService.checkURL('https://phish.example.com/')
    expect(hit).toMatchObject({ isThreat: true, checked: true, threatType: 'SOCIAL_ENGINEERING' })
    expect(fetchMock.mock.calls[0][1].signal).toBeDefined()

    const internal = await GoogleSafeBrowsingService.checkURL('http://10.0.0.1/')
    expect(internal.checked).toBe(false)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
