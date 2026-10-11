/** @jest-environment node */
/**
 * DomainService tests (domain layer used by MasterDetector) — offline:
 * fetch (RDAP), DNS and the DB are mocked.
 */

const mockFindFirst = jest.fn()
const mockInsertValues = jest.fn()
const mockDns = {
  resolve4: jest.fn(),
  resolveMx: jest.fn(),
  resolveNs: jest.fn(),
  resolveTxt: jest.fn(),
}

function mockDnsModule() {
  // Lazy wrappers: this factory can run before `mockDns` is initialised
  const api = {
    lookup: jest.fn(),
    resolve4: (...a: unknown[]) => mockDns.resolve4(...a),
    resolveMx: (...a: unknown[]) => mockDns.resolveMx(...a),
    resolveNs: (...a: unknown[]) => mockDns.resolveNs(...a),
    resolveTxt: (...a: unknown[]) => mockDns.resolveTxt(...a),
  }
  return { __esModule: true, default: api, ...api }
}
jest.mock('dns/promises', mockDnsModule)
jest.mock('node:dns/promises', mockDnsModule)
jest.mock('@/db', () => {
  const findFirst = (...a: unknown[]) => mockFindFirst(...a)
  return {
    db: {
      query: {
        blockedDomains: { findFirst },
        threatIntelligence: { findFirst },
        domainIntelligence: { findFirst },
        trustedDomains: { findFirst },
      },
      insert: () => ({
        values: (v: unknown) => {
          mockInsertValues(v)
          return { onConflictDoUpdate: () => Promise.resolve() }
        },
      }),
    },
  }
})

import { DomainService } from '@/services/detection/domainService'

const DAY = 24 * 60 * 60 * 1000
let fetchMock: jest.SpyInstance

const rdap = (registeredDaysAgo: number) => ({
  objectClassName: 'domain',
  ldhName: 'example.com',
  events: [
    { eventAction: 'registration', eventDate: new Date(Date.now() - registeredDaysAgo * DAY).toISOString() },
    { eventAction: 'expiration', eventDate: new Date(Date.now() + 300 * DAY).toISOString() },
  ],
  entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]] }],
})

beforeEach(() => {
  jest.clearAllMocks()
  mockFindFirst.mockResolvedValue(undefined)
  mockDns.resolve4.mockResolvedValue(['93.184.216.34'])
  mockDns.resolveMx.mockResolvedValue([{ priority: 10, exchange: 'mx.example.com' }])
  mockDns.resolveNs.mockResolvedValue(['ns1.example.com'])
  mockDns.resolveTxt.mockResolvedValue([['v=spf1 -all']])
  fetchMock = jest.spyOn(global, 'fetch')
  jest.spyOn(console, 'error').mockImplementation(() => {})
  // Pre-seed the IANA RDAP bootstrap so each test makes a single RDAP request
  ;(DomainService as unknown as { rdapBootstrap?: unknown }).rdapBootstrap = {
    servers: new Map([['com', 'https://rdap.verisign.com/com/v1/']]),
    fetchedAt: Date.now(),
  }
})

afterEach(() => jest.restoreAllMocks())

describe('DomainService.analyze (RDAP domain age)', () => {
  it('queries the TLD registry (IANA bootstrap) for the registrable domain with a timeout', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(rdap(4000)), { status: 200 }))
    const result = await DomainService.analyze('login.www.example.com')
    expect(fetchMock.mock.calls[0][0]).toBe('https://rdap.verisign.com/com/v1/domain/example.com')
    expect(fetchMock.mock.calls[0][1].signal).toBeDefined()
    expect(result.domainAgeStatus).toBe('known')
    expect(result.whoisData?.registrar).toBe('Example Registrar, Inc.')
    expect(result.whoisData?.domainAge).toBeGreaterThanOrEqual(3999)
    expect(result.riskScore).toBe(0)
  })

  it('loads the IANA bootstrap when not cached, and falls back to rdap.org for unknown TLDs', async () => {
    ;(DomainService as unknown as { rdapBootstrap?: unknown }).rdapBootstrap = undefined
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ services: [[['com', 'net'], ['https://rdap.verisign.com/com/v1/']]] }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(rdap(4000)), { status: 200 }))
    await DomainService.analyze('example.com')
    expect(fetchMock.mock.calls[0][0]).toBe('https://data.iana.org/rdap/dns.json')
    expect(fetchMock.mock.calls[1][0]).toBe('https://rdap.verisign.com/com/v1/domain/example.com')

    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(rdap(4000)), { status: 200 }))
    await DomainService.analyze('shop.example')
    expect(fetchMock.mock.calls[2][0]).toBe('https://rdap.org/domain/shop.example')
    expect(fetchMock.mock.calls[2][1].headers['User-Agent']).toBeDefined()
  })

  it('newly registered (<30 days) is a strong signal', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(rdap(5)), { status: 200 }))
    const result = await DomainService.analyze('new-shop.example')
    expect(result.riskScore).toBeGreaterThanOrEqual(40)
    expect(result.indicators.some(i => i.includes('newly registered'))).toBe(true)
  })

  it('<180 days is a moderate signal', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify(rdap(90)), { status: 200 }))
    const result = await DomainService.analyze('example.com')
    expect(result.riskScore).toBeGreaterThan(0)
    expect(result.riskScore).toBeLessThan(40)
  })

  it('RDAP failure → age unknown, no risk, no fake data', async () => {
    fetchMock.mockRejectedValueOnce(new Error('timeout'))
    const result = await DomainService.analyze('example.com')
    expect(result.domainAgeStatus).toBe('unknown')
    expect(result.whoisData).toBeUndefined()
    expect(result.riskScore).toBe(0)
  })

  it('does not send internal names to RDAP/DNS', async () => {
    const result = await DomainService.analyze('localhost')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(mockDns.resolve4).not.toHaveBeenCalled()
    expect(result.hasData).toBe(false)
  })

  it('cached result keeps the no-MX indicator together with its points', async () => {
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 404 }))
    mockDns.resolveMx.mockRejectedValue(Object.assign(new Error('ENODATA'), { code: 'ENODATA' }))

    const fresh = await DomainService.analyze('example.com')
    expect(fresh.indicators.some(i => i.includes('No MX'))).toBe(true)

    const stored = mockInsertValues.mock.calls[0][0]
    mockFindFirst.mockImplementation(async () => ({ ...stored, cacheExpiry: new Date(Date.now() + 60000) }))

    const cached = await DomainService.analyze('example.com')
    expect(cached.riskScore).toBe(fresh.riskScore)
    expect(cached.indicators).toEqual(fresh.indicators)
  })
})
