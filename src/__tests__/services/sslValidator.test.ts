/** @jest-environment node */
/**
 * SSLValidator tests — offline: TLS, DNS and the DB are mocked.
 * (next/jest rewrites builtin imports to `node:` ids, so those are what we mock.)
 */

import { EventEmitter } from 'events'

const mockConnect = jest.fn()
const mockLookup = jest.fn()
const mockSelectRows = jest.fn()
const mockInsertValues = jest.fn()

function mockTlsModule() {
  const api = { connect: (...args: unknown[]) => mockConnect(...args), checkServerIdentity: jest.fn() }
  return { __esModule: true, default: api, ...api }
}
// Mock both ids: the transform rewrites some builtins (dns/promises) to `node:` but not others
jest.mock('tls', mockTlsModule)
jest.mock('node:tls', mockTlsModule)
jest.mock('node:dns/promises', () => ({ lookup: (...args: unknown[]) => mockLookup(...args) }))
jest.mock('dns/promises', () => ({ lookup: (...args: unknown[]) => mockLookup(...args) }))
jest.mock('@/db', () => {
  const chain: any = {
    from: () => chain,
    where: () => chain,
    orderBy: () => chain,
    limit: () => Promise.resolve(mockSelectRows()),
  }
  return {
    db: {
      select: () => chain,
      insert: () => ({
        values: (v: unknown) => {
          mockInsertValues(v)
          return { onConflictDoUpdate: () => Promise.resolve() }
        },
      }),
    },
  }
})

import { SSLValidator } from '@/services/detection/sslValidator'
import { BlockedHostError } from '@/lib/netGuard'

const DAY = 24 * 60 * 60 * 1000

interface FakeTls {
  authorized?: boolean
  authorizationError?: string
  cert?: Record<string, unknown>
  fail?: boolean
}

function makeCert(overrides: Record<string, unknown> = {}) {
  return {
    subject: { CN: 'www.example.com' },
    issuer: { C: 'US', O: 'Test CA', CN: 'Test CA R1' },
    valid_from: new Date(Date.now() - 60 * DAY).toUTCString(),
    valid_to: new Date(Date.now() + 60 * DAY).toUTCString(),
    serialNumber: '01AB',
    fingerprint256: 'AA:BB:CC',
    subjectaltname: 'DNS:www.example.com, DNS:example.com',
    modulus: 'C0FFEE',
    bits: 2048,
    ...overrides,
  }
}

function fakeTls({ authorized = true, authorizationError, cert = makeCert(), fail = false }: FakeTls = {}) {
  mockConnect.mockImplementation((_opts: unknown, onSecure: () => void) => {
    const socket: any = new EventEmitter()
    socket.authorized = authorized
    socket.authorizationError = authorizationError
    socket.getPeerCertificate = () => cert
    socket.setTimeout = jest.fn()
    socket.destroy = jest.fn()
    socket.end = jest.fn()
    setImmediate(() => (fail ? socket.emit('error', new Error('ECONNRESET')) : onSecure()))
    return socket
  })
}

beforeEach(() => {
  jest.clearAllMocks()
  mockSelectRows.mockReturnValue([])
  mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }])
  fakeTls()
})

describe('SSRF protection', () => {
  it.each(['localhost', '127.0.0.1', '169.254.169.254', '[::1]', 'http://10.0.0.8/'])(
    '%s → BlockedHostError without connecting',
    async (target) => {
      await expect(SSLValidator.analyze(target)).rejects.toBeInstanceOf(BlockedHostError)
      expect(mockConnect).not.toHaveBeenCalled()
    }
  )

  it('blocks hostnames that resolve to private addresses', async () => {
    mockLookup.mockResolvedValue([{ address: '192.168.1.20', family: 4 }])
    await expect(SSLValidator.analyze('intranet.example.com')).rejects.toBeInstanceOf(BlockedHostError)
    expect(mockConnect).not.toHaveBeenCalled()
  })

  it('verifyCertificate rethrows BlockedHostError', async () => {
    await expect(SSLValidator.verifyCertificate('https://127.0.0.1/')).rejects.toBeInstanceOf(BlockedHostError)
  })

  it('connects to the vetted IP with the hostname as SNI', async () => {
    await SSLValidator.analyze('https://www.example.com/login')
    const opts = mockConnect.mock.calls[0][0]
    expect(opts.host).toBe('93.184.216.34')
    expect(opts.servername).toBe('www.example.com')
    expect(opts.rejectUnauthorized).toBe(false)
  })
})

describe('certificate analysis', () => {
  it('trusted, matching RSA-2048 certificate → valid, no risk', async () => {
    const result = await SSLValidator.analyze('www.example.com')
    expect(result.hostname).toBe('www.example.com')
    expect(result.isValid).toBe(true)
    expect(result.certificateAvailable).toBe(true)
    expect(result.riskScore).toBe(0)
    expect(result.trustAnalysis.chainValid).toBe(true)
    expect(result.trustAnalysis.hostnameMatches).toBe(true)
  })

  it('analyzes the actual hostname, not just the registrable domain', async () => {
    fakeTls({ cert: makeCert({ subjectaltname: 'DNS:example.com' }) })
    const result = await SSLValidator.analyze('login.example.com')
    expect(result.trustAnalysis.hostnameMatches).toBe(false)
    expect(result.indicators.some(i => i.includes('not issued for login.example.com'))).toBe(true)
  })

  it('wildcard SAN matches exactly one label', async () => {
    fakeTls({ cert: makeCert({ subjectaltname: 'DNS:*.example.com' }) })
    expect((await SSLValidator.analyze('a.example.com')).trustAnalysis.hostnameMatches).toBe(true)
    expect((await SSLValidator.analyze('a.b.example.com')).trustAnalysis.hostnameMatches).toBe(false)
  })

  it('chain validity comes from socket.authorized / authorizationError', async () => {
    fakeTls({ authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' })
    const result = await SSLValidator.analyze('www.example.com')
    expect(result.trustAnalysis.chainValid).toBe(false)
    expect(result.trustAnalysis.isSelfSigned).toBe(true)
    expect(result.isValid).toBe(false)
    expect(result.riskScore).toBeGreaterThanOrEqual(40)
  })

  it('untrusted chain (unknown issuer) is reported', async () => {
    fakeTls({ authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' })
    const result = await SSLValidator.analyze('www.example.com')
    expect(result.indicators.some(i => i.includes('chain is not trusted'))).toBe(true)
  })

  it('expired certificate is flagged', async () => {
    fakeTls({
      authorized: false,
      authorizationError: 'CERT_HAS_EXPIRED',
      cert: makeCert({ valid_from: new Date(Date.now() - 400 * DAY).toUTCString(), valid_to: new Date(Date.now() - 5 * DAY).toUTCString() }),
    })
    const result = await SSLValidator.analyze('www.example.com')
    expect(result.trustAnalysis.isExpired).toBe(true)
    expect(result.riskScore).toBeGreaterThanOrEqual(50)
  })

  it('EC P-256 keys are fine; RSA-1024 is weak', async () => {
    fakeTls({ cert: makeCert({ modulus: undefined, asn1Curve: 'prime256v1', nistCurve: 'P-256', bits: 256 }) })
    const ec = await SSLValidator.analyze('www.example.com')
    expect(ec.certificateDetails?.keyType).toBe('EC')
    expect(ec.trustAnalysis.hasWeakKey).toBe(false)
    expect(ec.riskScore).toBe(0)

    fakeTls({ cert: makeCert({ bits: 1024 }) })
    const rsa = await SSLValidator.analyze('www.example.com')
    expect(rsa.trustAnalysis.hasWeakKey).toBe(true)
    expect(rsa.indicators.some(i => i.includes('Weak RSA key size: 1024'))).toBe(true)
  })

  it('makes no revocation or EV claims', async () => {
    const result = await SSLValidator.analyze('www.example.com')
    expect(result.trustAnalysis.revocationStatus).toBe('not_checked')
    expect(result.trustAnalysis).not.toHaveProperty('isRevoked')
    expect(result.trustAnalysis).not.toHaveProperty('isEV')
    expect(result.indicators.some(i => /revoked/i.test(i))).toBe(false)
  })

  it('missing signature algorithm is skipped, not guessed', async () => {
    const result = await SSLValidator.analyze('www.example.com')
    expect(result.certificateDetails?.algorithm).toBeUndefined()
    expect(result.trustAnalysis.hasWeakSignature).toBe(false)
  })

  it('connection failure → no data, no risk', async () => {
    fakeTls({ fail: true })
    const result = await SSLValidator.analyze('www.example.com')
    expect(result.certificateAvailable).toBe(false)
    expect(result.riskScore).toBe(0)
  })

  it('DNS failure (not a private address) → no data instead of an exception', async () => {
    mockLookup.mockRejectedValue(Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' }))
    const result = await SSLValidator.analyze('nope.example.com')
    expect(result.certificateAvailable).toBe(false)
    expect(mockConnect).not.toHaveBeenCalled()
  })
})

describe('cache consistency', () => {
  it.each([
    ['clean', {}],
    ['self-signed', { authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }],
    ['hostname mismatch + weak key', { authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID', cert: makeCert({ subjectaltname: 'DNS:other.com', bits: 1024 }) }],
    ['untrusted chain', { authorized: false, authorizationError: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' }],
  ] as Array<[string, FakeTls]>)('cached result scores the same as a fresh scan (%s)', async (_name, tlsSetup) => {
    fakeTls(tlsSetup)
    const fresh = await SSLValidator.analyze('www.example.com')
    expect(fresh.fromCache).toBe(false)

    const stored = mockInsertValues.mock.calls[0][0]
    mockSelectRows.mockReturnValue([{ ...stored, lastChecked: new Date() }])
    mockConnect.mockClear()

    const cached = await SSLValidator.analyze('www.example.com')
    expect(cached.fromCache).toBe(true)
    expect(mockConnect).not.toHaveBeenCalled()
    expect(cached.riskScore).toBe(fresh.riskScore)
    expect(cached.isValid).toBe(fresh.isValid)
    expect(cached.trustAnalysis.trustScore).toBe(fresh.trustAnalysis.trustScore)
  })
})
