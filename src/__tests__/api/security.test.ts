/** @jest-environment node */

/**
 * API authorization / validation tests.
 *
 * drizzle's `eq`/`and` are replaced with plain objects so the fake database can
 * evaluate WHERE clauses and we can assert on exactly which user a query is scoped to.
 */

import { NextRequest } from 'next/server'

type Cond =
  | { op: 'eq'; col: string; val: unknown }
  | { op: 'and'; conds: Cond[] }

jest.mock('drizzle-orm', () => {
  const actual = jest.requireActual('drizzle-orm')
  return {
    ...actual,
    eq: (col: { name: string }, val: unknown) => ({ op: 'eq', col: col.name, val }),
    and: (...conds: Cond[]) => ({ op: 'and', conds }),
    desc: (col: { name: string }) => ({ op: 'desc', col: col.name }),
  }
})

const SESSION_USER = 'anon_session-user'
const OTHER_USER = 'anon_victim'

jest.mock('@/lib/session', () => ({
  getSessionUserId: jest.fn(async () => SESSION_USER),
  ensureUser: jest.fn(async () => undefined),
}))

const now = new Date('2026-10-01T10:00:00Z')
const rows = [
  { id: '11111111-1111-4111-8111-111111111111', userId: SESSION_USER, type: 'URL', target: 'https://mine.example', confidence: 80, threatLevel: 'SAFE', riskScore: 5, indicators: [], recommendations: [], timestamp: now, modelVersion: '1.0.0', metadata: null },
  { id: '22222222-2222-4222-8222-222222222222', userId: OTHER_USER, type: 'URL', target: 'https://victim.example', confidence: 80, threatLevel: 'HIGH', riskScore: 70, indicators: [], recommendations: [], timestamp: now, modelVersion: '1.0.0', metadata: { secret: true } },
]

function matches(row: Record<string, unknown>, cond?: Cond): boolean {
  if (!cond) return true
  if (cond.op === 'and') return cond.conds.every(c => matches(row, c))
  return row[cond.col] === cond.val
}

const findMany = jest.fn(async ({ where }: { where?: Cond }) => rows.filter(r => matches(r, where)))
const findFirst = jest.fn(async ({ where }: { where?: Cond }) => rows.find(r => matches(r, where)))
const deleteWhere = jest.fn((where: Cond) => ({
  returning: async () => rows.filter(r => matches(r, where)).map(r => ({ id: r.id })),
}))

jest.mock('@/db', () => ({
  db: {
    query: {
      scanResults: {
        findMany: (args: { where?: Cond }) => findMany(args),
        findFirst: (args: { where?: Cond }) => findFirst(args),
      },
    },
    delete: () => ({ where: (w: Cond) => deleteWhere(w) }),
  },
}))

const trustDomain = jest.fn()
const blockDomain = jest.fn()
jest.mock('@/services/detection/domainService', () => ({
  DomainService: {
    trustDomain: (...a: unknown[]) => trustDomain(...a),
    blockDomain: (...a: unknown[]) => blockDomain(...a),
    analyze: jest.fn(),
    isTrustedDomain: jest.fn(async () => false),
    isBlockedDomain: jest.fn(async () => false),
  },
}))

jest.mock('groq-sdk', () => jest.fn())

import * as scansRoute from '@/app/api/scans/route'
import * as scanIdRoute from '@/app/api/scans/[scanId]/route'
import * as domainRoute from '@/app/api/threat-intel/domain/route'
import * as chatRoute from '@/app/api/chat/route'

const params = (scanId: string) => ({ params: Promise.resolve({ scanId }) })

beforeEach(() => {
  jest.clearAllMocks()
})

describe('GET /api/scans', () => {
  it('returns only the session user’s scans and ignores ?user_id', async () => {
    const res = await scansRoute.GET(new NextRequest(`http://localhost/api/scans?user_id=${OTHER_USER}`))
    const data = await res.json()

    expect(res.status).toBe(200)
    expect(findMany).toHaveBeenCalledTimes(1)
    expect(findMany.mock.calls[0][0].where).toEqual({ op: 'eq', col: 'userId', val: SESSION_USER })
    expect(data.scans).toHaveLength(1)
    expect(data.scans[0].target).toBe('https://mine.example')
  })

  it('caps ?limit at 100', async () => {
    await scansRoute.GET(new NextRequest('http://localhost/api/scans?limit=5000'))
    expect((findMany.mock.calls[0][0] as unknown as { limit: number }).limit).toBe(100)
  })
})

describe('/api/scans/[scanId]', () => {
  it('returns the session user’s own scan', async () => {
    const res = await scanIdRoute.GET(new NextRequest('http://localhost/x'), params(rows[0].id))
    expect(res.status).toBe(200)
    expect((await res.json()).scan.id).toBe(rows[0].id)
  })

  it('returns 404 for another user’s scan', async () => {
    const res = await scanIdRoute.GET(new NextRequest('http://localhost/x'), params(rows[1].id))
    const data = await res.json()
    expect(res.status).toBe(404)
    expect(JSON.stringify(data)).not.toContain('victim')
  })

  it('does not delete another user’s scan', async () => {
    const res = await scanIdRoute.DELETE(new NextRequest('http://localhost/x', { method: 'DELETE' }), params(rows[1].id))
    expect(res.status).toBe(404)
    expect(deleteWhere.mock.calls[0][0]).toEqual({
      op: 'and',
      conds: [
        { op: 'eq', col: 'id', val: rows[1].id },
        { op: 'eq', col: 'userId', val: SESSION_USER },
      ],
    })
  })

  it('rejects a non-UUID id with 400', async () => {
    const res = await scanIdRoute.GET(new NextRequest('http://localhost/x'), params('1 OR 1=1'))
    expect(res.status).toBe(400)
    expect(findFirst).not.toHaveBeenCalled()
  })
})

describe('PUT /api/threat-intel/domain (admin only)', () => {
  const put = (headers: Record<string, string> = {}) =>
    domainRoute.PUT(
      new NextRequest('http://localhost/api/threat-intel/domain', {
        method: 'PUT',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify({ domain: 'evil.example', action: 'trust' }),
      })
    )

  afterEach(() => {
    delete process.env.ADMIN_API_TOKEN
  })

  it('is disabled (404) when ADMIN_API_TOKEN is not configured', async () => {
    delete process.env.ADMIN_API_TOKEN
    const res = await put()
    expect(res.status).toBe(404)
    expect(trustDomain).not.toHaveBeenCalled()
  })

  it('returns 401 without the admin token', async () => {
    process.env.ADMIN_API_TOKEN = 'a'.repeat(40)
    const res = await put({ 'x-admin-token': 'wrong' })
    expect(res.status).toBe(401)
    expect(trustDomain).not.toHaveBeenCalled()
  })

  it('accepts the correct admin token', async () => {
    process.env.ADMIN_API_TOKEN = 'a'.repeat(40)
    const res = await put({ 'x-admin-token': 'a'.repeat(40) })
    expect(res.status).toBe(200)
    expect(trustDomain).toHaveBeenCalledWith('evil.example', undefined, 'admin')
  })
})

describe('POST /api/chat', () => {
  const chat = (body: unknown) =>
    chatRoute.POST(
      new NextRequest('http://localhost/api/chat', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
    )

  it('rejects an oversized message with 400', async () => {
    const res = await chat({ message: 'x'.repeat(4001) })
    expect(res.status).toBe(400)
    expect((await res.json()).success).toBe(false)
  })

  it('rejects more than 20 context messages with 400', async () => {
    const context = Array.from({ length: 21 }, () => ({ role: 'user', content: 'hi' }))
    const res = await chat({ message: 'hello', context })
    expect(res.status).toBe(400)
  })

  it('answers with local safety tips when no AI key is configured', async () => {
    const saved = process.env.GROQ_API_KEY
    delete process.env.GROQ_API_KEY
    const res = await chat({ message: 'someone asked for my OTP' })
    const data = await res.json()
    expect(res.status).toBe(200)
    expect(data.fallback).toBe(true)
    expect(data.response).toMatch(/never share/i)
    if (saved !== undefined) process.env.GROQ_API_KEY = saved
  })
})
