/** @jest-environment node */

/**
 * Health Check API Tests — /api/health
 */

const findMany = jest.fn()

jest.mock('@/db', () => ({
  db: {
    query: {
      modelConfigs: {
        findMany: (...args: unknown[]) => findMany(...args),
      },
    },
  },
}))

import { GET } from '@/app/api/health/route'

describe('/api/health', () => {
  beforeEach(() => {
    findMany.mockReset()
    findMany.mockResolvedValue([
      { modelId: 'url_analyzer_v1', state: 'ACTIVE' },
      { modelId: 'email_scanner_v2', state: 'ACTIVE' },
    ])
  })

  it('returns ok when the database responds', async () => {
    const response = await GET()
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.success).toBe(true)
    expect(data.status).toBe('ok')
    expect(data.database).toBe('up')
  })

  it('includes available models', async () => {
    const data = await (await GET()).json()

    expect(data.models).toEqual(['url_analyzer_v1', 'email_scanner_v2'])
    expect(data.models_available).toBe(2)
  })

  it('includes a valid ISO timestamp', async () => {
    const data = await (await GET()).json()
    expect(new Date(data.timestamp).toISOString()).toBe(data.timestamp)
  })

  it('returns JSON', async () => {
    const response = await GET()
    expect(response.headers.get('content-type')).toContain('application/json')
  })

  it('reports degraded (scanner still usable) and does not leak the database error', async () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {})
    findMany.mockRejectedValue(new Error('password authentication failed for user "postgres" at db.internal:5432'))

    const response = await GET()
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data.status).toBe('degraded')
    expect(data.database).toBe('down')
    expect(JSON.stringify(data)).not.toMatch(/password|db\.internal|postgres/)
    spy.mockRestore()
  })
})
