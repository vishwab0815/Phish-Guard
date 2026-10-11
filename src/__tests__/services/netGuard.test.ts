/** @jest-environment node */
/**
 * netGuard (SSRF protection) tests — offline: DNS is mocked.
 */

// next/jest's SWC transform rewrites builtin imports to the `node:` form, so mock that id
jest.mock('node:dns/promises', () => ({ lookup: jest.fn() }))

import { lookup } from 'dns/promises'
import { isNonPublicIp, resolvePublicHost, BlockedHostError } from '@/lib/netGuard'

const mockLookup = lookup as unknown as jest.Mock

describe('isNonPublicIp', () => {
  it.each([
    '127.0.0.1',
    '10.1.2.3',
    '169.254.169.254',
    '100.64.1.1',
    '192.168.0.10',
    '172.16.5.4',
    '0.0.0.0',
    '::1',
    'fd00::1',
    'fe80::1',
    '::ffff:127.0.0.1',
  ])('%s → non-public', (ip) => {
    expect(isNonPublicIp(ip)).toBe(true)
  })

  it.each(['8.8.8.8', '1.1.1.1', '2606:4700::1111', '172.32.0.1'])('%s → public', (ip) => {
    expect(isNonPublicIp(ip)).toBe(false)
  })

  it('treats non-IP strings as non-public', () => {
    expect(isNonPublicIp('example.com')).toBe(true)
  })
})

describe('resolvePublicHost', () => {
  beforeEach(() => mockLookup.mockReset())

  it('returns a public IP literal without DNS', async () => {
    await expect(resolvePublicHost('8.8.8.8')).resolves.toEqual({ address: '8.8.8.8', family: 4 })
    expect(mockLookup).not.toHaveBeenCalled()
  })

  it('blocks private IP literals (incl. bracketed IPv6)', async () => {
    await expect(resolvePublicHost('127.0.0.1')).rejects.toBeInstanceOf(BlockedHostError)
    await expect(resolvePublicHost('[::1]')).rejects.toBeInstanceOf(BlockedHostError)
  })

  it('blocks single-label hosts like localhost', async () => {
    await expect(resolvePublicHost('localhost')).rejects.toBeInstanceOf(BlockedHostError)
  })

  it('blocks hostnames that resolve to a private address', async () => {
    mockLookup.mockResolvedValue([{ address: '10.0.0.5', family: 4 }])
    await expect(resolvePublicHost('internal.example.com')).rejects.toBeInstanceOf(BlockedHostError)
  })

  it('blocks when ANY resolved record is private', async () => {
    mockLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ])
    await expect(resolvePublicHost('rebind.example.com')).rejects.toBeInstanceOf(BlockedHostError)
  })

  it('returns the first public record', async () => {
    mockLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }])
    await expect(resolvePublicHost('example.com')).resolves.toEqual({ address: '93.184.216.34', family: 4 })
  })
})
