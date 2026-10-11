/**
 * Network Guard (SSRF protection)
 *
 * Any time the server opens a connection to a host the user supplied
 * (TLS certificate checks, redirect following, etc.) it must go through
 * resolvePublicHost first. It resolves DNS once and refuses loopback,
 * private, link-local, CGNAT, multicast and other non-public addresses.
 * Connect to the returned IP (with the hostname as SNI) so DNS can't be
 * swapped between the check and the connection.
 */

import { lookup } from 'dns/promises'
import { isIP } from 'net'

export class BlockedHostError extends Error {
  constructor(host: string, reason: string) {
    super(`Refusing to connect to ${host}: ${reason}`)
    this.name = 'BlockedHostError'
  }
}

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0
}

const BLOCKED_V4: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local, cloud metadata
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
]

/** True for any address the server should never connect to on a user's behalf. */
export function isNonPublicIp(ip: string): boolean {
  const version = isIP(ip)

  if (version === 4) {
    const value = ipv4ToInt(ip)
    return BLOCKED_V4.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
      return (value & mask) === (ipv4ToInt(base) & mask)
    })
  }

  if (version === 6) {
    const lower = ip.toLowerCase()
    // IPv4-mapped (::ffff:a.b.c.d) — check the embedded IPv4 address
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (mapped) return isNonPublicIp(mapped[1])
    return (
      lower === '::' ||
      lower === '::1' ||
      lower.startsWith('fc') || lower.startsWith('fd') || // unique local
      /^fe[89ab]/.test(lower) || // link-local
      lower.startsWith('ff') // multicast
    )
  }

  return true // not an IP at all
}

/**
 * Resolve a hostname and make sure it points to a public address.
 * Returns the IP to connect to. Throws BlockedHostError otherwise.
 */
export async function resolvePublicHost(host: string): Promise<{ address: string; family: number }> {
  const bare = host.replace(/^\[|\]$/g, '')

  if (isIP(bare)) {
    if (isNonPublicIp(bare)) throw new BlockedHostError(host, 'private or reserved address')
    return { address: bare, family: isIP(bare) }
  }

  if (!/^[a-z0-9.-]+$/i.test(bare) || !bare.includes('.')) {
    throw new BlockedHostError(host, 'not a public hostname')
  }

  const records = await lookup(bare, { all: true })
  if (records.length === 0) throw new BlockedHostError(host, 'does not resolve')

  const bad = records.find(r => isNonPublicIp(r.address))
  if (bad) throw new BlockedHostError(host, `resolves to non-public address ${bad.address}`)

  return records[0]
}
