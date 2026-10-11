/**
 * API Guards
 *
 * Small helpers every API route uses:
 * - requireAdmin: protects routes that change global state
 * - enforceRateLimit: per-session AND per-IP limits (dropping the cookie doesn't reset them)
 * - parseJson: zod validation with a consistent 400 response
 */

import { timingSafeEqual } from 'crypto'
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { checkRateLimit, getClientIP } from '@/lib/rateLimit'

/**
 * Returns a 401/404 response unless the request carries the admin token
 * (header `x-admin-token` matching ADMIN_API_TOKEN). If ADMIN_API_TOKEN is not
 * configured, admin routes are disabled entirely.
 */
export function requireAdmin(request: NextRequest | Request): NextResponse | null {
  const configured = process.env.ADMIN_API_TOKEN
  if (!configured) {
    return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 })
  }

  const given = Buffer.from(request.headers.get('x-admin-token') ?? '')
  const expected = Buffer.from(configured)
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 })
  }
  return null
}

export interface LimitOptions {
  /** Requests allowed per window for one session */
  perSession: number
  /** Requests allowed per window for one IP (covers cookie-less abuse) */
  perIp: number
  windowSeconds: number
}

export const LIMITS = {
  analyze: { perSession: 30, perIp: 120, windowSeconds: 600 },
  chat: { perSession: 20, perIp: 60, windowSeconds: 600 },
  threatIntel: { perSession: 30, perIp: 120, windowSeconds: 600 },
  read: { perSession: 300, perIp: 1000, windowSeconds: 600 },
} satisfies Record<string, LimitOptions>

/** Returns a 429 response if either the session or the IP is over its limit. */
export async function enforceRateLimit(
  request: NextRequest | Request,
  userId: string,
  action: string,
  options: LimitOptions
): Promise<NextResponse | null> {
  const ip = getClientIP(request as NextRequest)
  const [bySession, byIp] = await Promise.all([
    checkRateLimit(`session:${userId}`, action, options.perSession, options.windowSeconds),
    checkRateLimit(`ip:${ip}`, action, options.perIp, options.windowSeconds),
  ])

  const blocked = !bySession.success ? bySession : !byIp.success ? byIp : null
  if (!blocked) return null

  const retryAfter = Math.max(1, Math.ceil((blocked.resetAt.getTime() - Date.now()) / 1000))
  return NextResponse.json(
    { success: false, error: 'Too many requests. Please wait and try again.' },
    { status: 429, headers: { 'Retry-After': String(retryAfter) } }
  )
}

/** Parse and validate a JSON body. Returns either the data or a ready 400 response. */
export async function parseJson<T extends z.ZodTypeAny>(
  request: NextRequest | Request,
  schema: T
): Promise<{ data: z.infer<T>; error?: never } | { data?: never; error: NextResponse }> {
  let body: unknown
  try {
    body = await request.json()
  } catch {
    return { error: NextResponse.json({ success: false, error: 'Invalid JSON body' }, { status: 400 }) }
  }

  const parsed = schema.safeParse(body)
  if (!parsed.success) {
    const message = parsed.error.issues.map(i => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ')
    return { error: NextResponse.json({ success: false, error: message }, { status: 400 }) }
  }
  return { data: parsed.data }
}
