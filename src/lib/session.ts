/**
 * Anonymous Session
 *
 * Every browser gets a server-issued, HMAC-signed session cookie. The user id
 * inside it is the ONLY identity API routes trust — never a `user_id` sent by
 * the client. This gives each visitor private scan history and settings
 * without requiring sign-up.
 */

import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'crypto'
import { cookies } from 'next/headers'
import { db } from '@/db'
import { users } from '@/db/schema'

const COOKIE_NAME = 'pg_sid'
const MAX_AGE_SECONDS = 60 * 60 * 24 * 365

let devSecret: string | undefined

function getSecret(): string {
  const secret = process.env.SESSION_SECRET
  if (secret && secret.length >= 32) return secret

  if (process.env.NODE_ENV === 'production') {
    throw new Error('SESSION_SECRET must be set (at least 32 characters) in production')
  }

  // Development only: a per-process secret. Sessions reset when the server restarts.
  if (!devSecret) {
    devSecret = randomBytes(32).toString('hex')
    console.warn('[session] SESSION_SECRET not set — using a temporary development secret')
  }
  return devSecret
}

function sign(userId: string): string {
  return createHmac('sha256', getSecret()).update(userId).digest('base64url')
}

/** Returns the user id if the cookie value carries a valid signature. */
export function verifySessionValue(value: string | undefined): string | null {
  if (!value) return null
  const dot = value.lastIndexOf('.')
  if (dot <= 0) return null

  const userId = value.slice(0, dot)
  const given = Buffer.from(value.slice(dot + 1))
  const expected = Buffer.from(sign(userId))
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null

  return userId
}

/**
 * Get the current visitor's user id, issuing a new session cookie if needed.
 * Must be called from a Route Handler or Server Action (cookies are writable there).
 */
export async function getSessionUserId(): Promise<string> {
  const store = await cookies()
  const existing = verifySessionValue(store.get(COOKIE_NAME)?.value)
  if (existing) return existing

  const userId = `anon_${randomUUID()}`
  store.set(COOKIE_NAME, `${userId}.${sign(userId)}`, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: MAX_AGE_SECONDS,
  })
  return userId
}

/**
 * Make sure a `users` row exists for this id, so foreign keys on scans/settings hold.
 * Returns false (instead of throwing) when the database is unavailable, so scans
 * still work — they just aren't saved to history.
 */
export async function ensureUser(userId: string): Promise<boolean> {
  try {
    await db.insert(users).values({ id: userId }).onConflictDoNothing()
    return true
  } catch (error) {
    console.error('[session] database unavailable, scan will not be saved:', error)
    return false
  }
}
