/**
 * Rate Limiting Middleware
 *
 * Implements rate limiting for API endpoints to prevent abuse.
 * Uses simple in-memory tracking with optional database persistence.
 *
 * Usage:
 * const { success, remaining } = await checkRateLimit(userId, 'analyze', 100, 3600)
 * if (!success) return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429 })
 */

import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/db';
import { userSettings } from '@/db/schema';
import { eq } from 'drizzle-orm';

// ... (keep the rest of the imports and types if any, but I'll replace the block)
// Assuming lines 1-13 are imports

// In-memory rate limit tracking (for single server)
// Format: { key: { count: number, resetTime: number } }
const rateLimitMap = new Map<string, { count: number; resetTime: number }>()

export interface RateLimitResult {
  success: boolean
  remaining: number
  resetAt: Date
  error?: string
}

/**
 * Check if request is within rate limit
 *
 * @param identifier - User ID, IP address, or unique identifier
 * @param action - Type of action (analyze_url, analyze_email, etc.)
 * @param limit - Maximum requests allowed
 * @param windowSeconds - Time window in seconds (default: 1 hour)
 * @returns Rate limit check result
 */
export async function checkRateLimit(
  identifier: string,
  action: string,
  limit: number = 100,
  windowSeconds: number = 3600
): Promise<RateLimitResult> {
  const key = `${identifier}:${action}`
  const now = Date.now()

  // Get current limit data
  const limitData = rateLimitMap.get(key)
  const resetAt = new Date(limitData?.resetTime || now + windowSeconds * 1000)

  // Check if window has expired
  if (!limitData || now > limitData.resetTime) {
    // Start new window
    rateLimitMap.set(key, {
      count: 1,
      resetTime: now + windowSeconds * 1000,
    })

    return {
      success: true,
      remaining: limit - 1,
      resetAt,
    }
  }

  // Within existing window
  if (limitData.count >= limit) {
    // Rate limit exceeded
    return {
      success: false,
      remaining: 0,
      resetAt,
      error: `Rate limit exceeded. Max ${limit} requests per ${windowSeconds}s`,
    }
  }

  // Increment counter
  limitData.count++

  return {
    success: true,
    remaining: limit - limitData.count,
    resetAt,
  }
}

/**
 * Get user's rate limit settings from database
 * Allows per-user customization of rate limits
 */
export async function getUserRateLimit(userId: string) {
  try {
    const settings = await db.query.userSettings.findFirst({
      where: eq(userSettings.userId, userId),
    });

    return {
      limit: settings?.rateLimit || 100, // Default: 100 scans per hour
      windowSeconds: 3600, // 1 hour
    }
  } catch (error) {
    console.error('Failed to get user rate limit settings:', error)
    return {
      limit: 100,
      windowSeconds: 3600,
    }
  }
}

/**
 * Extract user IP from request headers
 * Useful for rate limiting by IP address
 */
export function getClientIP(request: NextRequest): string {
  // Check various header possibilities (order matters with proxies)
  const forwarded = request.headers.get('x-forwarded-for')
  if (forwarded) {
    return forwarded.split(',')[0].trim()
  }

  const ip = request.headers.get('x-real-ip')
  if (ip) {
    return ip
  }

  // Fallback — no IP available
  return 'unknown'
}

/**
 * Middleware to apply rate limiting to API route
 *
 * Usage in API route:
 * export async function POST(request: NextRequest) {
 *   const rateLimitResult = await applyRateLimit(request, 'userId123')
 *   if (!rateLimitResult.success) {
 *     return NextResponse.json(
 *       { error: rateLimitResult.error },
 *       { status: 429, headers: rateLimitResult.headers }
 *     )
 *   }
 *   // Continue with request...
 * }
 */
export async function applyRateLimit(
  request: NextRequest,
  identifier?: string
): Promise<
  RateLimitResult & {
    headers?: Record<string, string>
  }
> {
  // Use provided identifier, fall back to IP
  const id = identifier || getClientIP(request)
  const action = request.nextUrl.pathname.replace(/[^a-z0-9_]/gi, '_')

  const result = await checkRateLimit(id, action, 100, 3600)

  // Add HTTP headers for rate limit info
  const headers = {
    'X-RateLimit-Limit': '100',
    'X-RateLimit-Remaining': result.remaining.toString(),
    'X-RateLimit-Reset': Math.floor(result.resetAt.getTime() / 1000).toString(),
  }

  return {
    ...result,
    headers,
  }
}

/**
 * Clear rate limit for a user (for testing or administrative purposes)
 */
export function clearRateLimit(identifier: string, action: string): void {
  const key = `${identifier}:${action}`
  rateLimitMap.delete(key)
}

/**
 * Get current rate limit status for debugging
 */
export function getRateLimitStatus(identifier: string, action: string) {
  const key = `${identifier}:${action}`
  const data = rateLimitMap.get(key)

  if (!data) {
    return {
      status: 'no_limit_tracked',
      nextReset: null,
    }
  }

  return {
    status: 'limited',
    count: data.count,
    resetAt: new Date(data.resetTime),
    secondsUntilReset: Math.floor((data.resetTime - Date.now()) / 1000),
  }
}

/**
 * Cleanup old entries from in-memory map (optional)
 * Call periodically to prevent memory leaks
 */
export function cleanupExpiredLimits(): void {
  const now = Date.now()
  let cleaned = 0

  for (const [key, value] of rateLimitMap.entries()) {
    if (now > value.resetTime) {
      rateLimitMap.delete(key)
      cleaned++
    }
  }

  if (cleaned > 0) {
    console.log(`Cleaned up ${cleaned} expired rate limit entries`)
  }
}

/**
 * Start periodic cleanup (every 10 minutes)
 * Call this once at application startup
 */
export function startRateLimitCleanup(): void {
  setInterval(() => {
    cleanupExpiredLimits()
  }, 10 * 60 * 1000) // Every 10 minutes

  console.log('Rate limit cleanup scheduled every 10 minutes')
}
