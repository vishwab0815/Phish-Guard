/**
 * Shared helpers for API route handlers (private folder: not routed by Next.js).
 */

import { NextResponse } from 'next/server';
import { isIP } from 'net';
import { eq } from 'drizzle-orm';
import { db } from '@/db';
import { modelConfigs, scanResults } from '@/db/schema';
import { BlockedHostError } from '@/lib/netGuard';

export const THREAT_LEVELS = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type ThreatLevelValue = (typeof THREAT_LEVELS)[number];

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const PRIVATE_TARGET_MESSAGE = "That address is private or internal and can't be checked.";

/** JSON error response with `{ success: false, error }`. */
export function jsonError(message: string, status: number, headers?: Record<string, string>) {
  return NextResponse.json({ success: false, error: message }, { status, headers });
}

const DB_UNAVAILABLE_CODES = new Set(['ENOTFOUND', 'ECONNREFUSED', 'ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'CONNECT_TIMEOUT', 'CONNECTION_CLOSED']);

/** True when an error means the database can't be reached (not a bug in the query). */
export function isDatabaseUnavailable(error: unknown): boolean {
  type ErrorLike = { code?: unknown; message?: unknown; cause?: unknown };
  for (let e = error as ErrorLike | undefined, depth = 0; e && depth < 5; e = e.cause as ErrorLike | undefined, depth++) {
    if (typeof e.code === 'string' && DB_UNAVAILABLE_CODES.has(e.code)) return true;
    if (typeof e.message === 'string' && e.message.startsWith('DATABASE_URL is not set')) return true;
  }
  return false;
}

/**
 * Log the real error server-side and return a generic message to the client:
 * 503 when the database is unreachable (history/stats/settings need it), otherwise 500.
 */
export function serverError(context: string, error: unknown, message = 'Something went wrong. Please try again.') {
  if (isDatabaseUnavailable(error)) {
    console.error(`[api] ${context}: database unavailable`);
    return jsonError("This isn't available right now because the database is offline. Scanning still works.", 503);
  }
  console.error(`[api] ${context}:`, error);
  return jsonError(message, 500);
}

/**
 * Reject requests whose declared Content-Length exceeds `maxBytes` before the
 * body is read. (Chunked bodies without a length are still bounded by schema checks.)
 */
export function rejectIfTooLarge(request: Request, maxBytes: number): NextResponse | null {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) {
    return jsonError(`Request is too large (max ${Math.floor(maxBytes / 1024)} KB).`, 413);
  }
  return null;
}

export function isBlockedHostError(error: unknown): boolean {
  return error instanceof BlockedHostError || (error instanceof Error && error.name === 'BlockedHostError');
}

/**
 * Model availability. A model that is missing from the table (DB not seeded)
 * counts as available; only an explicit INACTIVE/MAINTENANCE state disables it.
 */
export async function getModelStatus(modelId: string): Promise<{ available: boolean; version: string }> {
  try {
    const config = await db.query.modelConfigs.findFirst({ where: eq(modelConfigs.modelId, modelId) });
    if (!config) return { available: true, version: 'v1.0' };
    return { available: config.state === 'ACTIVE', version: config.version };
  } catch {
    // Database unavailable: scanning still works without it.
    return { available: true, version: 'v1.0' };
  }
}

/**
 * Save a scan to the user's history. Returns the new row's id and timestamp,
 * or null when the database is unavailable (the scan result is still returned).
 */
export async function saveScan(
  values: typeof scanResults.$inferInsert
): Promise<{ id: string; timestamp: Date | null } | null> {
  try {
    const [row] = await db.insert(scanResults).values(values).returning({ id: scanResults.id, timestamp: scanResults.timestamp });
    return row ?? null;
  } catch (error) {
    console.error('[api] could not save scan to history:', error);
    return null;
  }
}

const DOMAIN_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/**
 * Normalise user input to a bare hostname ("https://Example.com/x" -> "example.com").
 * Returns null if it isn't a syntactically valid public-style domain name.
 */
export function normalizeDomain(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  let value = input.trim().toLowerCase();
  if (!value || value.length > 2048) return null;

  if (value.includes('/') || value.includes(':')) {
    try {
      value = new URL(value.includes('://') ? value : `http://${value}`).hostname;
    } catch {
      return null;
    }
  }
  value = value.replace(/\.$/, '');
  if (isIP(value)) return null;
  return DOMAIN_RE.test(value) ? value : null;
}

/** Same thresholds as MasterDetector.determineThreatLevel, so a score means the same thing everywhere. */
export function threatLevelFromScore(score: number): ThreatLevelValue {
  if (score >= 70) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  if (score >= 15) return 'LOW';
  return 'SAFE';
}

export function clampScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

/** Shape used by /api/scans and /api/scans/[scanId]. */
export function toScanDto(scan: {
  id: string;
  type: string;
  target: string;
  confidence: number;
  threatLevel: string;
  riskScore: number;
  indicators: string[] | null;
  recommendations: string[] | null;
  userId: string | null;
  timestamp: Date | null;
  modelVersion: string | null;
}) {
  return {
    id: scan.id,
    type: scan.type,
    target: scan.target,
    result: {
      confidence: scan.confidence,
      threat_level: scan.threatLevel,
      risk_score: scan.riskScore,
      indicators: scan.indicators || [],
      recommendations: scan.recommendations || [],
    },
    user_id: scan.userId,
    timestamp: scan.timestamp?.toISOString(),
    model_version: scan.modelVersion,
  };
}
