import { NextRequest, NextResponse } from 'next/server';
import { and, count, eq, gte } from 'drizzle-orm';
import { db } from '@/db';
import { scanResults } from '@/db/schema';
import { getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS } from '@/lib/apiGuard';
import { serverError } from '../_lib/http';

export const runtime = 'nodejs';

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Start of "today" for the caller. `tzOffset` is the browser's
 * `new Date().getTimezoneOffset()` in minutes (e.g. -330 for IST); defaults to UTC.
 */
function startOfToday(tzOffsetMinutes: number, now = Date.now()): Date {
  const localNow = now - tzOffsetMinutes * 60_000;
  const localMidnight = Math.floor(localNow / DAY_MS) * DAY_MS;
  return new Date(localMidnight + tzOffsetMinutes * 60_000);
}

/** GET /api/stats?tzOffset=-330 — statistics for the current session only. */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'read', LIMITS.read);
    if (limited) return limited;

    const rawOffset = Number.parseInt(new URL(request.url).searchParams.get('tzOffset') ?? '0', 10);
    const tzOffset = Number.isFinite(rawOffset) && Math.abs(rawOffset) <= 14 * 60 ? rawOffset : 0;

    const mine = eq(scanResults.userId, userId);
    const now = Date.now();
    const today = startOfToday(tzOffset, now);
    const last24h = new Date(now - DAY_MS);
    const last7d = new Date(now - 7 * DAY_MS);

    const [totalRows, threatCounts, typeCounts, recentRows, todayRows, weekRows] = await Promise.all([
      db.select({ count: count() }).from(scanResults).where(mine),
      db
        .select({ threatLevel: scanResults.threatLevel, count: count() })
        .from(scanResults)
        .where(mine)
        .groupBy(scanResults.threatLevel),
      db
        .select({ type: scanResults.type, count: count() })
        .from(scanResults)
        .where(mine)
        .groupBy(scanResults.type),
      db.select({ count: count() }).from(scanResults).where(and(mine, gte(scanResults.timestamp, last24h))),
      db.select({ count: count() }).from(scanResults).where(and(mine, gte(scanResults.timestamp, today))),
      db.select({ count: count() }).from(scanResults).where(and(mine, gte(scanResults.timestamp, last7d))),
    ]);

    const threatMap: Record<string, number> = {};
    threatCounts.forEach(t => { threatMap[t.threatLevel] = Number(t.count); });

    const typeMap: Record<string, number> = {};
    typeCounts.forEach(t => { typeMap[t.type] = Number(t.count); });

    const byThreatLevel = {
      SAFE: threatMap.SAFE || 0,
      LOW: threatMap.LOW || 0,
      MEDIUM: threatMap.MEDIUM || 0,
      HIGH: threatMap.HIGH || 0,
      CRITICAL: threatMap.CRITICAL || 0,
    };

    return NextResponse.json({
      success: true,
      stats: {
        total_scans: Number(totalRows[0]?.count ?? 0),
        threats_detected: byThreatLevel.HIGH + byThreatLevel.CRITICAL,
        safe_items: byThreatLevel.SAFE,
        suspicious_items: byThreatLevel.MEDIUM + byThreatLevel.LOW,
        by_type: {
          url: typeMap.URL || 0,
          email: typeMap.EMAIL || 0,
          message: typeMap.MESSAGE || 0,
          file: typeMap.FILE || 0,
        },
        recent_activity: Number(recentRows[0]?.count ?? 0), // last 24 hours
        by_threat_level: byThreatLevel,
        critical_threats: byThreatLevel.CRITICAL,
        scans_today: Number(todayRows[0]?.count ?? 0), // since local midnight (tzOffset)
        scans_this_week: Number(weekRows[0]?.count ?? 0), // last 7 days
      },
    });
  } catch (error) {
    return serverError('GET /api/stats', error, 'Failed to calculate statistics');
  }
}
