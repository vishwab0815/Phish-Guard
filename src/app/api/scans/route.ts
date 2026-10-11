import { NextRequest, NextResponse } from 'next/server';
import { desc, eq } from 'drizzle-orm';
import { db } from '@/db';
import { scanResults } from '@/db/schema';
import { getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS } from '@/lib/apiGuard';
import { serverError, toScanDto } from '../_lib/http';

export const runtime = 'nodejs';

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 100;

/**
 * GET /api/scans?limit=N — the current session's scan history (newest first).
 * Any user_id query parameter is ignored: identity comes only from the session cookie.
 */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'read', LIMITS.read);
    if (limited) return limited;

    const rawLimit = Number.parseInt(new URL(request.url).searchParams.get('limit') ?? '', 10);
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, MAX_LIMIT) : DEFAULT_LIMIT;

    const scans = await db.query.scanResults.findMany({
      where: eq(scanResults.userId, userId),
      orderBy: [desc(scanResults.timestamp)],
      limit,
    });

    return NextResponse.json({
      success: true,
      scans: scans.map(toScanDto),
    });
  } catch (error) {
    return serverError('GET /api/scans', error, 'Failed to fetch scan history');
  }
}
