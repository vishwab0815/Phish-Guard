import { NextRequest, NextResponse } from 'next/server';
import { and, eq } from 'drizzle-orm';
import { db } from '@/db';
import { scanResults } from '@/db/schema';
import { getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS } from '@/lib/apiGuard';
import { jsonError, serverError, toScanDto, UUID_RE } from '../../_lib/http';

export const runtime = 'nodejs';

type Params = { params: Promise<{ scanId: string }> };

function ownScan(scanId: string, userId: string) {
  return and(eq(scanResults.id, scanId), eq(scanResults.userId, userId));
}

export async function GET(request: NextRequest, { params }: Params) {
  try {
    const { scanId } = await params;
    if (!UUID_RE.test(scanId)) return jsonError('Invalid scan id', 400);

    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'read', LIMITS.read);
    if (limited) return limited;

    const scan = await db.query.scanResults.findFirst({ where: ownScan(scanId, userId) });
    // Another user's scan is indistinguishable from a missing one.
    if (!scan) return jsonError('Scan not found', 404);

    return NextResponse.json({
      success: true,
      scan: { ...toScanDto(scan), metadata: scan.metadata },
    });
  } catch (error) {
    return serverError('GET /api/scans/[scanId]', error, 'Failed to fetch scan details');
  }
}

export async function DELETE(request: NextRequest, { params }: Params) {
  try {
    const { scanId } = await params;
    if (!UUID_RE.test(scanId)) return jsonError('Invalid scan id', 400);

    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'read', LIMITS.read);
    if (limited) return limited;

    const deleted = await db
      .delete(scanResults)
      .where(ownScan(scanId, userId))
      .returning({ id: scanResults.id });

    if (deleted.length === 0) return jsonError('Scan not found', 404);

    return NextResponse.json({ success: true, message: 'Scan deleted successfully' });
  } catch (error) {
    return serverError('DELETE /api/scans/[scanId]', error, 'Failed to delete scan');
  }
}
