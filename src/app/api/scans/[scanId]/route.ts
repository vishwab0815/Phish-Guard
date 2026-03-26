import { NextResponse } from 'next/server';
import { db } from '@/db';
import { scanResults } from '@/db/schema';
import { eq } from 'drizzle-orm';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ scanId: string }> }
) {
  try {
    const { scanId } = await params;
    const scan = await db.query.scanResults.findFirst({
      where: eq(scanResults.id, scanId),
    });

    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      scan: {
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
        metadata: scan.metadata,
      },
    });
  } catch (error) {
    console.error('Error fetching scan:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch scan details' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ scanId: string }> }
) {
  try {
    const { scanId } = await params;

    // Check if scan exists
    const scan = await db.query.scanResults.findFirst({
      where: eq(scanResults.id, scanId),
    });

    if (!scan) {
      return NextResponse.json(
        { success: false, error: 'Scan not found' },
        { status: 404 }
      );
    }

    // Delete the scan result (cascading deletes should be handled by schema or manually)
    await db.delete(scanResults).where(eq(scanResults.id, scanId));

    return NextResponse.json({
      success: true,
      message: 'Scan deleted successfully',
    });
  } catch (error) {
    console.error('Error deleting scan:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to delete scan' },
      { status: 500 }
    );
  }
}
