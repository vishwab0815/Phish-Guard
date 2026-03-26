import { NextResponse } from 'next/server';
import { db } from '@/db';
import { scanResults } from '@/db/schema';
import { desc, eq } from 'drizzle-orm';

export async function GET(request: Request) {
  try {
    const searchParams = new URL(request.url).searchParams;
    const user_id = searchParams.get('user_id');

    const scans = await db.query.scanResults.findMany({
      where: user_id ? eq(scanResults.userId, user_id) : undefined,
      orderBy: [desc(scanResults.timestamp)],
      limit: 100,
    });

    return NextResponse.json({
      success: true,
      scans: scans.map(scan => ({
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
      })),
    });
  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch scan history' },
      { status: 500 }
    );
  }
}
