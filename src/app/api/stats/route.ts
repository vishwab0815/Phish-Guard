import { NextResponse } from 'next/server';
import { db } from '@/db';
import { scanResults } from '@/db/schema';
import { eq, gte, and, sql, count } from 'drizzle-orm';

export async function GET(request: Request) {
  try {
    const searchParams = new URL(request.url).searchParams;
    const user_id = searchParams.get('user_id');

    const where = user_id ? eq(scanResults.userId, user_id) : undefined;

    const [totalScansResult, threatCounts, typeCounts, recentActivityCount] = await Promise.all([
      db.select({ count: count() }).from(scanResults).where(where),
      
      db.select({ 
        threatLevel: scanResults.threatLevel, 
        count: count() 
      }).from(scanResults).where(where).groupBy(scanResults.threatLevel),

      db.select({ 
        type: scanResults.type, 
        count: count() 
      }).from(scanResults).where(where).groupBy(scanResults.type),

      db.select({ count: count() }).from(scanResults).where(
        user_id 
          ? and(eq(scanResults.userId, user_id), gte(scanResults.timestamp, new Date(Date.now() - 24 * 60 * 60 * 1000)))
          : gte(scanResults.timestamp, new Date(Date.now() - 24 * 60 * 60 * 1000))
      ),
    ]);

    const totalScans = totalScansResult[0].count;
    const recentActivity = recentActivityCount[0].count;

    const threatMap: Record<string, number> = {};
    threatCounts.forEach(t => { threatMap[t.threatLevel] = t.count; });

    const typeMap: Record<string, number> = {};
    typeCounts.forEach(t => { typeMap[t.type] = t.count; });

    const threatsDetected = (threatMap['HIGH'] || 0) + (threatMap['CRITICAL'] || 0);
    const safeItems = threatMap['SAFE'] || 0;
    const suspiciousItems = (threatMap['MEDIUM'] || 0) + (threatMap['LOW'] || 0);

    return NextResponse.json({
      success: true,
      stats: {
        total_scans: totalScans,
        threats_detected: threatsDetected,
        safe_items: safeItems,
        suspicious_items: suspiciousItems,
        by_type: {
          url: typeMap['URL'] || 0,
          email: typeMap['EMAIL'] || 0,
          message: typeMap['MESSAGE'] || 0,
          file: typeMap['FILE'] || 0,
        },
        recent_activity: recentActivity,
      },
    });
  } catch (error) {
    console.error('Error calculating stats:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to calculate statistics' },
      { status: 500 }
    );
  }
}
