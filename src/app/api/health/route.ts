import { NextResponse } from 'next/server'
import { eq } from 'drizzle-orm'
import { db } from '@/db'
import { modelConfigs } from '@/db/schema'

export const runtime = 'nodejs'

/**
 * GET /api/health
 * 200 { success: true, status: 'ok', database: 'up', models, models_available, timestamp }
 * 200 { success: true, status: 'degraded', database: 'down', ... } — scanning still works without the
 *     database; only history, stats and settings are unavailable.
 * Database error details are logged server-side only.
 */
export async function GET() {
  const timestamp = new Date().toISOString()
  try {
    const activeModels = await db.query.modelConfigs.findMany({
      where: eq(modelConfigs.state, 'ACTIVE'),
    })

    return NextResponse.json({
      success: true,
      status: 'ok',
      database: 'up',
      timestamp,
      models: activeModels.map(m => m.modelId),
      models_available: activeModels.length,
    })
  } catch (error) {
    console.error('[api] GET /api/health: database check failed:', error)
    return NextResponse.json(
      {
        success: true,
        status: 'degraded',
        database: 'down',
        timestamp,
        models: [],
        models_available: 0,
      }
    )
  }
}
