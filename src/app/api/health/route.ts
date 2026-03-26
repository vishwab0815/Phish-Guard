import { NextResponse } from 'next/server'
import { db } from '@/db'
import { modelConfigs } from '@/db/schema'
import { eq } from 'drizzle-orm'

export async function GET() {
  try {
    // Count active models
    const activeModels = await db.query.modelConfigs.findMany({
      where: eq(modelConfigs.state, 'ACTIVE')
    })

    return NextResponse.json({
      success: true,
      status: 'healthy',
      timestamp: new Date().toISOString(),
      models: activeModels.map(m => m.modelId),
      models_available: activeModels.length,
      database: 'connected'
    })
  } catch (error) {
    console.error('Health check error:', error)
    return NextResponse.json(
      {
        success: false,
        status: 'error',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}
