import { NextResponse } from 'next/server';
import { db } from '@/db';
import { serverError } from '../_lib/http';

export const runtime = 'nodejs';

/**
 * GET /api/models — read-only list of detection model configs.
 * Seeding happens only via `npm run db:seed` (src/db/seed.ts); this route never writes.
 * There is no write endpoint here; any future one must call requireAdmin().
 */
export async function GET() {
  try {
    const models = await db.query.modelConfigs.findMany();

    return NextResponse.json({
      success: true,
      models: models.map(model => ({
        id: model.modelId,
        config: {
          state: model.state,
          version: model.version,
          confidence_threshold: model.confidenceThreshold,
          features: model.features,
          initialized_at: model.initializedAt?.toISOString(),
          updated_at: model.updatedAt?.toISOString(),
        },
      })),
    });
  } catch (error) {
    return serverError('GET /api/models', error, 'Failed to fetch models');
  }
}
