import { NextRequest, NextResponse } from 'next/server';
import { and, eq } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '@/db';
import { scanJobs } from '@/db/schema';
import { MasterDetector } from '@/services/detection/masterDetector';
import { ensureUser, getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS, parseJson } from '@/lib/apiGuard';
import { getModelStatus, isBlockedHostError, jsonError, rejectIfTooLarge, serverError, UUID_RE } from '../../_lib/http';

export const runtime = 'nodejs';

const MAX_BATCH_SIZE = 10;

const bodySchema = z.object({
  urls: z
    .array(z.string().trim().min(1, 'URL cannot be empty').max(2048, 'URL is too long'))
    .min(1, 'Provide at least one URL')
    .max(MAX_BATCH_SIZE, `Batch size exceeds maximum limit of ${MAX_BATCH_SIZE} URLs`),
});

interface BatchResult {
  url: string;
  success: boolean;
  scan_id?: string | null;
  result?: {
    confidence: number;
    threat_level: string;
    risk_score: number;
    indicators: string[];
    recommendations: string[];
  };
  error?: string;
}

/** POST /api/analyze/batch — body `{ urls: string[] }` (max 10). Each URL counts against the analyze limit. */
export async function POST(request: NextRequest) {
  try {
    const tooLarge = rejectIfTooLarge(request, 64 * 1024);
    if (tooLarge) return tooLarge;

    const userId = await getSessionUserId();

    const parsed = await parseJson(request, bodySchema);
    if (parsed.error) return parsed.error;
    const { urls } = parsed.data;

    // One rate-limit unit per URL, so a batch can't be used to get around the per-scan limit.
    for (let i = 0; i < urls.length; i++) {
      const limited = await enforceRateLimit(request, userId, 'analyze', LIMITS.analyze);
      if (limited) return limited;
    }

    const model = await getModelStatus('url_analyzer_v1');
    if (!model.available) return jsonError('URL analyzer is temporarily unavailable', 503);

    const canSave = await ensureUser(userId);

    const results: BatchResult[] = await Promise.all(
      urls.map(async (url): Promise<BatchResult> => {
        try {
          const analysis = await MasterDetector.analyzeURL(url, canSave ? userId : undefined);
          return {
            url,
            success: true,
            scan_id: (analysis as { scanId?: string }).scanId ?? null,
            result: {
              confidence: analysis.confidence,
              threat_level: analysis.threatLevel,
              risk_score: analysis.riskScore,
              indicators: analysis.indicators,
              recommendations: analysis.recommendations,
            },
          };
        } catch (error) {
          if (isBlockedHostError(error)) {
            return { url, success: false, error: "That address is private or internal and can't be checked." };
          }
          console.error('[api] batch: URL analysis failed:', error);
          return { url, success: false, error: 'Failed to analyze URL' };
        }
      })
    );

    const successful = results.filter(r => r.success);
    const levels = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
    const threatDistribution = Object.fromEntries(
      levels.map(level => [level, successful.filter(r => r.result?.threat_level === level).length])
    );
    const avgRiskScore = successful.length
      ? successful.reduce((sum, r) => sum + (r.result?.risk_score || 0), 0) / successful.length
      : 0;

    return NextResponse.json({
      success: true,
      summary: {
        total: urls.length,
        successful: successful.length,
        failed: results.length - successful.length,
        threat_distribution: threatDistribution,
        average_risk_score: Math.round(avgRiskScore),
      },
      results,
    });
  } catch (error) {
    return serverError('POST /api/analyze/batch', error, 'Failed to process batch analysis');
  }
}

/** GET /api/analyze/batch?job_id=<uuid> — status of one of the current session's jobs */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'read', LIMITS.read);
    if (limited) return limited;

    const jobId = request.nextUrl.searchParams.get('job_id') ?? '';
    if (!UUID_RE.test(jobId)) return jsonError('A valid job_id is required', 400);

    const scanJob = await db.query.scanJobs.findFirst({
      where: and(eq(scanJobs.id, jobId), eq(scanJobs.userId, userId)),
      with: { scanResult: true },
    });

    if (!scanJob) return jsonError('Scan job not found', 404);

    return NextResponse.json({
      success: true,
      job: {
        id: scanJob.id,
        status: scanJob.status,
        type: scanJob.type,
        target: scanJob.target,
        created_at: scanJob.createdAt,
        started_at: scanJob.startedAt,
        completed_at: scanJob.completedAt,
        duration: scanJob.duration,
        result: scanJob.scanResult
          ? {
              confidence: scanJob.scanResult.confidence,
              threat_level: scanJob.scanResult.threatLevel,
              risk_score: scanJob.scanResult.riskScore,
              indicators: scanJob.scanResult.indicators,
              recommendations: scanJob.scanResult.recommendations,
            }
          : null,
        error: scanJob.errorMessage ? 'The scan failed' : null,
      },
    });
  } catch (error) {
    return serverError('GET /api/analyze/batch', error, 'Failed to fetch job status');
  }
}
