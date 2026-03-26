import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { modelConfigs, scanJobs, scanResults } from '@/db/schema';
import { eq } from 'drizzle-orm';
import { MasterDetector } from '@/services/detection/masterDetector';

interface BatchRequest {
  urls: string[];
  user_id?: string;
}

interface BatchResult {
  url: string;
  success: boolean;
  result?: {
    confidence: number;
    threat_level: string;
    risk_score: number;
    indicators: string[];
    recommendations: string[];
  };
  error?: string;
}

export async function POST(request: NextRequest) {
  try {
    const { urls, user_id }: BatchRequest = await request.json();

    // Validate input
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return NextResponse.json(
        { success: false, error: 'Invalid URLs array provided' },
        { status: 400 }
      );
    }

    // Limit batch size to prevent abuse
    const MAX_BATCH_SIZE = 10;
    if (urls.length > MAX_BATCH_SIZE) {
      return NextResponse.json(
        {
          success: false,
          error: `Batch size exceeds maximum limit of ${MAX_BATCH_SIZE} URLs`,
        },
        { status: 400 }
      );
    }

    // Get model config
    const modelConfig = await db.query.modelConfigs.findFirst({
      where: eq(modelConfigs.modelId, 'url_analyzer_v1'),
    });

    if (!modelConfig || modelConfig.state !== 'ACTIVE') {
      return NextResponse.json(
        { success: false, error: 'URL analyzer model not available' },
        { status: 503 }
      );
    }

    // Process URLs in parallel (with rate limiting)
    const results: BatchResult[] = await Promise.all(
      urls.map(async (url) => {
        try {
          // Validate URL format
          if (typeof url !== 'string' || url.trim().length === 0) {
            return {
              url,
              success: false,
              error: 'Invalid URL format',
            };
          }

          // Perform analysis
          const analysis = await MasterDetector.analyzeURL(url, user_id);

          return {
            url,
            success: true,
            result: {
              confidence: analysis.confidence,
              threat_level: analysis.threatLevel,
              risk_score: analysis.riskScore,
              indicators: analysis.indicators,
              recommendations: analysis.recommendations,
            },
          };
        } catch (error) {
          console.error(`Error analyzing URL ${url}:`, error);
          return {
            url,
            success: false,
            error: 'Failed to analyze URL',
          };
        }
      })
    );

    // Calculate summary statistics
    const successfulScans = results.filter((r) => r.success);
    const failedScans = results.filter((r) => !r.success);

    const threatDistribution = {
      SAFE: successfulScans.filter((r) => r.result?.threat_level === 'SAFE').length,
      LOW: successfulScans.filter((r) => r.result?.threat_level === 'LOW').length,
      MEDIUM: successfulScans.filter((r) => r.result?.threat_level === 'MEDIUM').length,
      HIGH: successfulScans.filter((r) => r.result?.threat_level === 'HIGH').length,
      CRITICAL: successfulScans.filter((r) => r.result?.threat_level === 'CRITICAL').length,
    };

    const avgRiskScore =
      successfulScans.length > 0
        ? successfulScans.reduce((sum, r) => sum + (r.result?.risk_score || 0), 0) /
          successfulScans.length
        : 0;

    return NextResponse.json({
      success: true,
      summary: {
        total: urls.length,
        successful: successfulScans.length,
        failed: failedScans.length,
        threat_distribution: threatDistribution,
        average_risk_score: Math.round(avgRiskScore),
      },
      results,
    });
  } catch (error) {
    console.error('Error in batch URL analysis:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to process batch analysis' },
      { status: 500 }
    );
  }
}

/**
 * GET endpoint to check batch analysis status
 * This can be used for async job status checking
 */
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const jobId = searchParams.get('job_id');
    const userId = searchParams.get('user_id');

    if (!jobId) {
      return NextResponse.json(
        { success: false, error: 'Job ID is required' },
        { status: 400 }
      );
    }

    // Find the scan job
    const scanJob = await db.query.scanJobs.findFirst({
      where: eq(scanJobs.id, jobId),
      with: {
        scanResult: true,
      },
    });

    if (!scanJob) {
      return NextResponse.json(
        { success: false, error: 'Scan job not found' },
        { status: 404 }
      );
    }

    // Check authorization
    if (userId && scanJob.userId !== userId) {
      return NextResponse.json(
        { success: false, error: 'Unauthorized' },
        { status: 403 }
      );
    }

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
        error: scanJob.errorMessage,
      },
    });
  } catch (error) {
    console.error('Error fetching batch job status:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch job status' },
      { status: 500 }
    );
  }
}
