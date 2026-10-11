import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { MasterDetector } from '@/services/detection/masterDetector'
import { ensureUser, getSessionUserId } from '@/lib/session'
import { enforceRateLimit, LIMITS, parseJson } from '@/lib/apiGuard'
import { getModelStatus, isBlockedHostError, jsonError, PRIVATE_TARGET_MESSAGE, rejectIfTooLarge, serverError } from '../../_lib/http'

export const runtime = 'nodejs'

const bodySchema = z.object({
  url: z.string().trim().min(1, 'URL is required').max(2048, 'URL is too long (max 2048 characters)'),
})

/** POST /api/analyze/url — body `{ url }` */
export async function POST(request: NextRequest) {
  try {
    const tooLarge = rejectIfTooLarge(request, 16 * 1024)
    if (tooLarge) return tooLarge

    const userId = await getSessionUserId()
    const limited = await enforceRateLimit(request, userId, 'analyze', LIMITS.analyze)
    if (limited) return limited

    const parsed = await parseJson(request, bodySchema)
    if (parsed.error) return parsed.error
    const { url } = parsed.data

    const model = await getModelStatus('url_analyzer_v1')
    if (!model.available) return jsonError('URL analyzer is temporarily unavailable', 503)

    const canSave = await ensureUser(userId)

    // Static analysis, domain intelligence, SSL, IP intelligence and external
    // reputation checks. The detector saves the scan and returns its id.
    const analysis = await MasterDetector.analyzeURL(url, canSave ? userId : undefined)
    const scanId = (analysis as { scanId?: string }).scanId ?? null

    return NextResponse.json({
      success: true,
      analysis: {
        id: scanId,
        saved: scanId !== null,
        type: analysis.type,
        target: analysis.target,
        result: {
          confidence: analysis.confidence,
          threat_level: analysis.threatLevel,
          risk_score: analysis.riskScore,
          indicators: analysis.indicators,
          recommendations: analysis.recommendations,
          riskBreakdown: analysis.riskBreakdown,
          // Real registration age from RDAP; null when the registry didn't answer
          domain_age_days: analysis.layers.domainIntelligence?.whoisData?.domainAge ?? null,
          scan_duration_ms: analysis.scanDuration,
          layers: {
            static_analysis: analysis.layers.staticAnalysis ? 'completed' : 'skipped',
            domain_intelligence: analysis.layers.domainIntelligence ? 'completed' : 'skipped',
            ssl_validation: analysis.layers.sslAnalysis ? 'completed' : 'skipped',
            ip_intelligence: analysis.layers.ipIntelligence ? 'completed' : 'skipped',
            external_scans: analysis.layers.externalScans ? 'completed' : 'skipped',
          },
        },
        user_id: userId,
        timestamp: new Date(analysis.timestamp ?? Date.now()).toISOString(),
        model_version: model.version,
      },
    })
  } catch (error) {
    if (isBlockedHostError(error)) return jsonError(PRIVATE_TARGET_MESSAGE, 400)
    return serverError('POST /api/analyze/url', error, 'Failed to analyze URL')
  }
}
