import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/db';
import { modelConfigs, scanResults } from '@/db/schema';
import { eq, and, desc } from 'drizzle-orm';
import { MasterDetector } from '@/services/detection/masterDetector'

export async function POST(request: NextRequest) {
  try {
    const { url, user_id } = await request.json()

    // Validate URL
    if (!url || typeof url !== 'string') {
      return NextResponse.json(
        { success: false, error: 'Invalid URL provided' },
        { status: 400 }
      )
    }

    // Get model config
    const modelConfig = await db.query.modelConfigs.findFirst({
      where: eq(modelConfigs.modelId, 'url_analyzer_v1'),
    });

    if (!modelConfig || modelConfig.state !== 'ACTIVE') {
      return NextResponse.json(
        { success: false, error: 'URL analyzer model not available' },
        { status: 503 }
      )
    }

    // Perform comprehensive analysis using MasterDetector
    // This includes: static analysis, domain intelligence, SSL validation,
    // IP intelligence, and external threat scans (VirusTotal, Safe Browsing, PhishTank)
    const analysis = await MasterDetector.analyzeURL(url, user_id)

    // Retrieve the saved scan result
    const scanResult = await db.query.scanResults.findFirst({
      where: and(
        eq(scanResults.target, url),
        user_id ? eq(scanResults.userId, user_id) : undefined
      ),
      orderBy: [desc(scanResults.timestamp)],
    });

    if (!scanResult) {
      return NextResponse.json(
        { success: false, error: 'Failed to save scan result' },
        { status: 500 }
      )
    }

    // Format response
    return NextResponse.json({
      success: true,
      analysis: {
        id: scanResult.id,
        type: scanResult.type,
        target: scanResult.target,
        result: {
          confidence: scanResult.confidence,
          threat_level: scanResult.threatLevel,
          risk_score: scanResult.riskScore,
          indicators: scanResult.indicators,
          recommendations: scanResult.recommendations,
          riskBreakdown: analysis.riskBreakdown, // Include actual backend risk breakdown
          scan_duration_ms: scanResult.scanDuration,
          layers: {
            static_analysis: analysis.layers.staticAnalysis ? 'completed' : 'skipped',
            domain_intelligence: analysis.layers.domainIntelligence ? 'completed' : 'skipped',
            ssl_validation: analysis.layers.sslAnalysis ? 'completed' : 'skipped',
            ip_intelligence: analysis.layers.ipIntelligence ? 'completed' : 'skipped',
            external_scans: analysis.layers.externalScans ? 'completed' : 'skipped',
          },
        },
        user_id: scanResult.userId,
        timestamp: scanResult.timestamp?.toISOString() || new Date().toISOString(),
        model_version: scanResult.modelVersion,
      },
    })
  } catch (error) {
    console.error('Error analyzing URL:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to analyze URL' },
      { status: 500 }
    )
  }
}
