import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/db';
import { modelConfigs, scanResults } from '@/db/schema';
import { eq } from 'drizzle-orm';

async function analyzeMessage(message: string, context: any) {
  const socialEngineeringPatterns = [
    'urgent', 'emergency', 'immediately', 'asap', 'deadline',
    'secret', 'confidential', 'do not tell', 'between us',
    'trust me', 'believe me', 'promise', 'guarantee',
    'free', 'win', 'winner', 'prize', 'lottery',
    'click here', 'download', 'install', 'run this'
  ]

  let riskScore = 0
  const indicators: string[] = []

  const lowerMessage = message.toLowerCase()
  const patternMatches = socialEngineeringPatterns.filter(pattern =>
    lowerMessage.includes(pattern)
  )

  if (patternMatches.length > 0) {
    riskScore += patternMatches.length * 0.12
    indicators.push(`Social engineering patterns: ${patternMatches.join(', ')}`)
  }

  // Urgency analysis
  const urgencyWords = ['urgent', 'immediate', 'asap', 'now', 'quickly']
  const urgencyCount = urgencyWords.filter(word => lowerMessage.includes(word)).length
  if (urgencyCount > 1) {
    riskScore += 0.25
    indicators.push('High urgency language detected')
  }

  // Financial request analysis
  const financialWords = ['money', 'payment', 'transfer', 'bank', 'card', 'password']
  const financialCount = financialWords.filter(word => lowerMessage.includes(word)).length
  if (financialCount > 2) {
    riskScore += 0.3
    indicators.push('Financial information request detected')
  }

  riskScore = Math.max(0, Math.min(1, riskScore))

  const threat_level = riskScore >= 0.8 ? 'CRITICAL' :
                      riskScore >= 0.6 ? 'HIGH' :
                      riskScore >= 0.4 ? 'MEDIUM' :
                      riskScore >= 0.2 ? 'LOW' : 'SAFE'

  const recommendations = generateRecommendations(threat_level)

  return {
    confidence: Math.round((1 - Math.abs(riskScore - 0.5) * 2) * 100),
    threat_level,
    risk_score: Math.round(riskScore * 100),
    indicators,
    message_analysis: {
      social_engineering_patterns: patternMatches,
      urgency_level: urgencyCount,
      financial_indicators: financialCount
    },
    recommendations
  }
}

function generateRecommendations(threat_level: string): string[] {
  const recommendations: Record<string, string[]> = {
    'SAFE': ['Continue with normal security practices', 'Monitor for any changes'],
    'LOW': ['Exercise standard caution', 'Verify sender if unknown'],
    'MEDIUM': ['Proceed with increased caution', 'Verify through alternate communication channel', 'Do not click suspicious links'],
    'HIGH': ['Do not interact with this content', 'Report to security team', 'Block sender if applicable'],
    'CRITICAL': ['IMMEDIATE ACTION: Do not interact', 'Report to security team immediately', 'Block and quarantine if possible', 'Change passwords if compromised']
  }

  return recommendations[threat_level] || ['Unable to generate recommendations']
}

export async function POST(request: NextRequest) {
  try {
    const { message, context, user_id } = await request.json()

    const modelConfig = await db.query.modelConfigs.findFirst({
      where: eq(modelConfigs.modelId, 'message_classifier_v1'),
    });

    if (!modelConfig || modelConfig.state !== 'ACTIVE') {
      return NextResponse.json(
        { success: false, error: 'Message classifier model not available' },
        { status: 503 }
      )
    }

    const analysis = await analyzeMessage(message, context)

    const [scanResult] = await db.insert(scanResults).values({
      userId: user_id,
      type: 'MESSAGE',
      target: message.substring(0, 50) + '...',
      confidence: analysis.confidence,
      threatLevel: analysis.threat_level as any,
      riskScore: analysis.risk_score,
      indicators: analysis.indicators,
      recommendations: analysis.recommendations,
      modelVersion: modelConfig.version,
      metadata: analysis.message_analysis,
    }).returning();

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
        },
        user_id: scanResult.userId,
        timestamp: scanResult.timestamp?.toISOString() || new Date().toISOString(),
        model_version: scanResult.modelVersion,
      },
    })
  } catch (error) {
    console.error('Error analyzing message:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to analyze message' },
      { status: 500 }
    )
  }
}
