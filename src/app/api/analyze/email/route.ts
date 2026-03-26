import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/db';
import { users, modelConfigs, scanResults } from '@/db/schema';
import { eq } from 'drizzle-orm';
import { EmailAnalyzer } from '@/services/email/emailAnalyzer'

export async function POST(request: NextRequest) {
  try {
    const { from, to, subject, body, bodyHtml, headers, attachments, user_id } = await request.json()

    // Validate required fields
    if (!from || !subject || !body) {
      return NextResponse.json(
        { success: false, error: 'Missing required fields: from, subject, body' },
        { status: 400 }
      )
    }

    const modelConfig = await db.query.modelConfigs.findFirst({
      where: eq(modelConfigs.modelId, 'email_scanner_v2'),
    });

    if (!modelConfig || modelConfig.state !== 'ACTIVE') {
      return NextResponse.json(
        { success: false, error: 'Email scanner model not available' },
        { status: 503 }
      )
    }

    // Perform comprehensive email analysis
    const analysis = await EmailAnalyzer.analyzeEmail({
      headers: headers || {},
      from,
      to: to || '',
      subject,
      body,
      bodyHtml,
      attachments,
    })

    // Ensure user exists if userId is provided
    let validUserId: string | null = null;

    if (user_id) {
      const userExists = await db.query.users.findFirst({
        where: eq(users.id, user_id),
      });

      // If user doesn't exist, create a minimal user record
      if (!userExists) {
        try {
          await db.insert(users).values({
            id: user_id,
            name: 'Demo User',
          });
          validUserId = user_id;
        } catch {
          // If creation fails (race condition), just use null
          validUserId = null;
        }
      } else {
        validUserId = user_id;
      }
    }

    // Save scan result
    const [scanResult] = await db.insert(scanResults).values({
      userId: validUserId,
      type: 'EMAIL',
      target: `From: ${from} - Subject: ${subject}`,
      confidence: analysis.confidence,
      threatLevel: analysis.threatLevel as any,
      riskScore: analysis.riskScore,
      indicators: analysis.indicators,
      recommendations: analysis.recommendations,
      modelVersion: modelConfig.version,
      metadata: {
        header_analysis: analysis.headerAnalysis,
        content_analysis: analysis.contentAnalysis,
        sender_reputation: analysis.senderReputation,
      },
    }).returning();

    return NextResponse.json({
      success: true,
      analysis: {
        id: scanResult.id,
        type: scanResult.type,
        target: scanResult.target,
        result: {
          is_phishing: analysis.isPhishing,
          is_spam: analysis.isSpam,
          is_spoofed: analysis.isSpoofed,
          confidence: scanResult.confidence,
          threat_level: scanResult.threatLevel,
          risk_score: scanResult.riskScore,
          indicators: scanResult.indicators,
          recommendations: scanResult.recommendations,
          spf_result: analysis.headerAnalysis.spfResult,
          dkim_result: analysis.headerAnalysis.dkimResult,
          dmarc_result: analysis.headerAnalysis.dmarcResult,
          suspicious_links: analysis.contentAnalysis.hasSuspiciousLinks,
          suspicious_attachments: analysis.contentAnalysis.hasSuspiciousAttachments,
        },
        user_id: scanResult.userId,
        timestamp: scanResult.timestamp?.toISOString() || new Date().toISOString(),
        model_version: scanResult.modelVersion,
      },
    })
  } catch (error) {
    console.error('Error analyzing email:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to analyze email' },
      { status: 500 }
    )
  }
}
