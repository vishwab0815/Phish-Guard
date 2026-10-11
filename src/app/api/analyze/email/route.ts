import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { EmailAnalyzer } from '@/services/email/emailAnalyzer'
import { ensureUser, getSessionUserId } from '@/lib/session'
import { enforceRateLimit, LIMITS, parseJson } from '@/lib/apiGuard'
import { getModelStatus, jsonError, rejectIfTooLarge, serverError, saveScan } from '../../_lib/http'

export const runtime = 'nodejs'

const MAX_EMAIL_BYTES = 200 * 1024
const MAX_BODY_BYTES = MAX_EMAIL_BYTES + 64 * 1024 // JSON overhead

const withinBytes = (max: number) => (value: string) => Buffer.byteLength(value, 'utf8') <= max

/** A pasted raw email (headers + body), e.g. "Show original" / .eml contents. */
const rawSchema = z.object({
  raw: z
    .string()
    .min(1, 'Paste the email to check')
    .refine(withinBytes(MAX_EMAIL_BYTES), 'Email is too large (max 200 KB)'),
})

/** Already-split email fields. */
const structuredSchema = z.object({
  from: z.string().max(1024).default(''),
  to: z.string().max(4096).optional(),
  subject: z.string().max(2000).default(''),
  body: z.string().refine(withinBytes(MAX_EMAIL_BYTES), 'Email body is too large (max 200 KB)').default(''),
  bodyHtml: z.string().refine(withinBytes(MAX_EMAIL_BYTES), 'Email HTML is too large (max 200 KB)').optional(),
  headers: z.record(z.string().max(8192)).optional(),
  attachments: z
    .array(
      z.object({
        filename: z.string().max(512),
        contentType: z.string().max(256),
        size: z.number().int().min(0),
      })
    )
    .max(50)
    .optional(),
})

/** `{ raw }` selects the raw-email form; anything else is treated as structured fields. */
const bodySchema = z.record(z.unknown()).transform((body, ctx) => {
  const schema = 'raw' in body ? rawSchema : structuredSchema
  const result = schema.safeParse(body)
  if (!result.success) {
    result.error.issues.forEach(issue => ctx.addIssue(issue))
    return z.NEVER
  }
  return result.data as z.infer<typeof rawSchema> | z.infer<typeof structuredSchema>
})

function htmlToText(html: string): string {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value
}

/**
 * POST /api/analyze/email
 * Body: `{ raw: string }` (preferred) OR `{ from, subject, body, to?, bodyHtml?, headers?, attachments? }`.
 */
export async function POST(request: NextRequest) {
  try {
    const tooLarge = rejectIfTooLarge(request, MAX_BODY_BYTES)
    if (tooLarge) return tooLarge

    const userId = await getSessionUserId()
    const limited = await enforceRateLimit(request, userId, 'analyze', LIMITS.analyze)
    if (limited) return limited

    const parsed = await parseJson(request, bodySchema)
    if (parsed.error) return parsed.error

    let email: {
      from: string
      to: string
      subject: string
      body: string
      bodyHtml?: string
      headers: Record<string, string>
      attachments?: Array<{ filename: string; contentType: string; size: number }>
    }

    if ('raw' in parsed.data) {
      const p = EmailAnalyzer.parseRawEmail(parsed.data.raw)
      email = {
        from: p.from || '',
        to: p.to || '',
        subject: p.subject || '',
        body: p.body || '',
        bodyHtml: p.bodyHtml,
        headers: p.headers || {},
        attachments: p.attachments,
      }
    } else {
      const d = parsed.data
      email = {
        from: d.from,
        to: d.to || '',
        subject: d.subject,
        body: d.body,
        bodyHtml: d.bodyHtml,
        headers: d.headers || {},
        attachments: d.attachments,
      }
    }

    if (!email.body.trim() && email.bodyHtml) email.body = htmlToText(email.bodyHtml)
    if (!email.body.trim()) {
      return jsonError('The email has no message text to check. Paste the full email, including its body.', 400)
    }

    const model = await getModelStatus('email_scanner_v2')
    if (!model.available) return jsonError('Email scanner is temporarily unavailable', 503)

    const analysis = await EmailAnalyzer.analyzeEmail(email)

    const target = truncate(`From: ${email.from || '(unknown sender)'} - Subject: ${email.subject || '(no subject)'}`, 300)
    const canSave = await ensureUser(userId)
    const saved = canSave ? await saveScan({
      userId,
      type: 'EMAIL',
      target,
      confidence: analysis.confidence,
      threatLevel: analysis.threatLevel,
      riskScore: analysis.riskScore,
      indicators: analysis.indicators,
      recommendations: analysis.recommendations,
      modelVersion: model.version,
      metadata: {
        header_analysis: analysis.headerAnalysis,
        content_analysis: analysis.contentAnalysis,
        sender_reputation: analysis.senderReputation,
      },
    }) : null

    return NextResponse.json({
      success: true,
      analysis: {
        id: saved?.id ?? null,
        saved: saved !== null,
        type: 'EMAIL',
        target,
        result: {
          is_phishing: analysis.isPhishing,
          is_spam: analysis.isSpam,
          is_spoofed: analysis.isSpoofed,
          confidence: analysis.confidence,
          threat_level: analysis.threatLevel,
          risk_score: analysis.riskScore,
          indicators: analysis.indicators,
          recommendations: analysis.recommendations,
          notes: analysis.notes ?? [],
          spf_result: analysis.headerAnalysis.spfResult,
          dkim_result: analysis.headerAnalysis.dkimResult,
          dmarc_result: analysis.headerAnalysis.dmarcResult,
          suspicious_links: analysis.contentAnalysis.hasSuspiciousLinks,
          suspicious_attachments: analysis.contentAnalysis.hasSuspiciousAttachments,
        },
        user_id: userId,
        timestamp: (saved?.timestamp ?? new Date()).toISOString(),
        model_version: model.version,
      },
    })
  } catch (error) {
    return serverError('POST /api/analyze/email', error, 'Failed to analyze email')
  }
}
