/**
 * SSL Certificate Intelligence API
 * Provides SSL/TLS certificate analysis and validation
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { SSLValidator } from '@/services/detection/sslValidator';
import { getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS, parseJson } from '@/lib/apiGuard';
import { isBlockedHostError, jsonError, normalizeDomain, PRIVATE_TARGET_MESSAGE, rejectIfTooLarge, serverError } from '../../_lib/http';

export const runtime = 'nodejs';

/** POST /api/threat-intel/certificate — body `{ domain }` */
export async function POST(request: NextRequest) {
  try {
    const tooLarge = rejectIfTooLarge(request, 8 * 1024);
    if (tooLarge) return tooLarge;

    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'threat-intel', LIMITS.threatIntel);
    if (limited) return limited;

    const parsed = await parseJson(request, z.object({ domain: z.string().max(2048) }));
    if (parsed.error) return parsed.error;

    const domain = normalizeDomain(parsed.data.domain);
    if (!domain) return jsonError('Please enter a valid domain name, like example.com', 400);

    const analysis = await SSLValidator.analyze(domain);

    return NextResponse.json({
      success: true,
      certificate_analysis: {
        domain,
        is_valid: analysis.isValid,
        risk_score: analysis.riskScore,
        indicators: analysis.indicators,
        certificate_details: analysis.certificateDetails,
        trust_analysis: analysis.trustAnalysis,
      },
    });
  } catch (error) {
    if (isBlockedHostError(error)) return jsonError(PRIVATE_TARGET_MESSAGE, 400);
    return serverError('POST /api/threat-intel/certificate', error, 'Failed to analyze certificate');
  }
}

/** GET /api/threat-intel/certificate?url=https://example.com — quick validity check */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'threat-intel', LIMITS.threatIntel);
    if (limited) return limited;

    const raw = request.nextUrl.searchParams.get('url')?.trim() ?? '';
    let url: URL;
    try {
      url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
    } catch {
      return jsonError('Please enter a valid web address', 400);
    }
    if (!raw || raw.length > 2048 || !['http:', 'https:'].includes(url.protocol)) {
      return jsonError('Please enter a valid web address', 400);
    }

    const isValid = await SSLValidator.verifyCertificate(url.toString());

    return NextResponse.json({
      success: true,
      url: url.toString(),
      certificate_valid: isValid,
      message: isValid
        ? 'SSL certificate is valid and trusted'
        : 'SSL certificate validation failed or has security issues',
    });
  } catch (error) {
    if (isBlockedHostError(error)) return jsonError(PRIVATE_TARGET_MESSAGE, 400);
    return serverError('GET /api/threat-intel/certificate', error, 'Failed to verify certificate');
  }
}
