/**
 * Domain Intelligence API
 * Provides detailed domain information and threat analysis
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { DomainService } from '@/services/detection/domainService';
import { getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS, parseJson, requireAdmin } from '@/lib/apiGuard';
import { isBlockedHostError, jsonError, normalizeDomain, PRIVATE_TARGET_MESSAGE, rejectIfTooLarge, serverError } from '../../_lib/http';

export const runtime = 'nodejs';

const INVALID_DOMAIN = 'Please enter a valid domain name, like example.com';

/** POST /api/threat-intel/domain — body `{ domain }` */
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
    if (!domain) return jsonError(INVALID_DOMAIN, 400);

    const analysis = await DomainService.analyze(domain);

    return NextResponse.json({
      success: true,
      domain_intelligence: {
        domain: analysis.domain,
        risk_score: analysis.riskScore,
        indicators: analysis.indicators,
        whois_data: analysis.whoisData,
        dns_data: analysis.dnsData,
        reputation: analysis.reputation,
      },
    });
  } catch (error) {
    if (isBlockedHostError(error)) return jsonError(PRIVATE_TARGET_MESSAGE, 400);
    return serverError('POST /api/threat-intel/domain', error, 'Failed to analyze domain');
  }
}

/** GET /api/threat-intel/domain?domain=example.com — trusted/blocked list status */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'threat-intel', LIMITS.threatIntel);
    if (limited) return limited;

    const domain = normalizeDomain(request.nextUrl.searchParams.get('domain'));
    if (!domain) return jsonError(INVALID_DOMAIN, 400);

    const [isTrusted, isBlocked] = await Promise.all([
      DomainService.isTrustedDomain(domain),
      DomainService.isBlockedDomain(domain),
    ]);

    return NextResponse.json({
      success: true,
      domain,
      is_trusted: isTrusted,
      is_blocked: isBlocked,
      status: isBlocked ? 'BLOCKED' : isTrusted ? 'TRUSTED' : 'UNKNOWN',
    });
  } catch (error) {
    return serverError('GET /api/threat-intel/domain', error, 'Failed to check domain status');
  }
}

const putSchema = z.object({
  domain: z.string().max(2048),
  action: z.enum(['trust', 'block']),
  reason: z.string().trim().max(500).optional(),
  added_by: z.string().trim().max(100).optional(),
});

/**
 * PUT /api/threat-intel/domain — add a domain to the global trusted/blocked list.
 * Admin only (header `x-admin-token`); these lists affect every user's results.
 */
export async function PUT(request: NextRequest) {
  const denied = requireAdmin(request);
  if (denied) return denied;

  try {
    const parsed = await parseJson(request, putSchema);
    if (parsed.error) return parsed.error;
    const { action, reason, added_by } = parsed.data;

    const domain = normalizeDomain(parsed.data.domain);
    if (!domain) return jsonError(INVALID_DOMAIN, 400);

    if (action === 'trust') {
      await DomainService.trustDomain(domain, reason, added_by ?? 'admin');
      return NextResponse.json({ success: true, message: 'Domain added to trusted list' });
    }

    if (!reason) return jsonError('Reason is required for blocking', 400);
    await DomainService.blockDomain(domain, reason, added_by ?? 'admin');
    return NextResponse.json({ success: true, message: 'Domain added to blocked list' });
  } catch (error) {
    return serverError('PUT /api/threat-intel/domain', error, 'Failed to update domain status');
  }
}
