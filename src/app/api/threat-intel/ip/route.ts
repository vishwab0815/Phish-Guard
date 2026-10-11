/**
 * IP Intelligence API
 * Provides IP address reputation and threat analysis
 */

import { NextRequest, NextResponse } from 'next/server';
import { isIP } from 'net';
import { z } from 'zod';
import { IPService } from '@/services/detection/ipService';
import { isNonPublicIp } from '@/lib/netGuard';
import { getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS, parseJson } from '@/lib/apiGuard';
import {
  isBlockedHostError,
  jsonError,
  PRIVATE_TARGET_MESSAGE,
  rejectIfTooLarge,
  serverError,
  threatLevelFromScore,
} from '../../_lib/http';

export const runtime = 'nodejs';

const INVALID_IP = 'Please enter a valid IPv4 or IPv6 address';

function cleanIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const ip = value.trim().replace(/^\[|\]$/g, '');
  return ip.length <= 64 && isIP(ip) ? ip : null;
}

/** POST /api/threat-intel/ip — body `{ ip_address }` */
export async function POST(request: NextRequest) {
  try {
    const tooLarge = rejectIfTooLarge(request, 8 * 1024);
    if (tooLarge) return tooLarge;

    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'threat-intel', LIMITS.threatIntel);
    if (limited) return limited;

    const parsed = await parseJson(request, z.object({ ip_address: z.string().max(64) }));
    if (parsed.error) return parsed.error;

    const ip = cleanIp(parsed.data.ip_address);
    if (!ip) return jsonError(INVALID_IP, 400);
    if (isNonPublicIp(ip)) return jsonError(PRIVATE_TARGET_MESSAGE, 400);

    const analysis = await IPService.analyze(ip);

    return NextResponse.json({
      success: true,
      ip_intelligence: {
        ip_address: analysis.ipAddress,
        risk_score: analysis.riskScore,
        indicators: analysis.indicators,
        geolocation: analysis.geolocation,
        network: analysis.network,
        reputation: analysis.reputation,
      },
    });
  } catch (error) {
    if (isBlockedHostError(error)) return jsonError(PRIVATE_TARGET_MESSAGE, 400);
    return serverError('POST /api/threat-intel/ip', error, 'Failed to analyze IP address');
  }
}

/** GET /api/threat-intel/ip?ip=1.2.3.4 — quick check */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'threat-intel', LIMITS.threatIntel);
    if (limited) return limited;

    const ip = cleanIp(request.nextUrl.searchParams.get('ip'));
    if (!ip) return jsonError(INVALID_IP, 400);

    const isPrivate = isNonPublicIp(ip);
    const analysis = isPrivate ? null : await IPService.analyze(ip);

    return NextResponse.json({
      success: true,
      ip_address: ip,
      is_private: isPrivate,
      is_safe: analysis ? analysis.riskScore < 40 : true,
      risk_score: analysis?.riskScore || 0,
      threat_level: analysis ? threatLevelFromScore(analysis.riskScore) : 'SAFE',
    });
  } catch (error) {
    if (isBlockedHostError(error)) return jsonError(PRIVATE_TARGET_MESSAGE, 400);
    return serverError('GET /api/threat-intel/ip', error, 'Failed to check IP address');
  }
}
