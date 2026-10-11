import { NextRequest, NextResponse } from 'next/server';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import { db } from '@/db';
import { userSettings } from '@/db/schema';
import { ensureUser, getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS, parseJson } from '@/lib/apiGuard';
import { rejectIfTooLarge, serverError } from '../_lib/http';

export const runtime = 'nodejs';

const DEFAULT_SETTINGS = {
  realTimeScanning: true,
  autoQuarantine: true,
  detectionSensitivity: 50,
  defaultAction: 'warn' as const,
  emailAlerts: true,
  desktopAlerts: true,
  dailySummary: false,
  apiEndpoint: '',
  rateLimit: 100,
  autoUpdate: true,
  dataRetentionDays: 30,
  securityLevel: 'medium' as const,
};

/**
 * Accepted settings. Unknown keys (including the old `apiKey`) are stripped and
 * never stored. Every field is optional; omitted fields keep their current value.
 */
const settingsSchema = z.object({
  realTimeScanning: z.boolean().optional(),
  autoQuarantine: z.boolean().optional(),
  detectionSensitivity: z.number().int().min(0).max(100).optional(),
  defaultAction: z.enum(['warn', 'block', 'quarantine']).optional(),
  emailAlerts: z.boolean().optional(),
  desktopAlerts: z.boolean().optional(),
  dailySummary: z.boolean().optional(),
  apiEndpoint: z
    .union([z.literal(''), z.string().trim().max(2048).url().refine(v => /^https?:\/\//i.test(v), 'must be http(s)')])
    .optional(),
  rateLimit: z.number().int().min(1).max(10000).optional(),
  autoUpdate: z.boolean().optional(),
  dataRetentionDays: z.number().int().min(1).max(365).optional(),
  securityLevel: z.enum(['low', 'medium', 'high', 'paranoid']).optional(),
});

const bodySchema = z.object({ settings: settingsSchema });

type StoredSettings = typeof userSettings.$inferSelect;

/** Public view of the settings row. The deprecated apiKey column is never returned. */
function toPublicSettings(s: StoredSettings) {
  return {
    realTimeScanning: s.realTimeScanning ?? DEFAULT_SETTINGS.realTimeScanning,
    autoQuarantine: s.autoQuarantine ?? DEFAULT_SETTINGS.autoQuarantine,
    detectionSensitivity: s.detectionSensitivity ?? DEFAULT_SETTINGS.detectionSensitivity,
    defaultAction: s.defaultAction ?? DEFAULT_SETTINGS.defaultAction,
    emailAlerts: s.emailAlerts ?? DEFAULT_SETTINGS.emailAlerts,
    desktopAlerts: s.desktopAlerts ?? DEFAULT_SETTINGS.desktopAlerts,
    dailySummary: s.dailySummary ?? DEFAULT_SETTINGS.dailySummary,
    apiEndpoint: s.apiEndpoint || '',
    rateLimit: s.rateLimit ?? DEFAULT_SETTINGS.rateLimit,
    autoUpdate: s.autoUpdate ?? DEFAULT_SETTINGS.autoUpdate,
    dataRetentionDays: s.dataRetentionDays ?? DEFAULT_SETTINGS.dataRetentionDays,
    securityLevel: s.securityLevel ?? DEFAULT_SETTINGS.securityLevel,
  };
}

/** GET /api/settings — settings for the current session. */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'read', LIMITS.read);
    if (limited) return limited;

    const settings = await db.query.userSettings.findFirst({
      where: eq(userSettings.userId, userId),
    });

    if (!settings) {
      return NextResponse.json({ success: true, settings: DEFAULT_SETTINGS, isDefault: true });
    }
    return NextResponse.json({ success: true, settings: toPublicSettings(settings), isDefault: false });
  } catch (error) {
    return serverError('GET /api/settings', error, 'Failed to fetch settings');
  }
}

/** POST /api/settings — body `{ settings: {...} }`, saved for the current session. */
export async function POST(request: NextRequest) {
  try {
    const tooLarge = rejectIfTooLarge(request, 16 * 1024);
    if (tooLarge) return tooLarge;

    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'settings', LIMITS.read);
    if (limited) return limited;

    const parsed = await parseJson(request, bodySchema);
    if (parsed.error) return parsed.error;
    const input = parsed.data.settings;

    // Only the fields the client actually sent are updated.
    const changes = Object.fromEntries(
      Object.entries(input).filter(([, v]) => v !== undefined)
    ) as Partial<z.infer<typeof settingsSchema>>;
    const normalized = {
      ...changes,
      ...(changes.apiEndpoint !== undefined ? { apiEndpoint: changes.apiEndpoint || null } : {}),
    };

    await ensureUser(userId);

    const [saved] = await db
      .insert(userSettings)
      .values({
        ...DEFAULT_SETTINGS,
        apiEndpoint: null,
        ...normalized,
        userId,
        updatedAt: new Date(),
      })
      .onConflictDoUpdate({
        target: userSettings.userId,
        set: { ...normalized, updatedAt: new Date() },
      })
      .returning();

    return NextResponse.json({
      success: true,
      message: 'Settings saved successfully',
      settings: toPublicSettings(saved),
    });
  } catch (error) {
    return serverError('POST /api/settings', error, 'Failed to save settings');
  }
}
