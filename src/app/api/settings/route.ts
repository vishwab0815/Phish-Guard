import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import { userSettings, users } from '@/db/schema';
import { eq } from 'drizzle-orm';

/**
 * GET /api/settings?user_id=xxx — Fetch user settings
 */
export async function GET(request: Request) {
  try {
    const searchParams = new URL(request.url).searchParams;
    const userId = searchParams.get('user_id');

    if (!userId) {
      return NextResponse.json(
        { success: false, error: 'user_id is required' },
        { status: 400 }
      );
    }

    const settings = await db.query.userSettings.findFirst({
      where: eq(userSettings.userId, userId),
    });

    if (!settings) {
      // Return defaults
      return NextResponse.json({
        success: true,
        settings: {
          realTimeScanning: true,
          autoQuarantine: true,
          detectionSensitivity: 50,
          defaultAction: 'warn',
          emailAlerts: true,
          desktopAlerts: true,
          dailySummary: false,
          apiEndpoint: '',
          apiKey: '',
          rateLimit: 100,
          autoUpdate: true,
          dataRetentionDays: 30,
          securityLevel: 'medium',
        },
        isDefault: true,
      });
    }

    return NextResponse.json({
      success: true,
      settings: {
        realTimeScanning: settings.realTimeScanning,
        autoQuarantine: settings.autoQuarantine,
        detectionSensitivity: settings.detectionSensitivity,
        defaultAction: settings.defaultAction,
        emailAlerts: settings.emailAlerts,
        desktopAlerts: settings.desktopAlerts,
        dailySummary: settings.dailySummary,
        apiEndpoint: settings.apiEndpoint || '',
        rateLimit: settings.rateLimit,
        autoUpdate: settings.autoUpdate,
        dataRetentionDays: settings.dataRetentionDays,
        securityLevel: settings.securityLevel,
      },
      isDefault: false,
    });
  } catch (error) {
    console.error('Error fetching settings:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch settings' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/settings — Save user settings
 */
export async function POST(request: NextRequest) {
  try {
    const { user_id, settings } = await request.json();

    if (!user_id || !settings) {
      return NextResponse.json(
        { success: false, error: 'user_id and settings are required' },
        { status: 400 }
      );
    }

    // Ensure user exists
    const userExists = await db.query.users.findFirst({
      where: eq(users.id, user_id),
    });

    if (!userExists) {
      await db.insert(users).values({
        id: user_id,
        name: 'Demo User',
      }).onConflictDoNothing();
    }

    // Upsert settings
    const savedSettings = await db.insert(userSettings).values({
      userId: user_id,
      realTimeScanning: settings.realTimeScanning ?? true,
      autoQuarantine: settings.autoQuarantine ?? true,
      detectionSensitivity: settings.detectionSensitivity ?? 50,
      defaultAction: settings.defaultAction ?? 'warn',
      emailAlerts: settings.emailAlerts ?? true,
      desktopAlerts: settings.desktopAlerts ?? true,
      dailySummary: settings.dailySummary ?? false,
      apiEndpoint: settings.apiEndpoint || null,
      rateLimit: settings.rateLimit ?? 100,
      autoUpdate: settings.autoUpdate ?? true,
      dataRetentionDays: settings.dataRetentionDays ?? 30,
      securityLevel: settings.securityLevel ?? 'medium',
      updatedAt: new Date(),
    }).onConflictDoUpdate({
      target: userSettings.userId,
      set: {
        realTimeScanning: settings.realTimeScanning,
        autoQuarantine: settings.autoQuarantine,
        detectionSensitivity: settings.detectionSensitivity,
        defaultAction: settings.defaultAction,
        emailAlerts: settings.emailAlerts,
        desktopAlerts: settings.desktopAlerts,
        dailySummary: settings.dailySummary,
        apiEndpoint: settings.apiEndpoint || null,
        rateLimit: settings.rateLimit,
        autoUpdate: settings.autoUpdate,
        dataRetentionDays: settings.dataRetentionDays,
        securityLevel: settings.securityLevel,
        updatedAt: new Date(),
      },
    }).returning();

    return NextResponse.json({
      success: true,
      message: 'Settings saved successfully',
      settings: savedSettings[0],
    });
  } catch (error) {
    console.error('Error saving settings:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to save settings' },
      { status: 500 }
    );
  }
}
