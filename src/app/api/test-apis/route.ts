import { NextRequest, NextResponse } from 'next/server';
import { count } from 'drizzle-orm';
import Groq from 'groq-sdk';
import { VirusTotalService } from '@/services/external/virusTotal';
import { GoogleSafeBrowsingService } from '@/services/external/googleSafeBrowsing';
import { db } from '@/db';
import { modelConfigs } from '@/db/schema';
import { requireAdmin } from '@/lib/apiGuard';
import { GROQ_MODEL } from '@/lib/llm';

export const runtime = 'nodejs';

interface ServiceStatus {
  configured: boolean;
  working: boolean;
  message: string;
}

const TIMEOUT_MS = 10_000;

function withTimeout<T>(promise: Promise<T>, ms = TIMEOUT_MS): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
  ]);
}

async function probe(name: string, configured: boolean, run: () => Promise<string>): Promise<ServiceStatus> {
  if (!configured) return { configured, working: false, message: 'Not configured' };
  try {
    return { configured, working: true, message: await withTimeout(run()) };
  } catch (error) {
    // Upstream error text can contain request details; keep it in server logs only.
    console.error(`[api] test-apis ${name} probe failed:`, error);
    return { configured, working: false, message: 'Check failed (see server logs)' };
  }
}

/**
 * GET /api/test-apis — admin-only integration check (header `x-admin-token`).
 * Calls real upstream APIs and uses quota, so it is not public.
 */
export async function GET(request: NextRequest) {
  const denied = requireAdmin(request);
  if (denied) return denied;

  const [virusTotal, googleSafeBrowsing, groq, database] = await Promise.all([
    probe('virusTotal', !!process.env.VIRUSTOTAL_API_KEY, async () => {
      const r = await VirusTotalService.analyzeURL('http://example.com');
      return `Responding. Engines: ${r.totalEngines}, detections: ${r.detectionCount}`;
    }),
    probe('googleSafeBrowsing', !!process.env.GOOGLE_SAFE_BROWSING_API_KEY, async () => {
      const r = await GoogleSafeBrowsingService.checkURL('http://example.com');
      return `Responding. Threat detected for example.com: ${r.isThreat}`;
    }),
    probe('groq', !!process.env.GROQ_API_KEY, async () => {
      const client = new Groq({ apiKey: process.env.GROQ_API_KEY, timeout: TIMEOUT_MS, maxRetries: 0 });
      await client.chat.completions.create({
        model: GROQ_MODEL,
        messages: [{ role: 'user', content: 'Reply with OK' }],
        max_tokens: 5,
      });
      return 'Responding';
    }),
    probe('database', !!process.env.DATABASE_URL, async () => {
      const [row] = await db.select({ value: count() }).from(modelConfigs);
      return `Connected. Model configs: ${row.value}`;
    }),
  ]);

  const services = { virusTotal, googleSafeBrowsing, groq, database };
  const all = Object.values(services);
  const workingCount = all.filter(s => s.working).length;

  return NextResponse.json({
    success: true,
    summary: {
      working: workingCount,
      total: all.length,
      status:
        workingCount === all.length ? 'All systems operational' :
        workingCount > 0 ? 'Partial functionality' : 'Services unavailable',
    },
    services,
    timestamp: new Date().toISOString(),
  });
}
