import { NextRequest, NextResponse } from 'next/server';
import { VirusTotalService } from '@/services/external/virusTotal';
import { GoogleSafeBrowsingService } from '@/services/external/googleSafeBrowsing';
import Groq from 'groq-sdk';

/**
 * Test API endpoint to verify external service integrations
 * GET /api/test-apis
 */
export async function GET(request: NextRequest) {
  const results = {
    virusTotal: {
      configured: !!process.env.VIRUSTOTAL_API_KEY,
      working: false,
      message: '',
      testUrl: 'http://example.com'
    },
    googleSafeBrowsing: {
      configured: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY,
      working: false,
      message: '',
      testUrl: 'http://example.com'
    },
    openAI: {
      configured: !!process.env.GROQ_API_KEY,
      working: false,
      message: '',
      model: 'llama-3.3-70b-versatile (Groq - FREE!)'
    },
    database: {
      configured: !!process.env.DATABASE_URL,
      working: false,
      message: ''
    }
  };

  // Test VirusTotal
  if (results.virusTotal.configured) {
    try {
      const vtResult = await VirusTotalService.analyzeURL('http://example.com');
      results.virusTotal.working = true;
      results.virusTotal.message = `Successfully scanned. Engines: ${vtResult.totalEngines}, Detections: ${vtResult.detectionCount}`;
    } catch (error) {
      results.virusTotal.message = error instanceof Error ? error.message : 'Test failed';
    }
  } else {
    results.virusTotal.message = 'API key not configured in .env.local';
  }

  // Test Google Safe Browsing
  if (results.googleSafeBrowsing.configured) {
    try {
      const gsbResult = await GoogleSafeBrowsingService.checkURL('http://example.com');
      results.googleSafeBrowsing.working = true;
      results.googleSafeBrowsing.message = `API responding. Threat detected: ${gsbResult.isThreat}`;
    } catch (error) {
      results.googleSafeBrowsing.message = error instanceof Error ? error.message : 'Test failed';
    }
  } else {
    results.googleSafeBrowsing.message = 'API key not configured in .env.local';
  }

  // Test Groq AI (FREE!)
  if (results.openAI.configured) {
    try {
      const groq = new Groq({
        apiKey: process.env.GROQ_API_KEY,
      });

      const completion = await groq.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: 'Say "API Working" in 2 words' }],
        max_tokens: 10,
      });

      results.openAI.working = true;
      results.openAI.message = `Llama 3.1 responding: "${completion.choices[0]?.message?.content}"`;
    } catch (error) {
      results.openAI.message = error instanceof Error ? error.message : 'Test failed';
    }
  } else {
    results.openAI.message = 'API key not configured in .env.local - Get free key at https://console.groq.com';
  }

  // Test Database
  if (results.database.configured) {
    try {
      const { db } = await import('@/db');
      const { modelConfigs } = await import('@/db/schema');
      const { count } = await import('drizzle-orm');
      
      const [result] = await db.select({ value: count() }).from(modelConfigs);
      results.database.working = true;
      results.database.message = `Connected. Model configs: ${result.value}`;
    } catch (error) {
      results.database.message = error instanceof Error ? error.message : 'Connection failed';
    }
  } else {
    results.database.message = 'DATABASE_URL not configured';
  }

  // Summary
  const workingCount = Object.values(results).filter(r => r.working).length;
  const totalCount = Object.keys(results).length;

  return NextResponse.json({
    success: true,
    summary: {
      working: workingCount,
      total: totalCount,
      status: workingCount === totalCount ? 'All systems operational' :
              workingCount > 0 ? 'Partial functionality' : 'Services unavailable'
    },
    services: results,
    timestamp: new Date().toISOString()
  });
}
