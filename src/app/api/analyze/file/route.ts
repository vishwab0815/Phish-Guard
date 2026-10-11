/**
 * File Malware Analysis API
 * Upload and scan files for malware using comprehensive multi-layer detection
 */

import { NextRequest, NextResponse } from 'next/server';
import { MasterMalwareDetector } from '@/services/malware/masterMalwareDetector';
import { ensureUser, getSessionUserId } from '@/lib/session';
import { enforceRateLimit, LIMITS } from '@/lib/apiGuard';
import { jsonError, rejectIfTooLarge, serverError, saveScan } from '../../_lib/http';

export const runtime = 'nodejs';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_REQUEST_SIZE = MAX_FILE_SIZE + 64 * 1024; // multipart overhead
const TOO_LARGE = 'File is too large. The maximum size is 10 MB.';

/** POST /api/analyze/file — multipart/form-data with a `file` field */
export async function POST(request: NextRequest) {
  try {
    // Reject oversized uploads before reading the body into memory.
    const tooLarge = rejectIfTooLarge(request, MAX_REQUEST_SIZE);
    if (tooLarge) return jsonError(TOO_LARGE, 413);

    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'analyze', LIMITS.analyze);
    if (limited) return limited;

    let formData: FormData;
    try {
      formData = await request.formData();
    } catch {
      return jsonError('Upload a file using multipart/form-data', 400);
    }

    const file = formData.get('file');
    if (!file || typeof file === 'string') return jsonError('No file provided', 400);
    if (file.size > MAX_FILE_SIZE) return jsonError(TOO_LARGE, 413);
    if (file.size === 0) return jsonError('File is empty', 400);

    const fileName = (file.name || 'upload').slice(0, 255);
    const buffer = Buffer.from(await file.arrayBuffer());

    const canSave = await ensureUser(userId);
    const analysis = await MasterMalwareDetector.analyzeFile(buffer, fileName, userId);

    // Record the scan in the user's history (file contents are never stored).
    const saved = canSave ? await saveScan({
        userId,
        type: 'FILE',
        target: fileName,
        confidence: analysis.confidence,
        threatLevel: analysis.threatLevel,
        riskScore: analysis.riskScore,
        indicators: analysis.indicators,
        recommendations: analysis.recommendations,
        scanDuration: analysis.scanDuration,
        metadata: { file_type: analysis.fileType, file_size: analysis.fileSize, summary: analysis.summary },
      }) : null;
    const scanId = saved?.id ?? null;

    return NextResponse.json({
      success: true,
      analysis: {
        id: scanId,
        saved: scanId !== null,
        file: {
          name: analysis.fileName,
          size: analysis.fileSize,
          type: analysis.fileType,
        },
        result: {
          is_malicious: analysis.isMalicious,
          threat_level: analysis.threatLevel,
          risk_score: analysis.riskScore,
          confidence: analysis.confidence,
          indicators: analysis.indicators,
          recommendations: analysis.recommendations,
          notes: analysis.notes ?? [],
        },
        summary: {
          total_detections: analysis.summary.totalDetections,
          signature_matches: analysis.summary.signatureMatches,
          behavioral_flags: analysis.summary.behavioralFlags,
          external_engine_detections: analysis.summary.externalEngineDetections,
        },
        layers: {
          static_analysis: analysis.analysisLayers.staticAnalysis ? 'completed' : 'skipped',
          document_analysis: analysis.analysisLayers.documentAnalysis ? 'completed' : 'skipped',
          script_analysis: analysis.analysisLayers.scriptAnalysis ? 'completed' : 'skipped',
          virus_total: analysis.analysisLayers.virusTotal ? 'completed' : 'skipped',
        },
        scan_duration_ms: analysis.scanDuration,
        timestamp: analysis.timestamp.toISOString(),
      },
    });
  } catch (error) {
    return serverError('POST /api/analyze/file', error, 'Failed to analyze file');
  }
}

const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;

/** GET /api/analyze/file?hash=<md5|sha1|sha256> — quick hash lookup */
export async function GET(request: NextRequest) {
  try {
    const userId = await getSessionUserId();
    const limited = await enforceRateLimit(request, userId, 'threat-intel', LIMITS.threatIntel);
    if (limited) return limited;

    const hash = request.nextUrl.searchParams.get('hash')?.trim() ?? '';
    if (!HASH_RE.test(hash)) {
      return jsonError('Provide an MD5, SHA-1 or SHA-256 hash (hex)', 400);
    }

    const result = await MasterMalwareDetector.quickCheck(hash.toLowerCase());

    return NextResponse.json({
      success: true,
      result: {
        hash,
        is_malicious: result.isMalicious,
        status: result.status,
        source: result.source || 'local_cache',
      },
    });
  } catch (error) {
    return serverError('GET /api/analyze/file', error, 'Failed to check file hash');
  }
}
