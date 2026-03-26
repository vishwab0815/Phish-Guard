import { NextResponse } from 'next/server';
import { db } from '@/db';
import { modelConfigs } from '@/db/schema';

const MODEL_DEFAULTS = [
  {
    modelId: 'url_analyzer_v1',
    name: 'URL Analyzer',
    description: 'Advanced URL threat detection and analysis',
    version: '1.0.0',
    confidenceThreshold: 0.7,
    features: ['domain_analysis', 'ssl_check', 'content_scan', 'reputation_lookup'],
  },
  {
    modelId: 'email_scanner_v2',
    name: 'Email Scanner',
    description: 'Comprehensive email phishing detection',
    version: '2.0.0',
    confidenceThreshold: 0.8,
    features: ['header_analysis', 'attachment_scan', 'content_nlp', 'sender_reputation'],
  },
  {
    modelId: 'file_detector_v1',
    name: 'File Detector',
    description: 'Malicious file detection system',
    version: '1.0.0',
    confidenceThreshold: 0.75,
    features: ['file_signature', 'metadata_analysis', 'behavioral_patterns'],
  },
  {
    modelId: 'message_classifier_v1',
    name: 'Message Classifier',
    description: 'SMS and message phishing detection',
    version: '1.0.0',
    confidenceThreshold: 0.85,
    features: ['nlp_analysis', 'social_engineering_detection', 'urgency_patterns'],
  },
]

export async function GET() {
  try {
    // Check if models exist, if not create them
    let existingModels = await db.query.modelConfigs.findMany();

    if (existingModels.length === 0) {
      // Initialize models
      await db.insert(modelConfigs).values(
        MODEL_DEFAULTS.map(model => ({
          ...model,
          state: 'ACTIVE' as const,
        }))
      );

      // Fetch the newly created models
      existingModels = await db.query.modelConfigs.findMany();
    }

    return NextResponse.json({
      success: true,
      models: existingModels.map(model => ({
        id: model.modelId,
        config: {
          state: model.state,
          version: model.version,
          confidence_threshold: model.confidenceThreshold,
          features: model.features,
          initialized_at: model.initializedAt?.toISOString(),
          updated_at: model.updatedAt?.toISOString(),
        },
      })),
    });
  } catch (error) {
    console.error('Error fetching models:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch models',
      },
      { status: 500 }
    );
  }
}
