// Environment variables are loaded via --env-file flag in package.json
import { db } from './index';
import { modelConfigs, trustedDomains, blockedDomains, threatIntelligence } from './schema';

if (!process.env.DATABASE_URL) {
  console.error('❌ ERROR: DATABASE_URL is not defined in the environment.');
  process.exit(1);
}

const modelDefaults = [
  {
    modelId: 'url_analyzer_v1',
    name: 'URL Analyzer',
    description: 'Advanced URL threat detection and analysis with domain reputation checking, SSL verification, and content scanning',
    version: '1.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.7,
    features: ['domain_analysis', 'ssl_check', 'content_scan', 'reputation_lookup', 'typosquatting_detection'],
  },
  {
    modelId: 'email_scanner_v2',
    name: 'Email Scanner',
    description: 'Comprehensive email phishing detection with header analysis, attachment scanning, and NLP-based content analysis',
    version: '2.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.8,
    features: ['header_analysis', 'attachment_scan', 'content_nlp', 'sender_reputation', 'spf_dkim_check', 'link_analysis'],
  },
  {
    modelId: 'file_detector_v1',
    name: 'File Detector',
    description: 'Malicious file detection system with signature analysis, metadata inspection, and behavioral pattern recognition',
    version: '1.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.75,
    features: ['file_signature', 'metadata_analysis', 'behavioral_patterns', 'entropy_analysis', 'pe_analysis'],
  },
  {
    modelId: 'message_classifier_v1',
    name: 'Message Classifier',
    description: 'SMS and message phishing detection with social engineering pattern recognition and urgency analysis',
    version: '1.0.0',
    state: 'ACTIVE' as const,
    confidenceThreshold: 0.85,
    features: ['nlp_analysis', 'social_engineering_detection', 'urgency_patterns', 'financial_indicators', 'link_detection'],
  },
];

const trustedDomainsSeed = [
  { domain: 'google.com', reason: 'Major tech company', addedBy: 'system' },
  { domain: 'microsoft.com', reason: 'Major tech company', addedBy: 'system' },
  { domain: 'apple.com', reason: 'Major tech company', addedBy: 'system' },
  { domain: 'amazon.com', reason: 'Major e-commerce platform', addedBy: 'system' },
  { domain: 'github.com', reason: 'Developer platform', addedBy: 'system' },
  { domain: 'stackoverflow.com', reason: 'Developer community', addedBy: 'system' },
  { domain: 'linkedin.com', reason: 'Professional network', addedBy: 'system' },
  { domain: 'facebook.com', reason: 'Social media platform', addedBy: 'system' },
  { domain: 'twitter.com', reason: 'Social media platform', addedBy: 'system' },
  { domain: 'x.com', reason: 'Social media platform', addedBy: 'system' },
];

const blockedDomainsSeed = [
  { domain: 'phishing-example.com', reason: 'Known phishing domain - impersonates banking sites', addedBy: 'system' },
  { domain: 'malware-test.net', reason: 'Malware distribution site', addedBy: 'system' },
  { domain: 'scam-lottery.org', reason: 'Lottery scam operations', addedBy: 'system' },
  { domain: 'fake-paypal-verify.com', reason: 'PayPal phishing campaign', addedBy: 'system' },
  { domain: 'secure-amazon-update.net', reason: 'Amazon impersonation', addedBy: 'system' },
];

const threatIntelligenceSeed = [
  {
    domain: 'suspicious-bank-login.com',
    reputation: 15.0,
    sources: ['URLhaus', 'PhishTank', 'OpenPhish'],
    indicators: {
      blacklisted: true,
      malware_hosting: false,
      phishing_reports: 47,
      first_seen: '2024-01-15',
      last_seen: '2024-12-01',
      categories: ['phishing', 'banking-fraud'],
    },
  },
  {
    domain: 'legit-company.com',
    reputation: 95.0,
    sources: ['Google Safe Browsing', 'Norton SafeWeb'],
    indicators: {
      blacklisted: false,
      malware_hosting: false,
      phishing_reports: 0,
      ssl_valid: true,
      domain_age_days: 3650,
      categories: ['business', 'technology'],
    },
  },
];

async function main() {
  console.log('🌱 Starting database seeding with Drizzle...');

  try {
    console.log('🗑️  Cleaning up existing seed data...');
    await db.delete(threatIntelligence);
    await db.delete(blockedDomains);
    await db.delete(trustedDomains);
    await db.delete(modelConfigs);

    console.log('📊 Seeding AI model configurations...');
    const now = new Date();
    for (const model of modelDefaults) {
      await db.insert(modelConfigs).values({
        id: crypto.randomUUID(),
        ...model,
        initializedAt: now,
        updatedAt: now,
      }).onConflictDoUpdate({
        target: modelConfigs.modelId,
        set: {
          ...model,
          updatedAt: now,
        },
      });
      console.log(`  ✅ Created model: ${model.name}`);
    }

    console.log('🛡️  Seeding trusted domains...');
    for (const domain of trustedDomainsSeed) {
      await db.insert(trustedDomains).values({
        id: crypto.randomUUID(),
        ...domain,
      }).onConflictDoUpdate({
        target: trustedDomains.domain,
        set: domain,
      });
    }

    console.log('🚫 Seeding blocked domains...');
    for (const domain of blockedDomainsSeed) {
      await db.insert(blockedDomains).values({
        id: crypto.randomUUID(),
        ...domain,
      }).onConflictDoUpdate({
        target: blockedDomains.domain,
        set: domain,
      });
    }

    console.log('🔍 Seeding threat intelligence data...');
    for (const intel of threatIntelligenceSeed) {
      await db.insert(threatIntelligence).values({
        id: crypto.randomUUID(),
        ...intel,
      }).onConflictDoUpdate({
        target: threatIntelligence.domain,
        set: intel,
      });
    }

    console.log('\n✨ Database seeding completed successfully!');
  } catch (error) {
    console.error('❌ Error during seeding:', error);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
