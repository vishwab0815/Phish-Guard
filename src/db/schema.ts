import { pgTable, text, timestamp, boolean, doublePrecision, jsonb, uuid, integer, pgEnum } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// Enums
export const scanTypeEnum = pgEnum('ScanType', ['URL', 'EMAIL', 'MESSAGE', 'FILE']);
export const scanStatusEnum = pgEnum('ScanStatus', ['PENDING', 'IN_PROGRESS', 'COMPLETED', 'QUARANTINED', 'BLOCKED', 'ERROR']);
export const threatLevelEnum = pgEnum('ThreatLevel', ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
export type ThreatLevel = typeof threatLevelEnum.enumValues[number];
export const modelStateEnum = pgEnum('ModelState', ['ACTIVE', 'INACTIVE', 'MAINTENANCE']);
export const jobStatusEnum = pgEnum('JobStatus', ['PENDING', 'QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT']);

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  email: text('email').unique(),
  name: text('name'),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

export const userSettings = pgTable('user_settings', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: text('userId').unique().notNull().references(() => users.id, { onDelete: 'cascade' }),
  
  // Detection Settings
  realTimeScanning: boolean('realTimeScanning').default(true),
  autoQuarantine: boolean('autoQuarantine').default(true),
  detectionSensitivity: integer('detectionSensitivity').default(50),
  defaultAction: text('defaultAction').default('warn'),
  
  // Notifications
  emailAlerts: boolean('emailAlerts').default(true),
  desktopAlerts: boolean('desktopAlerts').default(true),
  dailySummary: boolean('dailySummary').default(false),
  
  // API Configuration
  apiEndpoint: text('apiEndpoint'),
  apiKey: text('apiKey'),
  rateLimit: integer('rateLimit').default(100),
  
  // Security
  autoUpdate: boolean('autoUpdate').default(true),
  dataRetentionDays: integer('dataRetentionDays').default(30),
  securityLevel: text('securityLevel').default('medium'),
  
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

export const scanResults = pgTable('scan_results', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: text('userId').references(() => users.id, { onDelete: 'set null' }),
  
  type: scanTypeEnum('type').notNull(),
  target: text('target').notNull(),
  status: scanStatusEnum('status').default('COMPLETED'),
  
  confidence: doublePrecision('confidence').notNull(),
  threatLevel: threatLevelEnum('threatLevel').notNull(),
  riskScore: doublePrecision('riskScore').notNull(),
  indicators: text('indicators').array(),
  recommendations: text('recommendations').array(),
  
  modelVersion: text('modelVersion').default('v1.0'),
  scanDuration: integer('scanDuration'),
  timestamp: timestamp('timestamp').defaultNow(),
  metadata: jsonb('metadata'),
  
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

export const modelConfigs = pgTable('model_configs', {
  id: uuid('id').defaultRandom().primaryKey(),
  modelId: text('modelId').unique().notNull(),
  name: text('name').notNull(),
  description: text('description'),
  state: modelStateEnum('state').default('ACTIVE'),
  version: text('version').notNull(),
  confidenceThreshold: doublePrecision('confidenceThreshold').default(0.7),
  features: text('features').array(),
  initializedAt: timestamp('initializedAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
  lastUsed: timestamp('lastUsed'),
});

export const trustedDomains = pgTable('trusted_domains', {
  id: uuid('id').defaultRandom().primaryKey(),
  domain: text('domain').unique().notNull(),
  addedBy: text('addedBy'),
  reason: text('reason'),
  createdAt: timestamp('createdAt').defaultNow(),
});

export const blockedDomains = pgTable('blocked_domains', {
  id: uuid('id').defaultRandom().primaryKey(),
  domain: text('domain').unique().notNull(),
  reason: text('reason').notNull(),
  addedBy: text('addedBy'),
  createdAt: timestamp('createdAt').defaultNow(),
});

export const threatIntelligence = pgTable('threat_intelligence', {
  id: uuid('id').defaultRandom().primaryKey(),
  domain: text('domain').unique().notNull(),
  reputation: doublePrecision('reputation').notNull(),
  lastChecked: timestamp('lastChecked').defaultNow(),
  sources: text('sources').array(),
  indicators: jsonb('indicators'),
});

export const domainIntelligence = pgTable('domain_intelligence', {
  id: uuid('id').defaultRandom().primaryKey(),
  domain: text('domain').unique().notNull(),
  
  // WHOIS Data
  registrar: text('registrar'),
  createdDate: timestamp('createdDate'),
  expiresDate: timestamp('expiresDate'),
  updatedDate: timestamp('updatedDate'),
  registrantName: text('registrantName'),
  registrantOrg: text('registrantOrg'),
  domainAge: integer('domainAge'),
  
  // DNS Data
  ipAddresses: text('ipAddresses').array(),
  mxRecords: text('mxRecords').array(),
  nsRecords: text('nsRecords').array(),
  txtRecords: text('txtRecords').array(),
  
  // Risk & Reputation
  riskScore: doublePrecision('riskScore').default(50),
  isKnownPhishing: boolean('isKnownPhishing').default(false),
  isKnownMalware: boolean('isKnownMalware').default(false),
  reportCount: integer('reportCount').default(0),
  
  lastChecked: timestamp('lastChecked').defaultNow(),
  cacheExpiry: timestamp('cacheExpiry').defaultNow(),
});

export const certificateInfo = pgTable('certificate_info', {
  id: uuid('id').defaultRandom().primaryKey(),
  domain: text('domain').notNull(),
  
  // Certificate Details
  issuer: text('issuer').notNull(),
  subject: text('subject').notNull(),
  validFrom: timestamp('validFrom').notNull(),
  validUntil: timestamp('validUntil').notNull(),
  serialNumber: text('serialNumber').notNull(),
  fingerprint: text('fingerprint').unique().notNull(),
  algorithm: text('algorithm').notNull(),
  keySize: integer('keySize'),
  
  // Security Analysis
  isSelfSigned: boolean('isSelfSigned').default(false),
  isWildcard: boolean('isWildcard').default(false),
  isEV: boolean('isEV').default(false),
  chainValid: boolean('chainValid').default(true),
  chainLength: integer('chainLength').default(1),
  isRevoked: boolean('isRevoked').default(false),
  hasWeakCipher: boolean('hasWeakCipher').default(false),
  trustScore: doublePrecision('trustScore').default(50),
  sanDomains: text('sanDomains').array(),
  ctLogged: boolean('ctLogged').default(false),
  ctLogCount: integer('ctLogCount').default(0),
  
  lastChecked: timestamp('lastChecked').defaultNow(),
  checkCount: integer('checkCount').default(1),
});

export const ipIntelligence = pgTable('ip_intelligence', {
  id: uuid('id').defaultRandom().primaryKey(),
  ipAddress: text('ipAddress').unique().notNull(),
  
  // Geolocation
  country: text('country'),
  countryCode: text('countryCode'),
  region: text('region'),
  city: text('city'),
  latitude: doublePrecision('latitude'),
  longitude: doublePrecision('longitude'),
  timezone: text('timezone'),
  
  // Network Information
  asn: text('asn'),
  asnOrg: text('asnOrg'),
  isp: text('isp'),
  organization: text('organization'),
  
  // Security & Reputation
  abuseScore: integer('abuseScore').default(0),
  threatScore: doublePrecision('threatScore').default(0),
  isProxy: boolean('isProxy').default(false),
  isVPN: boolean('isVPN').default(false),
  isTor: boolean('isTor').default(false),
  isDataCenter: boolean('isDataCenter').default(false),
  isHosting: boolean('isHosting').default(false),
  isBlacklisted: boolean('isBlacklisted').default(false),
  blacklistCount: integer('blacklistCount').default(0),
  isBot: boolean('isBot').default(false),
  
  firstSeen: timestamp('firstSeen').defaultNow(),
  lastChecked: timestamp('lastChecked').defaultNow(),
  checkCount: integer('checkCount').default(1),
});

export const scanJobs = pgTable('scan_jobs', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: text('userId'),
  type: scanTypeEnum('type').notNull(),
  target: text('target').notNull(),
  status: jobStatusEnum('status').default('PENDING'),
  priority: integer('priority').default(50),
  
  scanResultId: uuid('scanResultId').unique().references(() => scanResults.id),
  
  createdAt: timestamp('createdAt').defaultNow(),
  startedAt: timestamp('startedAt'),
  completedAt: timestamp('completedAt'),
  duration: integer('duration'),
  
  errorMessage: text('errorMessage'),
  retryCount: integer('retryCount').default(0),
  maxRetries: integer('maxRetries').default(3),
  externalJobId: text('externalJobId'),
});

// Relationships
export const usersRelations = relations(users, ({ one, many }) => ({
  settings: one(userSettings, {
    fields: [users.id],
    references: [userSettings.userId],
  }),
  scans: many(scanResults),
  jobs: many(scanJobs),
}));

export const userSettingsRelations = relations(userSettings, ({ one }) => ({
  user: one(users, {
    fields: [userSettings.userId],
    references: [users.id],
  }),
}));

export const scanResultsRelations = relations(scanResults, ({ one }) => ({
  user: one(users, {
    fields: [scanResults.userId],
    references: [users.id],
  }),
  job: one(scanJobs, {
    fields: [scanResults.id],
    references: [scanJobs.scanResultId],
  }),
}));

export const scanJobsRelations = relations(scanJobs, ({ one }) => ({
  user: one(users, {
    fields: [scanJobs.userId],
    references: [users.id],
  }),
  scanResult: one(scanResults, {
    fields: [scanJobs.scanResultId],
    references: [scanResults.id],
  }),
}));

export const externalScanResults = pgTable('external_scan_results', {
  id: uuid('id').defaultRandom().primaryKey(),
  scanResultId: uuid('scanResultId').notNull().references(() => scanResults.id, { onDelete: 'cascade' }),
  provider: text('provider').notNull(),
  rawResponse: jsonb('rawResponse').notNull(),
  
  isPhishing: boolean('isPhishing').default(false),
  isMalware: boolean('isMalware').default(false),
  isSpam: boolean('isSpam').default(false),
  threatType: text('threatType'),
  confidence: doublePrecision('confidence').default(0),
  detectionCount: integer('detectionCount').default(0),
  totalEngines: integer('totalEngines').default(0),
  
  scanDate: timestamp('scanDate').defaultNow(),
  expiresAt: timestamp('expiresAt'),
  createdAt: timestamp('createdAt').defaultNow(),
});

export const fileAnalysis = pgTable('file_analysis', {
  id: uuid('id').defaultRandom().primaryKey(),
  userId: text('userId').references(() => users.id, { onDelete: 'set null' }),
  
  fileName: text('fileName').notNull(),
  fileSize: integer('fileSize').notNull(),
  fileType: text('fileType').notNull(),
  fileExtension: text('fileExtension'),
  
  md5: text('md5').notNull(),
  sha1: text('sha1').notNull(),
  sha256: text('sha256').unique().notNull(),
  ssdeep: text('ssdeep'),
  
  isMalicious: boolean('isMalicious').default(false),
  malwareFamily: text('malwareFamily'),
  threatLevel: threatLevelEnum('threatLevel').default('SAFE'),
  confidence: integer('confidence').default(0),
  riskScore: integer('riskScore').default(0),
  
  detectionNames: text('detectionNames').array(),
  indicators: text('indicators').array(),
  tags: text('tags').array(),
  
  isPacked: boolean('isPacked').default(false),
  isObfuscated: boolean('isObfuscated').default(false),
  isEncrypted: boolean('isEncrypted').default(false),
  hasSuspiciousAPI: boolean('hasSuspiciousAPI').default(false),
  
  virusTotalDetections: integer('virusTotalDetections').default(0),
  virusTotalEngines: integer('virusTotalEngines').default(0),
  
  lastScanned: timestamp('lastScanned').defaultNow(),
  createdAt: timestamp('createdAt').defaultNow(),
});

export const malwareThreatFeed = pgTable('malware_threat_feeds', {
  id: uuid('id').defaultRandom().primaryKey(),
  source: text('source').notNull(),
  indicatorType: text('indicatorType').notNull(), // 'FILE_HASH', 'IP', 'DOMAIN'
  indicatorValue: text('indicatorValue').notNull(),
  threatType: text('threatType'),
  severity: threatLevelEnum('severity').default('MEDIUM'),
  confidence: integer('confidence').default(50),
  firstSeen: timestamp('firstSeen').defaultNow(),
  lastSeen: timestamp('lastSeen').defaultNow(),
  isActive: boolean('isActive').default(true),
  isFalsePositive: boolean('isFalsePositive').default(false),
  metadata: jsonb('metadata'),
});

export const malwareSignature = pgTable('malware_signatures', {
  id: uuid('id').defaultRandom().primaryKey(),
  name: text('name').unique().notNull(),
  description: text('description'),
  type: text('type').notNull(), // 'REGEX', 'BYTE_PATTERN', 'YARA', 'HASH'
  pattern: text('pattern').notNull(),
  threatLevel: threatLevelEnum('threatLevel').default('MEDIUM'),
  category: text('category'),
  malwareFamily: text('malwareFamily'),
  isActive: boolean('isActive').default(true),
  caseSensitive: boolean('caseSensitive').default(false),
  detectionCount: integer('detectionCount').default(0),
  lastDetection: timestamp('lastDetection'),
  createdAt: timestamp('createdAt').defaultNow(),
});

// Additional Relationships
export const externalScanResultsRelations = relations(externalScanResults, ({ one }) => ({
  scanResult: one(scanResults, {
    fields: [externalScanResults.scanResultId],
    references: [scanResults.id],
  }),
}));

export const fileAnalysisRelations = relations(fileAnalysis, ({ one, many }) => ({
  user: one(users, {
    fields: [fileAnalysis.userId],
    references: [users.id],
  }),
}));
