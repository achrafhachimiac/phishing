import { z } from 'zod';

export const storagePathsSchema = z.object({
  root: z.string(),
  reports: z.string(),
  screenshots: z.string(),
  traces: z.string(),
  sandboxSessions: z.string(),
  downloads: z.string(),
  uploads: z.string(),
  fileReports: z.string(),
});

export const healthResponseSchema = z.object({
  status: z.literal('ok'),
  service: z.literal('phish-hunter-osint-api'),
  timestamp: z.string(),
  storage: storagePathsSchema,
});

export const apiErrorSchema = z.object({
  error: z.string(),
  message: z.string(),
});

export const domainAnalysisRequestSchema = z.object({
  domain: z.string().trim().min(1),
});

export const domainRiskLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH']);

export const domainRdapSchema = z.object({
  registrar: z.string().nullable(),
  createdAt: z.string().nullable(),
  updatedAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
});

export const domainTlsSchema = z.object({
  issuer: z.string().nullable(),
  subject: z.string().nullable(),
  validFrom: z.string().nullable(),
  validTo: z.string().nullable(),
  subjectAltNames: z.array(z.string()),
});

export const domainDnsRecordsSchema = z.object({
  a: z.array(z.string()),
  aaaa: z.array(z.string()),
  mx: z.array(z.string()),
  ns: z.array(z.string()),
  txt: z.array(z.string()),
  caa: z.array(z.string()),
  soa: z.string().nullable(),
});

export const domainMailRecordSchema = z.object({
  present: z.boolean(),
  record: z.string().nullable(),
});

export const domainSpfSchema = domainMailRecordSchema.extend({
  mode: z.string().nullable(),
});

export const domainDmarcSchema = domainMailRecordSchema.extend({
  policy: z.string().nullable(),
});

export const domainMailSecuritySchema = z.object({
  spf: domainSpfSchema,
  dmarc: domainDmarcSchema,
  mtaSts: domainMailRecordSchema,
  tlsRpt: domainMailRecordSchema,
});

export const domainIpIntelligenceSchema = z.object({
  ip: z.string(),
  reverseDns: z.array(z.string()),
  country: z.string().nullable(),
  city: z.string().nullable(),
  asn: z.string().nullable(),
  organization: z.string().nullable(),
});

export const domainInfrastructureSchema = z.object({
  ipAddresses: z.array(z.string()),
  ipIntelligence: z.array(domainIpIntelligenceSchema),
  tls: domainTlsSchema.nullable(),
});

export const domainHistorySchema = z.object({
  waybackSnapshots: z.number().int().nonnegative(),
  firstSeen: z.string().nullable(),
  lastSeen: z.string().nullable(),
});

export const domainCertificateTransparencySchema = z.object({
  certificateCount: z.number().int().nonnegative(),
  observedSubdomains: z.array(z.string()),
  observedCertificates: z.array(z.object({
    commonName: z.string().nullable(),
    issuerName: z.string().nullable(),
    loggedAt: z.string().nullable(),
    notBefore: z.string().nullable(),
    notAfter: z.string().nullable(),
    domains: z.array(z.string()),
  })),
});

export const domainCertificatesSchema = z.object({
  certificateTransparency: domainCertificateTransparencySchema,
});

export const domainOtxReputationSchema = z.object({
  status: z.enum(['listed', 'clean', 'unavailable']),
  pulseCount: z.number().int().nullable(),
  reference: z.string().nullable(),
});

export const domainVirusTotalReputationSchema = z.object({
  status: z.enum(['malicious', 'clean', 'unavailable', 'not_configured']),
  malicious: z.number().int().nullable(),
  suspicious: z.number().int().nullable(),
  reference: z.string().nullable(),
});

export const domainUrlscanReputationSchema = z.object({
  status: z.enum(['submitted', 'clean', 'unavailable', 'not_configured']),
  resultUrl: z.string().nullable(),
});

export const domainAbuseIpDbReputationSchema = z.object({
  status: z.enum(['listed', 'clean', 'unavailable', 'not_configured']),
  confidenceScore: z.number().int().nullable(),
  reports: z.number().int().nullable(),
  reference: z.string().nullable(),
});

export const domainUrlhausHostReputationSchema = z.object({
  status: z.enum(['listed', 'not_listed', 'unavailable']),
  reference: z.string().nullable(),
  urls: z.array(z.string()),
});

export const domainReputationSchema = z.object({
  alienVault: domainOtxReputationSchema,
  virustotal: domainVirusTotalReputationSchema,
  urlscan: domainUrlscanReputationSchema,
  abuseIpDb: domainAbuseIpDbReputationSchema,
  urlhausHost: domainUrlhausHostReputationSchema,
});

export const domainOsintLinksSchema = z.object({
  virustotal: z.string().url(),
  urlscan: z.string().url(),
  viewdns: z.string().url(),
  crtSh: z.string().url(),
  wayback: z.string().url(),
  dnsdumpster: z.string().url(),
  builtwith: z.string().url(),
  alienVault: z.string().url(),
  abuseIpDb: z.string().url(),
  urlhausHost: z.string().url(),
});

export const domainAnalysisResponseSchema = z.object({
  domain: z.string(),
  normalizedDomain: z.string(),
  score: z.number().int().min(0).max(100),
  riskLevel: domainRiskLevelSchema,
  summary: z.string(),
  dns: domainDnsRecordsSchema,
  rdap: domainRdapSchema,
  mailSecurity: domainMailSecuritySchema,
  infrastructure: domainInfrastructureSchema,
  history: domainHistorySchema,
  certificates: domainCertificatesSchema,
  reputation: domainReputationSchema,
  riskFactors: z.array(z.string()),
  osint: domainOsintLinksSchema,
});

export const emailParsingRequestSchema = z.object({
  rawEmail: z.string().trim().min(1),
});

export const emailHeadersSchema = z.object({
  from: z.string().nullable(),
  to: z.string().nullable(),
  subject: z.string().nullable(),
  date: z.string().nullable(),
  messageId: z.string().nullable(),
  returnPath: z.string().nullable(),
});

export const emailAuthenticationSchema = z.object({
  spf: z.string().nullable(),
  dkim: z.string().nullable(),
  dmarc: z.string().nullable(),
});

export const parsedUrlSchema = z.object({
  originalUrl: z.string(),
  decodedUrl: z.string(),
});

export const analyzedUrlSchema = parsedUrlSchema.extend({
  suspicious: z.boolean(),
  reason: z.string(),
});

export const parsedAttachmentSchema = z.object({
  filename: z.string().nullable(),
  contentType: z.string(),
  size: z.number().int().nonnegative(),
  checksum: z.string().nullable(),
});

export const emailParsingResponseSchema = z.object({
  headers: emailHeadersSchema,
  authentication: emailAuthenticationSchema,
  urls: z.array(parsedUrlSchema),
  emailAddresses: z.array(z.string()),
  domains: z.array(z.string()),
  ipAddresses: z.array(z.string()),
  attachments: z.array(parsedAttachmentSchema),
});

export const emailThreatLevelSchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

export const relatedDomainRelationSchema = z.enum(['from', 'return-path', 'url', 'discovered']);

export const relatedDomainSchema = z.object({
  domain: z.string(),
  relation: relatedDomainRelationSchema,
  analysis: domainAnalysisResponseSchema,
});

export const emailAnalysisResponseSchema = z.object({
  headers: emailHeadersSchema,
  authentication: emailAuthenticationSchema,
  urls: z.array(analyzedUrlSchema),
  inconsistencies: z.array(z.string()),
  threatLevel: emailThreatLevelSchema,
  executiveSummary: z.string(),
  emailAddresses: z.array(z.string()),
  domains: z.array(z.string()),
  ipAddresses: z.array(z.string()),
  attachments: z.array(parsedAttachmentSchema),
  relatedDomains: z.array(relatedDomainSchema),
});

export const emlAnalysisRequestSchema = z.object({
  filename: z.string().trim().min(1),
  rawEmail: z.string().trim().min(1),
});

export const emlIgnoredAttachmentSchema = z.object({
  filename: z.string().nullable(),
  contentType: z.string(),
  size: z.number().int().nonnegative(),
  reason: z.enum([
    'empty_attachment',
    'duplicate_attachment',
    'attachment_too_large',
    'attachment_limit_exceeded',
    'total_attachment_size_exceeded',
  ]),
});

export const emlAnalysisJobSchema = z.object({
  jobId: z.string(),
  status: z.enum(['queued', 'parsing', 'analyzing_files', 'completed', 'failed']),
  filename: z.string(),
  emailAnalysis: emailAnalysisResponseSchema.nullable(),
  attachmentCount: z.number().int().nonnegative(),
  analyzedAttachmentCount: z.number().int().nonnegative(),
  ignoredAttachments: z.array(emlIgnoredAttachmentSchema),
  fileAnalysisJobId: z.string().nullable(),
  attachmentResults: z.array(z.lazy(() => fileStaticAnalysisResultSchema)),
  consolidatedThreatLevel: emailThreatLevelSchema.nullable(),
  consolidatedRiskScore: z.number().int().min(0).max(100).nullable(),
  executiveSummary: z.string().nullable(),
  error: z.string().nullable(),
});

export const urlAnalysisRequestSchema = z.object({
  urls: z.array(z.string().trim().min(1)).min(1),
});

export const urlAnalysisResultSchema = z.object({
  externalScans: z.object({
    urlhaus: z.object({
      status: z.enum(['listed', 'not_listed', 'unavailable']),
      reference: z.string().nullable(),
      tags: z.array(z.string()),
      permalink: z.string().nullable(),
    }),
    virustotal: z.object({
      status: z.enum(['malicious', 'clean', 'unavailable', 'not_configured']),
      malicious: z.number().int().nullable(),
      suspicious: z.number().int().nullable(),
      reference: z.string().nullable(),
    }),
    urlscan: z.object({
      status: z.enum(['submitted', 'not_configured', 'unavailable']),
      resultUrl: z.string().nullable(),
    }),
    alienVault: z.object({
      status: z.enum(['listed', 'clean', 'unavailable']),
      pulseCount: z.number().int().nullable(),
      reference: z.string().nullable(),
    }),
  }),
  originalUrl: z.string().url(),
  finalUrl: z.string().nullable(),
  title: z.string().nullable(),
  screenshotPath: z.string().nullable(),
  tracePath: z.string().nullable(),
  redirectChain: z.array(z.string()),
  requestedDomains: z.array(z.string()),
  scriptUrls: z.array(z.string()),
  consoleErrors: z.array(z.string()),
  status: z.enum(['completed', 'failed']),
  error: z.string().nullable(),
});

export const urlAnalysisJobSchema = z.object({
  jobId: z.string(),
  status: z.enum(['queued', 'running', 'completed', 'failed']),
  queuedUrls: z.array(z.string().url()),
  results: z.array(urlAnalysisResultSchema),
});

export const browserSandboxRequestSchema = z.object({
  url: z.string().trim().min(1),
});

export const browserSandboxAccessSchema = z.object({
  mode: z.enum(['embedded', 'external', 'none']),
  url: z.string().nullable(),
  note: z.string().nullable(),
});

export const browserSandboxSessionSchema = z.object({
  provider: z.string(),
  sessionId: z.string(),
  status: z.enum(['ready', 'stopped', 'unavailable']),
  startedAt: z.string(),
  stoppedAt: z.string().nullable(),
  runtime: z.object({
    displayNumber: z.number().int().nonnegative(),
    vncPort: z.number().int().positive(),
    novncPort: z.number().int().positive(),
    sessionDirectory: z.string(),
  }),
  access: browserSandboxAccessSchema,
});

export const browserSandboxArtifactSchema = z.object({
  type: z.enum(['screenshot', 'trace', 'download']),
  label: z.string(),
  path: z.string(),
  mimeType: z.string().nullable(),
  size: z.number().int().nonnegative().nullable(),
});

export const observedDownloadSchema = z.object({
  filename: z.string(),
  path: z.string(),
  url: z.string().nullable(),
  sha256: z.string(),
  size: z.number().int().nonnegative(),
});

export const browserSandboxResultSchema = z.object({
  originalUrl: z.string().url(),
  finalUrl: z.string().nullable(),
  title: z.string().nullable(),
  session: browserSandboxSessionSchema,
  access: browserSandboxAccessSchema,
  screenshotPath: z.string().nullable(),
  tracePath: z.string().nullable(),
  redirectChain: z.array(z.string()),
  requestedDomains: z.array(z.string()),
  scriptUrls: z.array(z.string()),
  consoleErrors: z.array(z.string()),
  downloads: z.array(observedDownloadSchema),
  artifacts: z.array(browserSandboxArtifactSchema),
  status: z.enum(['completed', 'failed', 'stopped']),
  error: z.string().nullable(),
});

export const browserSandboxJobSchema = z.object({
  jobId: z.string(),
  status: z.enum(['queued', 'running', 'completed', 'failed', 'stopped']),
  requestedUrl: z.string().url(),
  expiresAt: z.string().nullable(),
  session: browserSandboxSessionSchema.nullable(),
  result: browserSandboxResultSchema.nullable(),
});

export const fileUploadSchema = z.object({
  filename: z.string().trim().min(1),
  contentBase64: z.string().trim().min(1),
  contentType: z.string().trim().min(1).nullable().optional(),
});

export const fileAnalysisRequestSchema = z.object({
  files: z.array(fileUploadSchema).min(1),
});

export const fileIndicatorSchema = z.object({
  kind: z.enum([
    'embedded_url',
    'pdf_javascript',
    'office_macro',
    'archive',
    'double_extension',
    'executable_extension',
    'pe_header',
    'suspicious_script',
    'clamav_match',
    'yara_match',
    'ioc_malicious_url',
    'ioc_suspicious_url',
    'ioc_malicious_domain',
    'ioc_suspicious_domain',
  ]),
  severity: z.enum(['low', 'medium', 'high']),
  value: z.string(),
});

export interface ArchiveTreeNode {
  path: string;
  filename: string;
  isDirectory: boolean;
  size?: number | null;
  detectedType?: string | null;
  indicators: z.infer<typeof fileIndicatorSchema>[];
  children: ArchiveTreeNode[];
}

export const archiveTreeNodeSchema: z.ZodType<ArchiveTreeNode> = z.lazy(() => z.object({
  path: z.string(),
  filename: z.string(),
  isDirectory: z.boolean(),
  size: z.number().int().nonnegative().nullable(),
  detectedType: z.string().nullable(),
  indicators: z.array(fileIndicatorSchema),
  children: z.array(archiveTreeNodeSchema),
}));

export const extractedArchiveTreeSchema = z.object({
  totalEntries: z.number().int().nonnegative(),
  maxDepth: z.number().int().nonnegative(),
  totalExtractedSize: z.number().int().nonnegative(),
  truncated: z.boolean(),
  warnings: z.array(z.string()),
  root: archiveTreeNodeSchema,
});

export const fileRiskFactorSchema = z.object({
  label: z.string(),
  severity: z.enum(['low', 'medium', 'high']),
  contribution: z.number().int().nonnegative(),
  evidence: z.string(),
});

export const fileRiskScoreBreakdownSchema = z.object({
  totalScore: z.number().int().min(0).max(100),
  thresholds: z.object({
    suspicious: z.number().int().min(0).max(100),
    malicious: z.number().int().min(0).max(100),
  }),
  factors: z.array(fileRiskFactorSchema),
});

export const fileIocProviderResultSchema = z.object({
  provider: z.enum(['urlhaus', 'virustotal', 'urlscan', 'alienvault', 'abuseipdb', 'urlhaus_host']),
  status: z.enum(['listed', 'malicious', 'suspicious', 'clean', 'submitted', 'not_listed', 'unavailable', 'not_configured']),
  detail: z.string().nullable(),
  reference: z.string().nullable(),
});

export const fileEnrichedIocSchema = z.object({
  type: z.enum(['url', 'domain']),
  value: z.string(),
  derivedFrom: z.string().nullable(),
  verdict: z.enum(['malicious', 'suspicious', 'clean', 'unavailable', 'pending']),
  summary: z.string(),
  providerResults: z.array(fileIocProviderResultSchema),
});

export const fileIocEnrichmentSchema = z.object({
  status: z.enum(['pending', 'running', 'completed', 'unavailable']),
  extractedUrls: z.array(z.string()),
  extractedDomains: z.array(z.string()),
  results: z.array(fileEnrichedIocSchema),
  summary: z.string(),
  updatedAt: z.string().nullable(),
});

export const fileArtifactSchema = z.object({
  type: z.enum(['upload', 'report', 'extracted']),
  label: z.string(),
  path: z.string(),
  mimeType: z.string().nullable(),
  size: z.number().int().nonnegative().nullable(),
});

export const fileParserReportSchema = z.object({
  parser: z.enum(['pdf', 'office-openxml', 'archive', 'pe', 'script', 'generic']),
  summary: z.string(),
  details: z.array(z.string()),
  snippets: z.array(z.string()).default([]),
  extractedTree: extractedArchiveTreeSchema.optional(),
});

export const fileExternalScanSchema = z.object({
  virustotal: z.object({
    status: z.enum(['pending', 'malicious', 'clean', 'unavailable', 'not_configured']),
    malicious: z.number().int().nullable(),
    suspicious: z.number().int().nullable(),
    reference: z.string().nullable(),
  }),
  clamav: z.object({
    status: z.enum(['malicious', 'clean', 'error', 'unavailable', 'not_configured']),
    signature: z.string().nullable(),
    engine: z.string().nullable(),
    detail: z.string().nullable(),
  }),
  yara: z.object({
    status: z.enum(['match', 'clean', 'error', 'unavailable', 'not_configured']),
    rules: z.array(z.string()),
    detail: z.string().nullable(),
  }),
});

export const fileStaticAnalysisResultSchema = z.object({
  filename: z.string(),
  contentType: z.string().nullable(),
  detectedType: z.string(),
  extension: z.string().nullable(),
  size: z.number().int().nonnegative(),
  sha256: z.string(),
  extractedUrls: z.array(z.string()),
  indicators: z.array(fileIndicatorSchema),
  parserReports: z.array(fileParserReportSchema),
  riskScore: z.number().int().min(0).max(100),
  riskScoreBreakdown: fileRiskScoreBreakdownSchema,
  iocEnrichment: fileIocEnrichmentSchema,
  verdict: z.enum(['clean', 'suspicious', 'malicious']),
  summary: z.string(),
  storagePath: z.string().nullable(),
  artifacts: z.array(fileArtifactSchema),
  externalScans: fileExternalScanSchema,
});

export const fileAnalysisJobSchema = z.object({
  jobId: z.string(),
  status: z.enum(['queued', 'running', 'completed', 'failed']),
  queuedFiles: z.array(z.string()),
  results: z.array(fileStaticAnalysisResultSchema),
});

export type StoragePaths = z.infer<typeof storagePathsSchema>;
export type HealthResponse = z.infer<typeof healthResponseSchema>;
export type ApiError = z.infer<typeof apiErrorSchema>;
export type DomainAnalysisRequest = z.infer<typeof domainAnalysisRequestSchema>;
export type DomainAnalysisResponse = z.infer<typeof domainAnalysisResponseSchema>;
export type DomainDnsRecords = z.infer<typeof domainDnsRecordsSchema>;
export type DomainRdap = z.infer<typeof domainRdapSchema>;
export type DomainTls = z.infer<typeof domainTlsSchema>;
export type DomainMailSecurity = z.infer<typeof domainMailSecuritySchema>;
export type DomainIpIntelligence = z.infer<typeof domainIpIntelligenceSchema>;
export type DomainHistory = z.infer<typeof domainHistorySchema>;
export type DomainCertificates = z.infer<typeof domainCertificatesSchema>;
export type DomainReputation = z.infer<typeof domainReputationSchema>;
export type EmailParsingRequest = z.infer<typeof emailParsingRequestSchema>;
export type EmailParsingResponse = z.infer<typeof emailParsingResponseSchema>;
export type EmailAnalysisResponse = z.infer<typeof emailAnalysisResponseSchema>;
export type EmlAnalysisRequest = z.infer<typeof emlAnalysisRequestSchema>;
export type EmlIgnoredAttachment = z.infer<typeof emlIgnoredAttachmentSchema>;
export type EmlAnalysisJob = z.infer<typeof emlAnalysisJobSchema>;
export type UrlAnalysisRequest = z.infer<typeof urlAnalysisRequestSchema>;
export type UrlAnalysisResult = z.infer<typeof urlAnalysisResultSchema>;
export type UrlAnalysisJob = z.infer<typeof urlAnalysisJobSchema>;
export type BrowserSandboxRequest = z.infer<typeof browserSandboxRequestSchema>;
export type BrowserSandboxArtifact = z.infer<typeof browserSandboxArtifactSchema>;
export type BrowserSandboxAccess = z.infer<typeof browserSandboxAccessSchema>;
export type BrowserSandboxSession = z.infer<typeof browserSandboxSessionSchema>;
export type ObservedDownload = z.infer<typeof observedDownloadSchema>;
export type BrowserSandboxResult = z.infer<typeof browserSandboxResultSchema>;
export type BrowserSandboxJob = z.infer<typeof browserSandboxJobSchema>;
export type FileUpload = z.infer<typeof fileUploadSchema>;
export type FileAnalysisRequest = z.infer<typeof fileAnalysisRequestSchema>;
export type FileIndicator = z.infer<typeof fileIndicatorSchema>;
export type ExtractedArchiveTree = z.infer<typeof extractedArchiveTreeSchema>;
export type FileRiskFactor = z.infer<typeof fileRiskFactorSchema>;
export type FileRiskScoreBreakdown = z.infer<typeof fileRiskScoreBreakdownSchema>;
export type FileIocProviderResult = z.infer<typeof fileIocProviderResultSchema>;
export type FileEnrichedIoc = z.infer<typeof fileEnrichedIocSchema>;
export type FileIocEnrichment = z.infer<typeof fileIocEnrichmentSchema>;
export type FileArtifact = z.infer<typeof fileArtifactSchema>;
export type FileParserReport = z.infer<typeof fileParserReportSchema>;
export type FileExternalScan = z.infer<typeof fileExternalScanSchema>;
export type FileStaticAnalysisResult = z.infer<typeof fileStaticAnalysisResultSchema>;
export type FileAnalysisJob = z.infer<typeof fileAnalysisJobSchema>;