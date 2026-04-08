import { z } from 'zod';

export const storagePathsSchema = z.object({
  root: z.string(),
  reports: z.string(),
  screenshots: z.string(),
  traces: z.string(),
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
export type UrlAnalysisRequest = z.infer<typeof urlAnalysisRequestSchema>;
export type UrlAnalysisResult = z.infer<typeof urlAnalysisResultSchema>;
export type UrlAnalysisJob = z.infer<typeof urlAnalysisJobSchema>;