import { createHash, randomUUID } from 'node:crypto';

import {
  emlAnalysisJobSchema,
  emlAnalysisRequestSchema,
  type EmailAnalysisResponse,
  type EmlAnalysisJob,
  type EmlIgnoredAttachment,
  type FileAnalysisJob,
  type FileStaticAnalysisResult,
  type FileUpload,
} from '../../shared/analysis-types.js';
import { analyzeEmail } from './email-analysis.js';
import { enqueueFileAnalysisJob, getFileAnalysisJob } from './file-analysis.js';
import { parseRawEmailForAnalysis, type ParsedEmailForAnalysis } from './email-parser.js';

type EmlAnalysisDependencies = {
  analyzeEmail?: typeof analyzeEmail;
  parseEmailForAnalysis?: typeof parseRawEmailForAnalysis;
  enqueueFileAnalysisJob?: typeof enqueueFileAnalysisJob;
  getFileAnalysisJob?: typeof getFileAnalysisJob;
  createJobId?: () => string;
  wait?: (milliseconds: number) => Promise<void>;
};

const emlAnalysisJobs = new Map<string, EmlAnalysisJob>();
const MAX_ANALYZED_ATTACHMENTS = 20;
const MAX_TOTAL_ANALYZED_ATTACHMENT_SIZE = 25 * 1024 * 1024;
const MAX_SINGLE_ATTACHMENT_SIZE = 10 * 1024 * 1024;
const FILE_JOB_POLL_INTERVAL_MS = 25;

export class EmlAnalysisError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function enqueueEmlAnalysisJob(
  filename: string,
  rawEmail: string,
  dependencies: EmlAnalysisDependencies = {},
): Promise<EmlAnalysisJob> {
  const payload = emlAnalysisRequestSchema.parse({ filename, rawEmail });
  const createJobId = dependencies.createJobId ?? randomUUID;
  const jobId = createJobId();
  const queuedJob = buildBaseJob(jobId, payload.filename);

  emlAnalysisJobs.set(jobId, queuedJob);
  queueMicrotask(async () => {
    try {
      await runEmlAnalysisJob(jobId, payload.filename, payload.rawEmail, dependencies);
    } catch (error) {
      emlAnalysisJobs.set(jobId, buildFailedJob(jobId, payload.filename, error));
    }
  });

  return queuedJob;
}

export async function getEmlAnalysisJob(jobId: string): Promise<EmlAnalysisJob | null> {
  return emlAnalysisJobs.get(jobId) ?? null;
}

export async function createEmlAnalysisJob(
  filename: string,
  rawEmail: string,
  dependencies: EmlAnalysisDependencies = {},
): Promise<EmlAnalysisJob> {
  const payload = emlAnalysisRequestSchema.parse({ filename, rawEmail });
  const createJobId = dependencies.createJobId ?? randomUUID;
  const jobId = createJobId();
  return buildCompletedEmlJob(jobId, payload.filename, payload.rawEmail, dependencies);
}

async function runEmlAnalysisJob(
  jobId: string,
  filename: string,
  rawEmail: string,
  dependencies: EmlAnalysisDependencies,
) {
  const parseEmailForAnalysis = dependencies.parseEmailForAnalysis ?? parseRawEmailForAnalysis;
  const analyzeEmailHandler = dependencies.analyzeEmail ?? analyzeEmail;
  const enqueueFileAnalysisHandler = dependencies.enqueueFileAnalysisJob ?? enqueueFileAnalysisJob;
  const getFileAnalysisJobHandler = dependencies.getFileAnalysisJob ?? getFileAnalysisJob;
  const wait = dependencies.wait ?? defaultWait;

  emlAnalysisJobs.set(jobId, {
    ...buildBaseJob(jobId, filename),
    status: 'parsing',
  });

  const parsedForAnalysis = await parseEmailForAnalysis(rawEmail);
  const emailAnalysis = await analyzeEmailHandler(rawEmail);
  const attachmentSelection = selectAttachmentUploads(parsedForAnalysis);

  if (attachmentSelection.files.length === 0) {
    const consolidated = buildConsolidatedVerdict(emailAnalysis, []);
    emlAnalysisJobs.set(jobId, emlAnalysisJobSchema.parse({
      jobId,
      status: 'completed',
      filename,
      emailAnalysis,
      attachmentCount: emailAnalysis.attachments.length,
      analyzedAttachmentCount: 0,
      ignoredAttachments: attachmentSelection.ignoredAttachments,
      fileAnalysisJobId: null,
      attachmentResults: [],
      consolidatedThreatLevel: consolidated.threatLevel,
      consolidatedRiskScore: consolidated.riskScore,
      executiveSummary: consolidated.summary,
      error: null,
    }));
    return;
  }

  const childJob = await enqueueFileAnalysisHandler(attachmentSelection.files);
  emlAnalysisJobs.set(jobId, emlAnalysisJobSchema.parse({
    jobId,
    status: 'analyzing_files',
    filename,
    emailAnalysis,
    attachmentCount: emailAnalysis.attachments.length,
    analyzedAttachmentCount: attachmentSelection.files.length,
    ignoredAttachments: attachmentSelection.ignoredAttachments,
    fileAnalysisJobId: childJob.jobId,
    attachmentResults: childJob.results,
    consolidatedThreatLevel: null,
    consolidatedRiskScore: null,
    executiveSummary: null,
    error: null,
  }));

  const completedChildJob = await waitForFileAnalysisJob(childJob.jobId, getFileAnalysisJobHandler, wait);
  if (completedChildJob.status === 'failed') {
    throw new EmlAnalysisError('eml_attachment_analysis_failed', 'Attachment analysis failed before completion.');
  }

  const consolidated = buildConsolidatedVerdict(emailAnalysis, completedChildJob.results);
  emlAnalysisJobs.set(jobId, emlAnalysisJobSchema.parse({
    jobId,
    status: 'completed',
    filename,
    emailAnalysis,
    attachmentCount: emailAnalysis.attachments.length,
    analyzedAttachmentCount: attachmentSelection.files.length,
    ignoredAttachments: attachmentSelection.ignoredAttachments,
    fileAnalysisJobId: completedChildJob.jobId,
    attachmentResults: completedChildJob.results,
    consolidatedThreatLevel: consolidated.threatLevel,
    consolidatedRiskScore: consolidated.riskScore,
    executiveSummary: consolidated.summary,
    error: null,
  }));
}

async function buildCompletedEmlJob(
  jobId: string,
  filename: string,
  rawEmail: string,
  dependencies: EmlAnalysisDependencies,
): Promise<EmlAnalysisJob> {
  const parseEmailForAnalysis = dependencies.parseEmailForAnalysis ?? parseRawEmailForAnalysis;
  const analyzeEmailHandler = dependencies.analyzeEmail ?? analyzeEmail;
  const enqueueFileAnalysisHandler = dependencies.enqueueFileAnalysisJob ?? enqueueFileAnalysisJob;
  const getFileAnalysisJobHandler = dependencies.getFileAnalysisJob ?? getFileAnalysisJob;
  const wait = dependencies.wait ?? defaultWait;

  const parsedForAnalysis = await parseEmailForAnalysis(rawEmail);
  const emailAnalysis = await analyzeEmailHandler(rawEmail);
  const attachmentSelection = selectAttachmentUploads(parsedForAnalysis);

  if (attachmentSelection.files.length === 0) {
    const consolidated = buildConsolidatedVerdict(emailAnalysis, []);
    return emlAnalysisJobSchema.parse({
      jobId,
      status: 'completed',
      filename,
      emailAnalysis,
      attachmentCount: emailAnalysis.attachments.length,
      analyzedAttachmentCount: 0,
      ignoredAttachments: attachmentSelection.ignoredAttachments,
      fileAnalysisJobId: null,
      attachmentResults: [],
      consolidatedThreatLevel: consolidated.threatLevel,
      consolidatedRiskScore: consolidated.riskScore,
      executiveSummary: consolidated.summary,
      error: null,
    });
  }

  const childJob = await enqueueFileAnalysisHandler(attachmentSelection.files);
  const completedChildJob = await waitForFileAnalysisJob(childJob.jobId, getFileAnalysisJobHandler, wait);
  if (completedChildJob.status === 'failed') {
    throw new EmlAnalysisError('eml_attachment_analysis_failed', 'Attachment analysis failed before completion.');
  }

  const consolidated = buildConsolidatedVerdict(emailAnalysis, completedChildJob.results);
  return emlAnalysisJobSchema.parse({
    jobId,
    status: 'completed',
    filename,
    emailAnalysis,
    attachmentCount: emailAnalysis.attachments.length,
    analyzedAttachmentCount: attachmentSelection.files.length,
    ignoredAttachments: attachmentSelection.ignoredAttachments,
    fileAnalysisJobId: completedChildJob.jobId,
    attachmentResults: completedChildJob.results,
    consolidatedThreatLevel: consolidated.threatLevel,
    consolidatedRiskScore: consolidated.riskScore,
    executiveSummary: consolidated.summary,
    error: null,
  });
}

async function waitForFileAnalysisJob(
  jobId: string,
  getFileAnalysisJobHandler: typeof getFileAnalysisJob,
  wait: (milliseconds: number) => Promise<void>,
): Promise<FileAnalysisJob> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const job = await getFileAnalysisJobHandler(jobId);
    if (!job) {
      throw new EmlAnalysisError('eml_attachment_job_missing', 'Attachment analysis job could not be found.');
    }

    if (job.status === 'completed' || job.status === 'failed') {
      return job;
    }

    await wait(FILE_JOB_POLL_INTERVAL_MS);
  }

  throw new EmlAnalysisError('eml_attachment_job_timeout', 'Attachment analysis job did not complete in time.');
}

function selectAttachmentUploads(parsedForAnalysis: ParsedEmailForAnalysis) {
  const ignoredAttachments: EmlIgnoredAttachment[] = [];
  const selectedFiles: FileUpload[] = [];
  const seenHashes = new Set<string>();
  let totalSize = 0;

  parsedForAnalysis.attachmentUploads.forEach((attachmentUpload, index) => {
    const attachmentMetadata = parsedForAnalysis.parsedEmail.attachments[index] ?? {
      filename: attachmentUpload.filename,
      contentType: attachmentUpload.contentType ?? 'application/octet-stream',
      size: 0,
    };
    const buffer = Buffer.from(attachmentUpload.contentBase64, 'base64');
    const hash = createHash('sha256').update(buffer).digest('hex');

    if (buffer.byteLength === 0) {
      ignoredAttachments.push(buildIgnoredAttachment(attachmentMetadata, 'empty_attachment'));
      return;
    }

    if (seenHashes.has(hash)) {
      ignoredAttachments.push(buildIgnoredAttachment(attachmentMetadata, 'duplicate_attachment'));
      return;
    }

    if (buffer.byteLength > MAX_SINGLE_ATTACHMENT_SIZE) {
      ignoredAttachments.push(buildIgnoredAttachment(attachmentMetadata, 'attachment_too_large'));
      return;
    }

    if (selectedFiles.length >= MAX_ANALYZED_ATTACHMENTS) {
      ignoredAttachments.push(buildIgnoredAttachment(attachmentMetadata, 'attachment_limit_exceeded'));
      return;
    }

    if (totalSize + buffer.byteLength > MAX_TOTAL_ANALYZED_ATTACHMENT_SIZE) {
      ignoredAttachments.push(buildIgnoredAttachment(attachmentMetadata, 'total_attachment_size_exceeded'));
      return;
    }

    seenHashes.add(hash);
    totalSize += buffer.byteLength;
    selectedFiles.push(attachmentUpload);
  });

  return {
    files: selectedFiles,
    ignoredAttachments,
  };
}

function buildIgnoredAttachment(
  attachment: { filename?: string | null; contentType: string; size: number },
  reason: EmlIgnoredAttachment['reason'],
): EmlIgnoredAttachment {
  return {
    filename: attachment.filename ?? null,
    contentType: attachment.contentType,
    size: attachment.size,
    reason,
  };
}

function buildConsolidatedVerdict(emailAnalysis: EmailAnalysisResponse, attachmentResults: FileStaticAnalysisResult[]) {
  const emailScore = mapEmailThreatLevelToScore(emailAnalysis.threatLevel);
  const attachmentScore = Math.max(0, ...attachmentResults.map((result) => result.riskScore));
  const riskScore = Math.max(emailScore, attachmentScore);

  let threatLevel: EmailAnalysisResponse['threatLevel'];
  if (emailAnalysis.threatLevel === 'CRITICAL' || attachmentResults.some((result) => result.verdict === 'malicious')) {
    threatLevel = 'CRITICAL';
  } else if (emailAnalysis.threatLevel === 'HIGH' || attachmentResults.some((result) => result.riskScore >= 70)) {
    threatLevel = 'HIGH';
  } else if (emailAnalysis.threatLevel === 'MEDIUM' || attachmentResults.some((result) => result.verdict === 'suspicious')) {
    threatLevel = 'MEDIUM';
  } else {
    threatLevel = 'LOW';
  }

  return {
    threatLevel,
    riskScore,
    summary: buildConsolidatedSummary(emailAnalysis, attachmentResults, threatLevel),
  };
}

function buildConsolidatedSummary(
  emailAnalysis: EmailAnalysisResponse,
  attachmentResults: FileStaticAnalysisResult[],
  threatLevel: EmailAnalysisResponse['threatLevel'],
) {
  if (attachmentResults.length === 0) {
    return `Email-only analysis completed with a consolidated threat level of ${threatLevel}.`;
  }

  const maliciousAttachments = attachmentResults.filter((result) => result.verdict === 'malicious').length;
  const suspiciousAttachments = attachmentResults.filter((result) => result.verdict === 'suspicious').length;

  return `Email threat ${emailAnalysis.threatLevel}. Attachments analyzed: ${attachmentResults.length}, malicious: ${maliciousAttachments}, suspicious: ${suspiciousAttachments}. Consolidated threat level: ${threatLevel}.`;
}

function mapEmailThreatLevelToScore(threatLevel: EmailAnalysisResponse['threatLevel']) {
  switch (threatLevel) {
    case 'CRITICAL':
      return 100;
    case 'HIGH':
      return 75;
    case 'MEDIUM':
      return 40;
    case 'LOW':
    default:
      return 10;
  }
}

function buildBaseJob(jobId: string, filename: string): EmlAnalysisJob {
  return emlAnalysisJobSchema.parse({
    jobId,
    status: 'queued',
    filename,
    emailAnalysis: null,
    attachmentCount: 0,
    analyzedAttachmentCount: 0,
    ignoredAttachments: [],
    fileAnalysisJobId: null,
    attachmentResults: [],
    consolidatedThreatLevel: null,
    consolidatedRiskScore: null,
    executiveSummary: null,
    error: null,
  });
}

function buildFailedJob(jobId: string, filename: string, error: unknown): EmlAnalysisJob {
  return emlAnalysisJobSchema.parse({
    ...buildBaseJob(jobId, filename),
    status: 'failed',
    error: error instanceof Error ? error.message : 'EML analysis failed unexpectedly.',
  });
}

function defaultWait(milliseconds: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}