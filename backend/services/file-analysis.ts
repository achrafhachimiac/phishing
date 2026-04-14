import { exec, spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';

import { path7za } from '7zip-bin';
import JSZip from 'jszip';
import * as tar from 'tar';

import {
  type ArchiveTreeNode,
  type CortexProviderSummary,
  type ExtractedArchiveTree,
  fileAnalysisJobSchema,
  type FileArtifact,
  type FileAnalysisJob,
  type FileExternalScan,
  type FileIndicator,
  type FileIocEnrichment,
  type FileParserReport,
  type FileRiskScoreBreakdown,
  type FileStaticAnalysisResult,
  type FileUpload,
} from '../../shared/analysis-types.js';
import { appConfig } from '../config.js';
import { getStoragePaths } from '../storage.js';
import { buildPendingIocEnrichment, buildUnavailableIocEnrichment, enrichFileIocs } from './file-ioc-enrichment.js';
import { analyzeFileHashWithCortex } from './cortex-orchestration.js';

type AnalyzeUploadedFile = (
  file: FileUpload,
  context: { jobId: string; index: number },
) => Promise<FileStaticAnalysisResult>;
type EnrichFileWithThreatIntel = (hash: string) => Promise<FileExternalScan['virustotal']>;
type EnrichFileWithCortex = (filename: string, hash: string) => Promise<CortexProviderSummary>;
type EnrichExtractedIocs = (urls: string[]) => Promise<{ enrichment: FileIocEnrichment; indicators: FileIndicator[] }>;
type RunScannerCommand = (command: string) => Promise<{ stdout: string; stderr: string }>;

const execAsync = promisify(exec);

const fileAnalysisJobs = new Map<string, FileAnalysisJob>();
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;
const MAX_ARCHIVE_RECURSION_DEPTH = 2;
const MAX_ARCHIVE_ENTRIES = 250;
const EXECUTABLE_EXTENSIONS = new Set(['exe', 'dll', 'scr', 'js', 'jse', 'vbs', 'vbe', 'hta', 'bat', 'cmd', 'ps1']);
const MACRO_EXTENSIONS = new Set(['docm', 'xlsm', 'pptm']);

export class FileAnalysisError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function enqueueFileAnalysisJob(
  files: FileUpload[],
  analyzeUploadedFile: AnalyzeUploadedFile = analyzeUploadedFileStatically,
  enrichFileWithThreatIntel: EnrichFileWithThreatIntel = lookupFileThreatIntel,
  createJobId: () => string = randomUUID,
  enrichExtractedIocs: EnrichExtractedIocs = enrichFileIocs,
  enrichFileWithCortex: EnrichFileWithCortex = analyzeFileHashWithCortex,
): Promise<FileAnalysisJob> {
  const normalizedFiles = normalizeFiles(files);
  const jobId = createJobId();
  const queuedJob = fileAnalysisJobSchema.parse({
    jobId,
    status: 'queued',
    queuedFiles: normalizedFiles.map((file) => file.filename),
    results: [],
  });

  fileAnalysisJobs.set(jobId, queuedJob);
  queueMicrotask(async () => {
    try {
      await runFileAnalysisJob(jobId, normalizedFiles, analyzeUploadedFile, enrichFileWithThreatIntel, enrichExtractedIocs, enrichFileWithCortex);
    } catch (error) {
      fileAnalysisJobs.set(jobId, buildFailedFileAnalysisJob(jobId, normalizedFiles, error));
    }
  });

  return queuedJob;
}

export async function getFileAnalysisJob(jobId: string): Promise<FileAnalysisJob | null> {
  return fileAnalysisJobs.get(jobId) ?? null;
}

export async function createFileAnalysisJob(
  files: FileUpload[],
  analyzeUploadedFile: AnalyzeUploadedFile = analyzeUploadedFileStatically,
  enrichFileWithThreatIntel: EnrichFileWithThreatIntel = lookupFileThreatIntel,
  createJobId: () => string = randomUUID,
  enrichExtractedIocs: EnrichExtractedIocs = enrichFileIocs,
  enrichFileWithCortex: EnrichFileWithCortex = analyzeFileHashWithCortex,
): Promise<FileAnalysisJob> {
  const normalizedFiles = normalizeFiles(files);
  const jobId = createJobId();
  const results = await Promise.all(
    normalizedFiles.map(async (file, index) => {
      const analysis = await analyzeUploadedFile(file, { jobId, index });
      return completeFileAnalysisResult(analysis, enrichFileWithThreatIntel, enrichExtractedIocs, enrichFileWithCortex);
    }),
  );

  return fileAnalysisJobSchema.parse({
    jobId,
    status: results.every((result) => result.verdict !== 'malicious' || result.summary.length > 0) ? 'completed' : 'failed',
    queuedFiles: normalizedFiles.map((file) => file.filename),
    results,
  });
}

export async function analyzeUploadedFileStatically(
  file: FileUpload,
  context: { jobId: string; index: number },
): Promise<FileStaticAnalysisResult> {
  const buffer = decodeBase64(file.contentBase64);
  if (buffer.byteLength > MAX_FILE_SIZE_BYTES) {
    throw new FileAnalysisError('file_too_large', 'Files larger than 10 MB are not supported in the MVP analyzer.');
  }

  const uploadDirectory = path.join(getStoragePaths().uploads, context.jobId);
  await fs.mkdir(uploadDirectory, { recursive: true });
  const safeFilename = sanitizeFilename(file.filename, context.index);
  const storagePath = path.join(uploadDirectory, safeFilename);
  await fs.writeFile(storagePath, buffer);

  const sha256 = createHash('sha256').update(buffer).digest('hex');
  const extension = extractExtension(file.filename);
  const detectedType = detectFileType(buffer, extension, file.filename, file.contentType ?? null);
  const extractedUrls = extractUrls(buffer);
  const indicators: FileIndicator[] = [];
  const parserReports = await buildParserReports({
    buffer,
    detectedType,
    extension,
    filename: file.filename,
    extractedUrls,
  });

  if (hasDoubleExtension(file.filename)) {
    indicators.push({ kind: 'double_extension', severity: 'high', value: file.filename });
  }
  if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
    indicators.push({ kind: 'executable_extension', severity: 'high', value: extension });
  }
  if (buffer.subarray(0, 2).toString('ascii') === 'MZ') {
    indicators.push({ kind: 'pe_header', severity: 'high', value: 'MZ header detected' });
  }
  if (detectedType === 'pdf' && /\/JavaScript|\/JS|\/OpenAction/i.test(buffer.toString('latin1'))) {
    indicators.push({ kind: 'pdf_javascript', severity: 'high', value: 'Embedded PDF JavaScript markers found' });
  }
  if ((extension && MACRO_EXTENSIONS.has(extension)) || /vbaProject\.bin/i.test(buffer.toString('latin1'))) {
    indicators.push({ kind: 'office_macro', severity: 'high', value: 'Macro-enabled Office indicators found' });
  }
  if (detectedType === 'zip' || detectedType === 'archive') {
    indicators.push({ kind: 'archive', severity: 'medium', value: 'Archive container detected' });
  }
  if (extractedUrls.length > 0) {
    indicators.push({ kind: 'embedded_url', severity: 'medium', value: `${extractedUrls.length} embedded URL(s)` });
  }

  indicators.push(...parserReports.flatMap(buildIndicatorsFromParserReport));

  const localScans = await runLocalFileScanners(
    {
      filename: file.filename,
      filePath: storagePath,
      sha256,
    },
  );
  indicators.push(...buildIndicatorsFromExternalScans(localScans));

  const deduplicatedIndicators = deduplicateIndicators(indicators);
  const artifacts = buildFileArtifacts({
    filename: file.filename,
    storagePath,
    contentType: file.contentType ?? null,
    size: buffer.byteLength,
  });

  const riskScore = Math.min(
    100,
    deduplicatedIndicators.reduce((score, indicator) => score + severityWeight(indicator.severity), 0),
  );
  const riskScoreBreakdown = buildRiskScoreBreakdown(deduplicatedIndicators, riskScore);
  const verdict = riskScore >= 70 ? 'malicious' : riskScore >= 25 ? 'suspicious' : 'clean';
  const summary = buildStaticAnalysisSummary({
    verdict,
    indicators: deduplicatedIndicators,
    parserReports,
    scans: localScans,
  });

  return {
    filename: file.filename,
    contentType: file.contentType ?? null,
    detectedType,
    extension,
    size: buffer.byteLength,
    sha256,
    extractedUrls,
    indicators: deduplicatedIndicators,
    parserReports,
    riskScore,
    riskScoreBreakdown,
    iocEnrichment: buildPendingIocEnrichment(extractedUrls),
    verdict,
    summary,
    storagePath,
    artifacts,
    externalScans: {
      virustotal: pendingVirusTotalScan(),
      cortex: pendingCortexScan(),
      clamav: localScans.clamav,
      yara: localScans.yara,
    },
  };
}

async function runFileAnalysisJob(
  jobId: string,
  files: FileUpload[],
  analyzeUploadedFile: AnalyzeUploadedFile,
  enrichFileWithThreatIntel: EnrichFileWithThreatIntel,
  enrichExtractedIocs: EnrichExtractedIocs,
  enrichFileWithCortex: EnrichFileWithCortex,
) {
  fileAnalysisJobs.set(jobId, {
    jobId,
    status: 'running',
    queuedFiles: files.map((file) => file.filename),
    results: [],
  });

  const results: FileStaticAnalysisResult[] = [];

  for (const [index, file] of files.entries()) {
    try {
      const analysis = await analyzeUploadedFile(file, { jobId, index });
      results.push(analysis);
      fileAnalysisJobs.set(jobId, fileAnalysisJobSchema.parse({
        jobId,
        status: 'running',
        queuedFiles: files.map((candidate) => candidate.filename),
        results,
      }));

      results[results.length - 1] = await completeFileAnalysisResult(analysis, enrichFileWithThreatIntel, enrichExtractedIocs, enrichFileWithCortex);
      fileAnalysisJobs.set(jobId, fileAnalysisJobSchema.parse({
        jobId,
        status: 'running',
        queuedFiles: files.map((candidate) => candidate.filename),
        results,
      }));
    } catch (error) {
      const decoded = safeDecode(file.contentBase64);
      results.push({
        filename: file.filename,
        contentType: file.contentType ?? null,
        detectedType: 'unknown',
        extension: extractExtension(file.filename),
        size: decoded?.byteLength ?? 0,
        sha256: decoded ? createHash('sha256').update(decoded).digest('hex') : '',
        extractedUrls: [],
        indicators: [],
        parserReports: [],
        riskScore: 0,
        riskScoreBreakdown: emptyRiskScoreBreakdown(),
        iocEnrichment: buildPendingIocEnrichment([]),
        verdict: 'clean',
        summary: error instanceof Error ? error.message : 'File analysis failed unexpectedly.',
        storagePath: null,
        artifacts: [],
        externalScans: {
          virustotal: pendingVirusTotalScan(),
          cortex: pendingCortexScan(),
          clamav: emptyClamAvScan('unavailable'),
          yara: emptyYaraScan('unavailable'),
        },
      });
    }
  }

  fileAnalysisJobs.set(
    jobId,
    fileAnalysisJobSchema.parse({
      jobId,
      status: 'completed',
      queuedFiles: files.map((file) => file.filename),
      results,
    }),
  );
}

function buildFailedFileAnalysisJob(jobId: string, files: FileUpload[], error: unknown): FileAnalysisJob {
  const message = error instanceof Error ? error.message : 'File analysis failed unexpectedly.';

  return fileAnalysisJobSchema.parse({
    jobId,
    status: 'failed',
    queuedFiles: files.map((file) => file.filename),
    results: files.map((file) => {
      const decoded = safeDecode(file.contentBase64);

      return {
        filename: file.filename,
        contentType: file.contentType ?? null,
        detectedType: 'unknown',
        extension: extractExtension(file.filename),
        size: decoded?.byteLength ?? 0,
        sha256: decoded ? createHash('sha256').update(decoded).digest('hex') : '',
        extractedUrls: [],
        indicators: [],
        parserReports: [],
        riskScore: 0,
        riskScoreBreakdown: emptyRiskScoreBreakdown(),
        iocEnrichment: buildPendingIocEnrichment([]),
        verdict: 'clean',
        summary: message,
        storagePath: null,
        artifacts: [],
        externalScans: {
          virustotal: pendingVirusTotalScan(),
          cortex: pendingCortexScan(),
          clamav: emptyClamAvScan('unavailable'),
          yara: emptyYaraScan('unavailable'),
        },
      };
    }),
  });
}

async function completeFileAnalysisResult(
  analysis: FileStaticAnalysisResult,
  enrichFileWithThreatIntel: EnrichFileWithThreatIntel,
  enrichExtractedIocs: EnrichExtractedIocs,
  enrichFileWithCortex: EnrichFileWithCortex,
): Promise<FileStaticAnalysisResult> {
  const shouldSkipInlineImageIocEnrichment = isLikelyInlineImageMetadataOnly(analysis);
  const [virustotal, cortex, iocCompletion] = await Promise.all([
    enrichFileWithThreatIntel(analysis.sha256).catch(() => emptyVirusTotalScan()),
    enrichFileWithCortex(analysis.filename, analysis.sha256).catch(() => emptyCortexScan('unavailable')),
    shouldSkipInlineImageIocEnrichment
      ? Promise.resolve({
          enrichment: buildInlineImageMetadataIocEnrichment(analysis.extractedUrls),
          indicators: [] as FileIndicator[],
        })
      : enrichExtractedIocs(analysis.extractedUrls)
          .catch((error) => ({
            enrichment: buildUnavailableIocEnrichment(
              analysis.extractedUrls,
              error instanceof Error ? error.message : 'IOC enrichment failed unexpectedly.',
            ),
            indicators: [] as FileIndicator[],
          })),
  ]);
  const indicators = deduplicateIndicators([...analysis.indicators, ...buildIndicatorsFromCortexScan(cortex), ...iocCompletion.indicators]);
  const riskScore = Math.min(
    100,
    indicators.reduce((score, indicator) => score + severityWeight(indicator.severity), 0),
  );
  const verdict = riskScore >= 70 ? 'malicious' : riskScore >= 25 ? 'suspicious' : 'clean';

  return {
    ...analysis,
    indicators,
    riskScore,
    riskScoreBreakdown: buildRiskScoreBreakdown(indicators, riskScore),
    iocEnrichment: iocCompletion.enrichment,
    verdict,
    summary: buildStaticAnalysisSummary({
      verdict,
      indicators,
      parserReports: analysis.parserReports,
      scans: {
        cortex,
        clamav: analysis.externalScans.clamav,
        yara: analysis.externalScans.yara,
      },
      iocEnrichment: iocCompletion.enrichment,
    }),
    externalScans: {
      ...analysis.externalScans,
      virustotal,
      cortex,
    },
  };
}

export async function lookupFileThreatIntel(hash: string): Promise<FileExternalScan['virustotal']> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { status: 'not_configured', malicious: null, suspicious: null, reference: null };
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, {
      headers: { 'x-apikey': apiKey },
      signal: AbortSignal.timeout(10000),
    });

    if (response.status === 404) {
      return { status: 'clean', malicious: 0, suspicious: 0, reference: null };
    }

    if (!response.ok) {
      return { status: 'unavailable', malicious: null, suspicious: null, reference: null };
    }

    const payload = (await response.json()) as {
      data?: {
        links?: { self?: string };
        attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number } };
      };
    };

    const malicious = payload.data?.attributes?.last_analysis_stats?.malicious ?? 0;
    const suspicious = payload.data?.attributes?.last_analysis_stats?.suspicious ?? 0;

    return {
      status: malicious > 0 || suspicious > 0 ? 'malicious' : 'clean',
      malicious,
      suspicious,
      reference: payload.data?.links?.self ?? null,
    };
  } catch {
    return { status: 'unavailable', malicious: null, suspicious: null, reference: null };
  }
}

async function buildParserReports(context: {
  buffer: Buffer;
  detectedType: string;
  extension: string | null;
  filename: string;
  extractedUrls: string[];
}) {
  const reports: FileParserReport[] = [];

  if (context.detectedType === 'pdf') {
    reports.push(buildPdfParserReport(context.buffer, context.extractedUrls));
  }

  if (context.detectedType === 'office-openxml' || context.detectedType === 'zip' || context.detectedType === 'archive') {
    reports.push(await buildArchiveParserReport(context.buffer, context.detectedType, context.filename, context.extension));
  }

  if (context.detectedType === 'pe') {
    reports.push(buildPeParserReport(context.buffer));
  }

  if (context.detectedType === 'script') {
    reports.push(buildScriptParserReport(context.buffer, context.extension));
  }

  if (reports.length === 0) {
    reports.push({
      parser: 'generic',
      summary: `Basic binary heuristics applied to ${context.filename}.`,
      details: [
        `Detected type: ${context.detectedType}`,
        `Extracted URLs: ${context.extractedUrls.length}`,
      ],
      snippets: [],
    });
  }

  return reports;
}

function buildPdfParserReport(buffer: Buffer, extractedUrls: string[]): FileParserReport {
  const content = buffer.toString('latin1');
  const objectCount = (content.match(/\b\d+\s+\d+\s+obj\b/g) ?? []).length;
  const autoActions = ['/OpenAction', '/Launch', '/AA'].filter((token) => content.includes(token));
  const snippets = extractSnippetMatches(content, [/\/JavaScript/gi, /\/JS/gi, /\/OpenAction/gi, /\/Launch/gi], 180);

  return {
    parser: 'pdf',
    summary: `PDF parser found ${objectCount} object(s) and ${autoActions.length} auto-action marker(s).`,
    details: [
      `Embedded URLs: ${extractedUrls.length}`,
      `JavaScript markers: ${/\/JavaScript|\/JS/i.test(content) ? 'present' : 'absent'}`,
      `Auto actions: ${autoActions.length ? autoActions.join(', ') : 'none'}`,
    ],
    snippets,
  };
}

async function buildArchiveParserReport(
  buffer: Buffer,
  detectedType: string,
  filename: string,
  extension: string | null,
): Promise<FileParserReport> {
  try {
    const archiveFormat = detectArchiveFormat(buffer, filename, extension);
    const extractedTree = await buildArchiveTreeForBuffer(buffer, filename, 0, detectedType, filename);
    const flattenedNodes = flattenArchiveTree(extractedTree.root).filter((node) => !node.isDirectory);
    const sampleEntries = flattenedNodes.slice(0, 12).map((node) => node.path);
    const suspiciousNodes = flattenedNodes.filter((node) => node.indicators.length > 0);
    const details = [
      `Archive format: ${formatArchiveFormatLabel(archiveFormat)}`,
      `Entries: ${extractedTree.totalEntries}`,
      `Max depth: ${extractedTree.maxDepth}`,
      `Extracted size: ${extractedTree.totalExtractedSize} bytes`,
    ];
    const snippets: string[] = [];

    if (sampleEntries.length) {
      details.push(`Sample entries: ${sampleEntries.join(', ')}`);
    }
    if (extractedTree.truncated) {
      details.push(...extractedTree.warnings);
    }

    if (detectedType === 'office-openxml' || (detectedType === 'zip' && extension && ['docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm'].includes(extension))) {
      const zip = await JSZip.loadAsync(buffer);
      const macroEntry = flattenedNodes.find((node) => /vbaProject\.bin/i.test(node.path));
      if (macroEntry) {
        details.push(`Macro payload: ${macroEntry.path}`);
        const macroFile = zip.file(macroEntry.path.replace(`${filename}::`, '')) ?? zip.file(macroEntry.path);
        const macroBuffer = await macroFile?.async('nodebuffer');
        if (macroBuffer) {
          snippets.push(...extractPrintableMacroSnippets(macroBuffer));
        }
      }

      const relCandidates = Object.values(zip.files).filter((entry) => entry.name.endsWith('.rels')).slice(0, 4);
      for (const candidate of relCandidates) {
        const content = await candidate.async('text');
        if (/TargetMode="External"|https?:\/\//i.test(content)) {
          details.push(`External relationship found in ${candidate.name}`);
          snippets.push(...extractSnippetMatches(content, [/TargetMode="External"/gi, /https?:\/\/[^\s"']+/gi], 160));
        }
      }
    }

    for (const node of suspiciousNodes.slice(0, 4)) {
      for (const indicator of node.indicators) {
        details.push(`Nested indicator (${node.path}): ${indicator.value}`);
      }
    }

    return {
      parser: detectedType === 'office-openxml' ? 'office-openxml' : 'archive',
      summary: `${detectedType === 'office-openxml' ? 'Office OpenXML' : 'Archive'} parser inspected ${flattenedNodes.length} extracted entr${flattenedNodes.length === 1 ? 'y' : 'ies'}.`,
      details,
      snippets: snippets.slice(0, 5),
      extractedTree,
    };
  } catch (error) {
    return {
      parser: detectedType === 'office-openxml' ? 'office-openxml' : 'archive',
      summary: 'Archive parser could not fully inspect the container.',
      details: [error instanceof Error ? error.message : 'Unknown archive parsing error'],
      snippets: [],
    };
  }
}

function buildPeParserReport(buffer: Buffer): FileParserReport {
  const peOffset = buffer.length >= 64 ? buffer.readUInt32LE(0x3c) : 0;
  const details: string[] = [`PE header offset: ${peOffset}`];

  if (peOffset > 0 && buffer.length >= peOffset + 24 && buffer.subarray(peOffset, peOffset + 4).toString('ascii') === 'PE\u0000\u0000') {
    const sectionCount = buffer.readUInt16LE(peOffset + 6);
    details.push(`Section count: ${sectionCount}`);
    const firstSectionOffset = peOffset + 24 + buffer.readUInt16LE(peOffset + 20);
    const sectionNames: string[] = [];
    for (let index = 0; index < Math.min(sectionCount, 6); index += 1) {
      const sectionOffset = firstSectionOffset + index * 40;
      if (sectionOffset + 8 > buffer.length) {
        break;
      }
      const name = buffer.subarray(sectionOffset, sectionOffset + 8).toString('ascii').replace(/\u0000+$/g, '');
      if (name) {
        sectionNames.push(name);
      }
    }
    if (sectionNames.length) {
      details.push(`Sections: ${sectionNames.join(', ')}`);
    }
  } else {
    details.push('PE signature not fully readable.');
  }

  return {
    parser: 'pe',
    summary: 'PE parser inspected DOS and NT headers.',
    details,
    snippets: [],
  };
}

function buildScriptParserReport(buffer: Buffer, extension: string | null): FileParserReport {
  const scriptContent = buffer.toString('utf8');
  const normalizedContent = scriptContent.toLowerCase();
  const markers = [
    'eval(',
    'frombase64string',
    'invoke-expression',
    'wscript.shell',
    'activexobject',
    'powershell -enc',
  ].filter((marker) => normalizedContent.includes(marker));

  return {
    parser: 'script',
    summary: `Script parser inspected ${extension ?? 'unknown'} content and found ${markers.length} suspicious marker(s).`,
    details: markers.length ? markers.map((marker) => `Marker: ${marker}`) : ['No high-risk script markers found.'],
    snippets: extractSuspiciousScriptSnippets(scriptContent, markers),
  };
}

function buildIndicatorsFromParserReport(report: FileParserReport): FileIndicator[] {
  if (report.parser === 'script') {
    return report.details
      .filter((detail) => detail.startsWith('Marker: '))
      .map((detail) => ({
        kind: 'suspicious_script' as const,
        severity: 'high' as const,
        value: detail.replace('Marker: ', ''),
      }));
  }

  if (report.parser === 'office-openxml' || report.parser === 'archive') {
    return [
      ...report.details
      .filter((detail) => detail.startsWith('Macro payload: '))
      .map((detail) => ({
        kind: 'office_macro' as const,
        severity: 'high' as const,
        value: detail.replace('Macro payload: ', ''),
      })),
      ...collectArchiveTreeIndicators(report.extractedTree),
    ];
  }

  return [];
}

function buildIndicatorsFromExternalScans(scans: Pick<FileExternalScan, 'clamav' | 'yara'>): FileIndicator[] {
  const indicators: FileIndicator[] = [];

  if (scans.clamav.status === 'malicious' && scans.clamav.signature) {
    indicators.push({ kind: 'clamav_match', severity: 'high', value: scans.clamav.signature });
  }

  if (scans.yara.status === 'match') {
    for (const rule of scans.yara.rules) {
      indicators.push({ kind: 'yara_match', severity: 'high', value: rule });
    }
  }

  return indicators;
}

function buildIndicatorsFromCortexScan(scan: CortexProviderSummary): FileIndicator[] {
  if (scan.status === 'malicious') {
    return [{ kind: 'cortex_malicious', severity: 'high', value: scan.summary }];
  }

  if (scan.status === 'suspicious') {
    return [{ kind: 'cortex_suspicious', severity: 'medium', value: scan.summary }];
  }

  return [];
}

function buildStaticAnalysisSummary(context: {
  verdict: FileStaticAnalysisResult['verdict'];
  indicators: FileIndicator[];
  parserReports: FileParserReport[];
  scans: Pick<FileExternalScan, 'clamav' | 'yara' | 'cortex'>;
  iocEnrichment?: FileIocEnrichment;
}) {
  if (context.verdict === 'clean') {
    if (context.iocEnrichment && context.iocEnrichment.status === 'completed') {
      return `No high-confidence malicious indicators were found during static analysis. ${context.iocEnrichment.summary}`;
    }
    return 'No high-confidence malicious indicators were found during static analysis.';
  }

  const headline = context.indicators[0]?.value ?? 'embedded content';
  const scanNotes: string[] = [];
  if (context.scans.clamav.status === 'malicious' && context.scans.clamav.signature) {
    scanNotes.push(`ClamAV matched ${context.scans.clamav.signature}.`);
  }
  if (context.scans.yara.status === 'match' && context.scans.yara.rules.length > 0) {
    scanNotes.push(`YARA matched ${context.scans.yara.rules.join(', ')}.`);
  }
  if (context.scans.cortex && ['malicious', 'suspicious'].includes(context.scans.cortex.status)) {
    scanNotes.push(`Cortex reported ${context.scans.cortex.status} file reputation evidence.`);
  }

  return [
    `Static analysis found ${context.indicators.length} suspicious indicator(s), including ${headline}.`,
    context.iocEnrichment && context.iocEnrichment.status === 'completed'
      ? context.iocEnrichment.summary
      : scanNotes[0] ?? `${context.parserReports.length} specialized parser report(s) were generated.`,
  ].join(' ');
}

function buildFileArtifacts(context: {
  filename: string;
  storagePath: string;
  contentType: string | null;
  size: number;
}): FileArtifact[] {
  return [
    {
      type: 'upload',
      label: context.filename,
      path: context.storagePath,
      mimeType: context.contentType,
      size: context.size,
    },
  ];
}

async function buildArchiveTree(
  zip: JSZip,
  archiveLabel: string,
  archiveDepth: number,
): Promise<ExtractedArchiveTree> {
  const warnings: string[] = [];
  const root: ArchiveTreeNode = createArchiveNode({
    path: archiveLabel,
    filename: path.posix.basename(archiveLabel),
    isDirectory: true,
    size: null,
    detectedType: 'archive',
    indicators: [],
  });
  let totalEntries = 0;
  let totalExtractedSize = 0;

  const entries = Object.values(zip.files)
    .filter((entry) => !/^__MACOSX\//.test(entry.name) && !/\.DS_Store$/i.test(entry.name))
    .slice(0, MAX_ARCHIVE_ENTRIES + 1);

  if (entries.length > MAX_ARCHIVE_ENTRIES) {
    warnings.push(`Archive tree truncated after ${MAX_ARCHIVE_ENTRIES} entries.`);
  }

  for (const entry of entries.slice(0, MAX_ARCHIVE_ENTRIES)) {
    const normalizedEntryPath = entry.name.replace(/\/$/, '');
    if (!normalizedEntryPath) {
      continue;
    }

    const segments = normalizedEntryPath.split('/').filter(Boolean);
    if (segments.length === 0) {
      continue;
    }

    if (entry.dir) {
      upsertArchiveTreeNode(root, segments, {
        path: normalizedEntryPath,
        filename: segments[segments.length - 1] ?? normalizedEntryPath,
        isDirectory: true,
        size: null,
        detectedType: 'archive',
        indicators: [],
      });
      totalEntries += 1;
      continue;
    }

    const entryBuffer = await entry.async('nodebuffer');
    totalExtractedSize += entryBuffer.byteLength;
    totalEntries += 1;

    const extension = extractExtension(normalizedEntryPath);
    const detectedType = detectFileType(entryBuffer, extension, normalizedEntryPath);
    const indicators = analyzeArchiveNodeIndicators(entryBuffer, normalizedEntryPath, detectedType, extension);
    const nodePath = archiveDepth === 0 ? normalizedEntryPath : `${archiveLabel}::${normalizedEntryPath}`;
    const leafNode = upsertArchiveTreeNode(root, segments, {
      path: nodePath,
      filename: segments[segments.length - 1] ?? normalizedEntryPath,
      isDirectory: false,
      size: entryBuffer.byteLength,
      detectedType,
      indicators,
    });

    if (isRecursiveArchiveCandidate(detectedType, normalizedEntryPath) && archiveDepth < MAX_ARCHIVE_RECURSION_DEPTH) {
      try {
        const childTree = await buildArchiveTreeForBuffer(entryBuffer, nodePath, archiveDepth + 1, detectedType, normalizedEntryPath);
        leafNode.children = childTree.root.children;
        totalEntries += childTree.totalEntries;
        totalExtractedSize += childTree.totalExtractedSize;
        warnings.push(...childTree.warnings);
      } catch {
        warnings.push(`Nested archive ${nodePath} could not be fully extracted.`);
      }
    } else if (isRecursiveArchiveCandidate(detectedType, normalizedEntryPath)) {
      warnings.push(`Nested archive depth limit reached at ${nodePath}.`);
    }
  }

  return {
    totalEntries,
    maxDepth: computeArchiveTreeDepth(root),
    totalExtractedSize,
    truncated: warnings.length > 0,
    warnings: [...new Set(warnings)],
    root,
  };
}

function createArchiveNode(node: Omit<ArchiveTreeNode, 'children'>): ArchiveTreeNode {
  return {
    ...node,
    children: [],
  };
}

function upsertArchiveTreeNode(
  root: ArchiveTreeNode,
  segments: string[],
  leaf: Omit<ArchiveTreeNode, 'children'>,
): ArchiveTreeNode {
  let cursor = root;
  let currentPath = '';

  for (const [index, segment] of segments.entries()) {
    currentPath = currentPath ? `${currentPath}/${segment}` : segment;
    const isLeaf = index === segments.length - 1;
    const existing = cursor.children.find((child) => child.filename === segment);
    if (existing) {
      cursor = existing;
      if (isLeaf) {
        cursor.path = leaf.path;
        cursor.isDirectory = leaf.isDirectory;
        cursor.size = leaf.size;
        cursor.detectedType = leaf.detectedType;
        cursor.indicators = leaf.indicators;
      }
      continue;
    }

    const nextNode = createArchiveNode(isLeaf ? leaf : {
      path: currentPath,
      filename: segment,
      isDirectory: true,
      size: null,
      detectedType: null,
      indicators: [],
    });
    cursor.children.push(nextNode);
    cursor = nextNode;
  }

  return cursor;
}

function computeArchiveTreeDepth(node: ArchiveTreeNode): number {
  if (node.children.length === 0) {
    return 0;
  }

  return 1 + Math.max(...node.children.map((child) => computeArchiveTreeDepth(child)));
}

function flattenArchiveTree(node: ArchiveTreeNode): ArchiveTreeNode[] {
  return [node, ...node.children.flatMap((child) => flattenArchiveTree(child))];
}

function analyzeArchiveNodeIndicators(
  buffer: Buffer,
  entryName: string,
  detectedType: string,
  extension: string | null,
): FileIndicator[] {
  const indicators: FileIndicator[] = [];
  const extractedUrls = extractUrls(buffer);

  if (extension && EXECUTABLE_EXTENSIONS.has(extension)) {
    indicators.push({ kind: 'executable_extension', severity: 'high', value: entryName });
  }
  if (extractedUrls.length > 0) {
    indicators.push({ kind: 'embedded_url', severity: 'medium', value: `${entryName} contains ${extractedUrls.length} embedded URL(s)` });
  }
  if (detectedType === 'script') {
    indicators.push(...buildIndicatorsFromParserReport(buildScriptParserReport(buffer, extension)));
  }
  if ((extension && MACRO_EXTENSIONS.has(extension)) || /vbaProject\.bin/i.test(entryName)) {
    indicators.push({ kind: 'office_macro', severity: 'high', value: entryName });
  }

  return deduplicateIndicators(indicators);
}

function collectArchiveTreeIndicators(tree: ExtractedArchiveTree | undefined): FileIndicator[] {
  if (!tree) {
    return [];
  }

  return flattenArchiveTree(tree.root)
    .flatMap((node) => node.indicators)
    .filter((indicator) => indicator.kind !== 'embedded_url');
}

function buildRiskScoreBreakdown(indicators: FileIndicator[], totalScore: number): FileRiskScoreBreakdown {
  return {
    totalScore,
    thresholds: {
      suspicious: 25,
      malicious: 70,
    },
    factors: indicators
      .map((indicator) => ({
        label: formatIndicatorLabel(indicator.kind),
        severity: indicator.severity,
        contribution: severityWeight(indicator.severity),
        evidence: indicator.value,
      }))
      .sort((left, right) => right.contribution - left.contribution || left.label.localeCompare(right.label)),
  };
}

function buildInlineImageMetadataIocEnrichment(extractedUrls: string[]): FileIocEnrichment {
  return {
    status: 'completed',
    extractedUrls,
    extractedDomains: [],
    results: [],
    summary: 'IOC enrichment skipped because the extracted URLs appear to come from inline image metadata embedded in the email body.',
    updatedAt: new Date().toISOString(),
  };
}

function isLikelyInlineImageMetadataOnly(analysis: FileStaticAnalysisResult) {
  const isImage = analysis.detectedType === 'image' || analysis.contentType?.toLowerCase().startsWith('image/');
  const looksLikeInlineEmailPart = /^attachment-\d+\.(bin|png|jpg|jpeg|gif|webp)$/i.test(analysis.filename);
  const onlyMetadataLikeIndicators = analysis.indicators.length > 0 && analysis.indicators.every((indicator) => indicator.kind === 'embedded_url');

  return isImage && looksLikeInlineEmailPart && onlyMetadataLikeIndicators;
}

function emptyRiskScoreBreakdown(): FileRiskScoreBreakdown {
  return buildRiskScoreBreakdown([], 0);
}

function formatIndicatorLabel(kind: FileIndicator['kind']): string {
  const labels: Record<FileIndicator['kind'], string> = {
    archive: 'Archive Container',
    clamav_match: 'ClamAV Match',
    double_extension: 'Double Extension',
    embedded_url: 'Embedded URL',
    executable_extension: 'Executable Extension',
    ioc_malicious_domain: 'IOC Malicious Domain',
    ioc_malicious_url: 'IOC Malicious URL',
    ioc_suspicious_domain: 'IOC Suspicious Domain',
    ioc_suspicious_url: 'IOC Suspicious URL',
    cortex_malicious: 'Cortex Malicious Reputation',
    cortex_suspicious: 'Cortex Suspicious Reputation',
    office_macro: 'Office Macro',
    pdf_javascript: 'PDF JavaScript',
    pe_header: 'PE Header',
    suspicious_script: 'Suspicious Script',
    yara_match: 'YARA Match',
  };

  if (labels[kind]) {
    return labels[kind];
  }

  return kind
    .split('_')
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ');
}

async function buildArchiveTreeForBuffer(
  buffer: Buffer,
  archiveLabel: string,
  archiveDepth: number,
  detectedType: string,
  filenameHint: string,
): Promise<ExtractedArchiveTree> {
  if (detectedType === 'office-openxml' || isZipBuffer(buffer)) {
    const zip = await JSZip.loadAsync(buffer);
    return buildArchiveTree(zip, archiveLabel, archiveDepth);
  }

  return buildArchiveTreeFromExtractor(buffer, archiveLabel, archiveDepth, filenameHint);
}

async function buildArchiveTreeFromExtractor(
  buffer: Buffer,
  archiveLabel: string,
  archiveDepth: number,
  filenameHint: string,
): Promise<ExtractedArchiveTree> {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'phish-archive-'));
  const extractionRoot = path.join(tempRoot, 'extracted');
  const sourceArchivePath = path.join(tempRoot, sanitizeFilename(filenameHint, archiveDepth));

  await fs.mkdir(extractionRoot, { recursive: true });
  await fs.writeFile(sourceArchivePath, buffer);

  try {
    await extractArchiveWithBestEffort(sourceArchivePath, extractionRoot, buffer, filenameHint);
    return buildArchiveTreeFromDirectory(extractionRoot, archiveLabel, archiveDepth);
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
}

async function buildArchiveTreeFromDirectory(
  directoryPath: string,
  archiveLabel: string,
  archiveDepth: number,
): Promise<ExtractedArchiveTree> {
  const warnings: string[] = [];
  const root: ArchiveTreeNode = createArchiveNode({
    path: archiveLabel,
    filename: path.posix.basename(archiveLabel),
    isDirectory: true,
    size: null,
    detectedType: 'archive',
    indicators: [],
  });
  let totalEntries = 0;
  let totalExtractedSize = 0;

  const visitDirectory = async (currentDirectoryPath: string, relativeParentPath = ''): Promise<void> => {
    const directoryEntries = (await fs.readdir(currentDirectoryPath, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name));

    for (const entry of directoryEntries) {
      if (totalEntries >= MAX_ARCHIVE_ENTRIES) {
        warnings.push(`Archive tree truncated after ${MAX_ARCHIVE_ENTRIES} entries.`);
        return;
      }

      const relativePath = relativeParentPath ? `${relativeParentPath}/${entry.name}` : entry.name;
      if (!isSafeArchiveEntryPath(relativePath)) {
        warnings.push(`Skipped unsafe archive entry path ${relativePath}.`);
        continue;
      }

      const absolutePath = path.join(currentDirectoryPath, entry.name);
      const segments = relativePath.split('/').filter(Boolean);

      if (entry.isDirectory()) {
        upsertArchiveTreeNode(root, segments, {
          path: relativePath,
          filename: entry.name,
          isDirectory: true,
          size: null,
          detectedType: 'archive',
          indicators: [],
        });
        totalEntries += 1;
        await visitDirectory(absolutePath, relativePath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const entryBuffer = await fs.readFile(absolutePath);
      const extension = extractExtension(relativePath);
      const detectedType = detectFileType(entryBuffer, extension, relativePath);
      const indicators = analyzeArchiveNodeIndicators(entryBuffer, relativePath, detectedType, extension);
      const nodePath = archiveDepth === 0 ? relativePath : `${archiveLabel}::${relativePath}`;
      const leafNode = upsertArchiveTreeNode(root, segments, {
        path: nodePath,
        filename: entry.name,
        isDirectory: false,
        size: entryBuffer.byteLength,
        detectedType,
        indicators,
      });

      totalEntries += 1;
      totalExtractedSize += entryBuffer.byteLength;

      if (isRecursiveArchiveCandidate(detectedType, relativePath) && archiveDepth < MAX_ARCHIVE_RECURSION_DEPTH) {
        try {
          const childTree = await buildArchiveTreeForBuffer(entryBuffer, nodePath, archiveDepth + 1, detectedType, relativePath);
          leafNode.children = childTree.root.children;
          totalEntries += childTree.totalEntries;
          totalExtractedSize += childTree.totalExtractedSize;
          warnings.push(...childTree.warnings);
        } catch {
          warnings.push(`Nested archive ${nodePath} could not be fully extracted.`);
        }
      } else if (isRecursiveArchiveCandidate(detectedType, relativePath)) {
        warnings.push(`Nested archive depth limit reached at ${nodePath}.`);
      }
    }
  };

  await visitDirectory(directoryPath);

  return {
    totalEntries,
    maxDepth: computeArchiveTreeDepth(root),
    totalExtractedSize,
    truncated: warnings.length > 0,
    warnings: [...new Set(warnings)],
    root,
  };
}

async function extractArchiveWithBestEffort(
  sourceArchivePath: string,
  extractionRoot: string,
  buffer: Buffer,
  filenameHint: string,
) {
  if (selectArchiveExtractionStrategy(buffer, filenameHint) === 'tar') {
    await extractTarArchive(sourceArchivePath, extractionRoot, filenameHint);
    return;
  }

  await validateSevenZipArchivePaths(sourceArchivePath);
  await runSpawnedProcess(path7za, ['x', sourceArchivePath, `-o${extractionRoot}`, '-y']);
}

async function extractTarArchive(sourceArchivePath: string, extractionRoot: string, filenameHint: string) {
  await tar.x({
    cwd: extractionRoot,
    file: sourceArchivePath,
    gzip: isGzipLikeFilename(filenameHint),
    strict: true,
    filter: (entryPath) => isSafeArchiveEntryPath(entryPath.replace(/\\/g, '/')),
  });
}

async function validateSevenZipArchivePaths(sourceArchivePath: string) {
  const { stdout } = await runSpawnedProcess(path7za, ['l', '-slt', sourceArchivePath]);
  const entryPaths = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('Path = '))
    .map((line) => line.slice('Path = '.length).trim())
    .filter((entryPath) => entryPath !== sourceArchivePath && entryPath !== path.basename(sourceArchivePath));

  for (const entryPath of entryPaths) {
    if (!isSafeArchiveEntryPath(entryPath.replace(/\\/g, '/'))) {
      throw new Error(`Archive contains unsafe path entry: ${entryPath}`);
    }
  }
}

async function runSpawnedProcess(command: string, args: string[]) {
  await ensureCommandIsExecutable(command);

  return new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }

      reject(new Error(stderr.trim() || `${path.basename(command)} exited with code ${code ?? 'unknown'}.`));
    });
  });
}

async function ensureCommandIsExecutable(command: string) {
  await fs.access(command);

  if (process.platform === 'win32') {
    return;
  }

  try {
    await fs.access(command, fsConstants.X_OK);
  } catch {
    const stats = await fs.stat(command);
    await fs.chmod(command, stats.mode | 0o111);
    await fs.access(command, fsConstants.X_OK);
  }
}

function isRecursiveArchiveCandidate(detectedType: string, filename: string) {
  return detectedType === 'zip' || detectedType === 'office-openxml' || (detectedType === 'archive' && isArchiveFilename(filename));
}

function isArchiveFilename(filename: string) {
  const normalized = filename.toLowerCase();
  return normalized.endsWith('.zip')
    || normalized.endsWith('.7z')
    || normalized.endsWith('.rar')
    || normalized.endsWith('.tar')
    || normalized.endsWith('.tar.gz')
    || normalized.endsWith('.tgz')
    || normalized.endsWith('.gz');
}

function isTarLikeFilename(filename: string) {
  const normalized = filename.toLowerCase();
  return normalized.endsWith('.tar') || normalized.endsWith('.tar.gz') || normalized.endsWith('.tgz');
}

function isGzipLikeFilename(filename: string) {
  const normalized = filename.toLowerCase();
  return normalized.endsWith('.tar.gz') || normalized.endsWith('.tgz') || normalized.endsWith('.gz');
}

function isSafeArchiveEntryPath(entryPath: string) {
  const normalized = entryPath.replace(/\\/g, '/');
  return normalized.length > 0
    && !normalized.startsWith('/')
    && !/^[A-Za-z]:\//.test(normalized)
    && !normalized.split('/').some((segment) => segment === '..');
}

function isZipBuffer(buffer: Buffer) {
  return buffer.subarray(0, 4).toString('latin1') === 'PK\u0003\u0004';
}

function isSevenZipBuffer(buffer: Buffer) {
  return buffer.subarray(0, 6).equals(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]));
}

function isRarBuffer(buffer: Buffer) {
  return buffer.subarray(0, 7).equals(Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00]))
    || buffer.subarray(0, 8).equals(Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]));
}

function isGzipBuffer(buffer: Buffer) {
  return buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b;
}

function isTarBuffer(buffer: Buffer) {
  return buffer.length > 262 && buffer.subarray(257, 262).toString('ascii') === 'ustar';
}

function detectArchiveFormat(buffer: Buffer, filename: string, extension: string | null = extractExtension(filename)) {
  const normalizedFilename = filename.toLowerCase();

  if (isZipBuffer(buffer)) {
    if (extension && ['docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm'].includes(extension)) {
      return 'office-openxml' as const;
    }

    return 'zip' as const;
  }

  if (isRarBuffer(buffer) || normalizedFilename.endsWith('.rar') || extension === 'rar') {
    return 'rar' as const;
  }

  if (isSevenZipBuffer(buffer) || normalizedFilename.endsWith('.7z') || extension === '7z') {
    return '7z' as const;
  }

  if (isTarBuffer(buffer) || normalizedFilename.endsWith('.tar') || extension === 'tar') {
    return 'tar' as const;
  }

  if (isGzipBuffer(buffer)) {
    if (normalizedFilename.endsWith('.tar.gz') || normalizedFilename.endsWith('.tgz')) {
      return 'tar.gz' as const;
    }

    return 'gzip' as const;
  }

  if (normalizedFilename.endsWith('.tar.gz') || normalizedFilename.endsWith('.tgz')) {
    return 'tar.gz' as const;
  }

  return 'unknown' as const;
}

function formatArchiveFormatLabel(format: ReturnType<typeof detectArchiveFormat>) {
  switch (format) {
    case 'office-openxml':
      return 'Office OpenXML';
    case 'tar.gz':
      return 'TAR.GZ';
    case '7z':
      return '7Z';
    case 'rar':
      return 'RAR';
    case 'tar':
      return 'TAR';
    case 'gzip':
      return 'GZIP';
    case 'zip':
      return 'ZIP';
    default:
      return 'Unknown';
  }
}

function selectArchiveExtractionStrategy(buffer: Buffer, filenameHint: string) {
  const archiveFormat = detectArchiveFormat(buffer, filenameHint);
  return archiveFormat === 'tar' || archiveFormat === 'tar.gz' || archiveFormat === 'gzip' ? 'tar' : 'seven-zip';
}

async function runLocalFileScanners(
  context: { filename: string; filePath: string; sha256: string },
  runCommand: RunScannerCommand = execScannerCommand,
): Promise<Pick<FileExternalScan, 'clamav' | 'yara'>> {
  const [clamav, yara] = await Promise.all([
    runClamAvScan(context, runCommand),
    runYaraScan(context, runCommand),
  ]);

  return { clamav, yara };
}

async function runClamAvScan(
  context: { filename: string; filePath: string; sha256: string },
  runCommand: RunScannerCommand,
): Promise<FileExternalScan['clamav']> {
  const template = appConfig.fileAnalysis.clamavCommandTemplate;
  if (!template) {
    return emptyClamAvScan('not_configured');
  }

  const command = interpolateScannerCommand(template, context);
  try {
    const { stdout, stderr } = await runCommand(command);
    return parseClamAvOutput(`${stdout}\n${stderr}`);
  } catch (error) {
    const stdout = readCommandStream(error, 'stdout');
    const stderr = readCommandStream(error, 'stderr');
    const parsed = parseClamAvOutput(`${stdout}\n${stderr}`);
    if (parsed.status === 'malicious' || parsed.status === 'clean') {
      return parsed;
    }
    return {
      ...emptyClamAvScan('error'),
      detail: stderr.trim() || (error instanceof Error ? error.message : 'ClamAV scan failed unexpectedly.'),
    };
  }
}

async function runYaraScan(
  context: { filename: string; filePath: string; sha256: string },
  runCommand: RunScannerCommand,
): Promise<FileExternalScan['yara']> {
  const template = appConfig.fileAnalysis.yaraCommandTemplate;
  if (!template) {
    return emptyYaraScan('not_configured');
  }

  const command = interpolateScannerCommand(template, context);
  try {
    const { stdout, stderr } = await runCommand(command);
    return parseYaraOutput(stdout, stderr);
  } catch (error) {
    const stdout = readCommandStream(error, 'stdout');
    const stderr = readCommandStream(error, 'stderr');
    const parsed = parseYaraOutput(stdout, stderr);
    if (parsed.status === 'match' || parsed.status === 'clean') {
      return parsed;
    }
    return {
      ...emptyYaraScan('error'),
      detail: stderr.trim() || (error instanceof Error ? error.message : 'YARA scan failed unexpectedly.'),
    };
  }
}

async function execScannerCommand(command: string) {
  return execAsync(command);
}

function parseClamAvOutput(output: string): FileExternalScan['clamav'] {
  const meaningfulLine = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.includes(':'));

  if (!meaningfulLine) {
    return emptyClamAvScan('clean');
  }

  const verdict = meaningfulLine.split(':').slice(1).join(':').trim();
  if (/\bOK\b/i.test(verdict)) {
    return emptyClamAvScan('clean');
  }

  if (verdict) {
    return {
      status: 'malicious',
      signature: verdict.replace(/\s+FOUND$/i, '').trim(),
      engine: 'ClamAV',
      detail: meaningfulLine,
    };
  }

  return emptyClamAvScan('unavailable');
}

function parseYaraOutput(stdout: string, stderr: string): FileExternalScan['yara'] {
  const rules = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => line.split(/\s+/)[0])
    .filter(Boolean);

  if (rules.length > 0) {
    return {
      status: 'match',
      rules: [...new Set(rules)],
      detail: null,
    };
  }

  if (stderr.trim()) {
    return {
      ...emptyYaraScan('error'),
      detail: stderr.trim(),
    };
  }

  return emptyYaraScan('clean');
}

function interpolateScannerCommand(template: string, context: { filename: string; filePath: string; sha256: string }) {
  return template
    .replaceAll(':path', shellEscape(context.filePath))
    .replaceAll(':filename', shellEscape(context.filename))
    .replaceAll(':sha256', context.sha256);
}

function readCommandStream(error: unknown, key: 'stdout' | 'stderr') {
  if (typeof error === 'object' && error !== null && key in error) {
    const value = (error as Record<'stdout' | 'stderr', unknown>)[key];
    return typeof value === 'string' ? value : '';
  }
  return '';
}

function emptyVirusTotalScan(): FileExternalScan['virustotal'] {
  return {
    status: 'unavailable',
    malicious: null,
    suspicious: null,
    reference: null,
  };
}

function pendingVirusTotalScan(): FileExternalScan['virustotal'] {
  return {
    status: 'pending',
    malicious: null,
    suspicious: null,
    reference: null,
  };
}

function emptyCortexScan(status: NonNullable<FileExternalScan['cortex']>['status']): NonNullable<FileExternalScan['cortex']> {
  return {
    status,
    analyzerCount: 0,
    matchedAnalyzerCount: 0,
    summary: status === 'not_configured'
      ? 'Cortex file reputation enrichment is not configured.'
      : status === 'unavailable'
        ? 'Cortex file reputation enrichment is unavailable.'
        : 'Cortex file reputation enrichment found no matches.',
  };
}

function pendingCortexScan(): NonNullable<FileExternalScan['cortex']> {
  return {
    status: 'unavailable',
    analyzerCount: 0,
    matchedAnalyzerCount: 0,
    summary: 'Cortex file reputation enrichment has not completed yet.',
  };
}

function emptyClamAvScan(status: FileExternalScan['clamav']['status']): FileExternalScan['clamav'] {
  return {
    status,
    signature: null,
    engine: status === 'not_configured' ? null : 'ClamAV',
    detail: null,
  };
}

function emptyYaraScan(status: FileExternalScan['yara']['status']): FileExternalScan['yara'] {
  return {
    status,
    rules: [],
    detail: null,
  };
}

function deduplicateIndicators(indicators: FileIndicator[]) {
  const seen = new Set<string>();
  return indicators.filter((indicator) => {
    const key = `${indicator.kind}:${indicator.value}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function normalizeFiles(files: FileUpload[]) {
  if (files.length === 0) {
    throw new FileAnalysisError('invalid_file_upload', 'At least one file is required for analysis.');
  }

  return files.map((file) => {
    if (!file.filename.trim()) {
      throw new FileAnalysisError('invalid_file_upload', 'Every uploaded file must include a filename.');
    }

    const decoded = decodeBase64(file.contentBase64);
    if (decoded.byteLength === 0) {
      throw new FileAnalysisError('invalid_file_upload', 'Uploaded files must not be empty.');
    }

    if (decoded.byteLength > MAX_FILE_SIZE_BYTES) {
      throw new FileAnalysisError('file_too_large', 'Files larger than 10 MB are not supported in the MVP analyzer.');
    }

    return {
      ...file,
      contentType: file.contentType ?? null,
    };
  });
}

function decodeBase64(contentBase64: string) {
  try {
    return Buffer.from(contentBase64, 'base64');
  } catch {
    throw new FileAnalysisError('invalid_file_upload', 'One or more uploaded files are not valid base64 payloads.');
  }
}

function safeDecode(contentBase64: string) {
  try {
    return Buffer.from(contentBase64, 'base64');
  } catch {
    return null;
  }
}

function sanitizeFilename(filename: string, index: number) {
  const cleaned = filename.replace(/[\\/:*?"<>|]+/g, '-').trim();
  return `${index.toString().padStart(2, '0')}-${cleaned || 'upload.bin'}`;
}

function extractExtension(filename: string) {
  const lastSegment = filename.split('.').pop()?.toLowerCase() ?? '';
  return lastSegment.length > 0 && lastSegment !== filename.toLowerCase() ? lastSegment : null;
}

function hasDoubleExtension(filename: string) {
  const parts = filename.toLowerCase().split('.').filter(Boolean);
  return parts.length >= 3;
}

function detectFileType(buffer: Buffer, extension: string | null, filename = '', contentType: string | null = null) {
  const normalizedFilename = filename.toLowerCase();
  const normalizedContentType = contentType?.toLowerCase() ?? null;
  const header = buffer.subarray(0, 8).toString('latin1');
  if (header.startsWith('%PDF')) {
    return 'pdf';
  }
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return 'image';
  }
  if (buffer.subarray(0, 3).toString('ascii') === 'GIF') {
    return 'image';
  }
  if (buffer.subarray(0, 2).toString('hex') === 'ffd8') {
    return 'image';
  }
  if (header.startsWith('RIFF') && buffer.subarray(8, 12).toString('ascii') === 'WEBP') {
    return 'image';
  }
  if (buffer.subarray(0, 2).toString('ascii') === 'MZ') {
    return 'pe';
  }
  if (isZipBuffer(buffer)) {
    if (extension && ['docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm'].includes(extension)) {
      return 'office-openxml';
    }
    return 'zip';
  }
  if (isSevenZipBuffer(buffer) || isRarBuffer(buffer) || isTarBuffer(buffer) || isGzipBuffer(buffer)) {
    return 'archive';
  }
  if (normalizedFilename.endsWith('.tar.gz') || normalizedFilename.endsWith('.tgz')) {
    return 'archive';
  }
  if (extension && ['7z', 'rar', 'zip', 'tar', 'gz', 'tgz'].includes(extension)) {
    return 'archive';
  }
  if (extension && ['js', 'vbs', 'ps1', 'bat', 'cmd'].includes(extension)) {
    return 'script';
  }
  if (normalizedContentType?.startsWith('image/') || (extension && ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'].includes(extension))) {
    return 'image';
  }
  return extension ?? 'unknown';
}

function extractUrls(buffer: Buffer) {
  const content = buffer.toString('utf8');
  return [...new Set(content.match(/https?:\/\/[^\s<>"']+/gi) ?? [])];
}

function extractSnippetMatches(content: string, patterns: RegExp[], radius: number) {
  const snippets: string[] = [];

  for (const pattern of patterns) {
    for (const match of content.matchAll(pattern)) {
      if (typeof match.index !== 'number') {
        continue;
      }

      const start = Math.max(0, match.index - radius);
      const end = Math.min(content.length, match.index + match[0].length + radius);
      const snippet = content.slice(start, end).replace(/\s+/g, ' ').trim();
      if (snippet) {
        snippets.push(snippet);
      }
      if (snippets.length >= 5) {
        return [...new Set(snippets)];
      }
    }
  }

  return [...new Set(snippets)];
}

function extractSuspiciousScriptSnippets(content: string, markers: string[]) {
  const lines = content.split(/\r?\n/);
  const snippets: string[] = [];

  for (const marker of markers) {
    const matchingLine = lines.find((line) => line.toLowerCase().includes(marker));
    if (matchingLine) {
      snippets.push(matchingLine.trim());
    }
  }

  return [...new Set(snippets)].slice(0, 5);
}

function extractPrintableMacroSnippets(buffer: Buffer) {
  const suspiciousMarkers = ['AutoOpen', 'Document_Open', 'Shell', 'CreateObject', 'WScript', 'PowerShell', 'http', 'cmd.exe'];

  return buffer
    .toString('latin1')
    .replace(/[^\x20-\x7e\r\n\t]+/g, ' ')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length >= 8)
    .filter((line) => suspiciousMarkers.some((marker) => line.toLowerCase().includes(marker.toLowerCase())))
    .slice(0, 5);
}

export const __fileAnalysisTestUtils = {
  detectArchiveFormat,
  detectFileType,
  selectArchiveExtractionStrategy,
};

function shellEscape(value: string) {
  return `"${value.replace(/"/g, '\\"')}"`;
}

function severityWeight(severity: FileIndicator['severity']) {
  switch (severity) {
    case 'high':
      return 40;
    case 'medium':
      return 20;
    case 'low':
    default:
      return 10;
  }
}
