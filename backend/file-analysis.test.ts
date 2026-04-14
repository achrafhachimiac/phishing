import { spawn } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { path7za } from '7zip-bin';
import { describe, expect, it, vi } from 'vitest';
import JSZip from 'jszip';
import * as tar from 'tar';

import {
  __fileAnalysisTestUtils,
  createFileAnalysisJob,
  enqueueFileAnalysisJob,
  getFileAnalysisJob,
} from './services/file-analysis.js';

describe('createFileAnalysisJob', () => {
  it('rejects uploads without a filename', async () => {
    await expect(
      createFileAnalysisJob([
        {
          filename: '',
          contentBase64: Buffer.from('hello').toString('base64'),
          contentType: 'text/plain',
        },
      ]),
    ).rejects.toMatchObject({
      code: 'invalid_file_upload',
    });
  });

  it('creates a completed static analysis job with suspicious pdf indicators', async () => {
    const suspiciousPdf = Buffer.from('%PDF-1.7\n1 0 obj\n/JavaScript https://evil.example/login\n/OpenAction\n');

    const job = await createFileAnalysisJob(
      [
        {
          filename: 'invoice.pdf',
          contentBase64: suspiciousPdf.toString('base64'),
          contentType: 'application/pdf',
        },
      ],
      undefined,
      async () => ({
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
      }),
      () => 'job_file_123',
    );

    expect(job.jobId).toBe('job_file_123');
    expect(job.status).toBe('completed');
    expect(job.results[0]).toEqual(
      expect.objectContaining({
        filename: 'invoice.pdf',
        detectedType: 'pdf',
        verdict: 'suspicious',
      }),
    );
    expect(job.results[0].extractedUrls).toContain('https://evil.example/login');
    expect(job.results[0].indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'pdf_javascript' }),
        expect.objectContaining({ kind: 'embedded_url' }),
      ]),
    );
    expect(job.results[0].parserReports).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ parser: 'pdf' }),
      ]),
    );
    expect(job.results[0].artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'upload', label: 'invoice.pdf' }),
      ]),
    );
  }, 10000);

  it('does not amplify inline base64 image metadata into a malicious IOC verdict', async () => {
    const pngWithMetadataUrl = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.from('https://evil.example/tracker', 'utf8'),
    ]);
    const enrichExtractedIocs: NonNullable<Parameters<typeof createFileAnalysisJob>[4]> = vi.fn(async () => ({
      enrichment: {
        status: 'completed' as const,
        extractedUrls: ['https://evil.example/tracker'],
        extractedDomains: ['evil.example'],
        results: [
          {
            type: 'url' as const,
            value: 'https://evil.example/tracker',
            derivedFrom: null,
            verdict: 'malicious' as const,
            summary: 'https://evil.example/tracker flagged by URLhaus.',
            providerResults: [
              {
                provider: 'urlhaus' as const,
                status: 'listed' as const,
                detail: 'phishing',
                reference: 'https://urlhaus.example/report',
              },
            ],
          },
        ],
        summary: '1 malicious IOC found.',
        updatedAt: '2026-04-12T12:00:00.000Z',
      },
      indicators: [
        {
          kind: 'ioc_malicious_url' as const,
          severity: 'high' as const,
          value: 'https://evil.example/tracker flagged by URLhaus.',
        },
      ],
    }));

    const job = await createFileAnalysisJob(
      [
        {
          filename: 'attachment-1.bin',
          contentBase64: pngWithMetadataUrl.toString('base64'),
          contentType: 'image/png',
        },
      ],
      undefined,
      async () => ({
        status: 'clean',
        malicious: 0,
        suspicious: 0,
        reference: null,
      }),
      () => 'job_inline_png',
      enrichExtractedIocs,
    );

    expect(enrichExtractedIocs).not.toHaveBeenCalled();
    expect(job.results[0].detectedType).toBe('image');
    expect(job.results[0].riskScore).toBe(20);
    expect(job.results[0].verdict).toBe('clean');
    expect(job.results[0].iocEnrichment.summary).toMatch(/inline image metadata/i);
  });

  it('adds Cortex hash reputation to the file result when configured', async () => {
    const suspiciousPdf = Buffer.from('%PDF-1.7\n1 0 obj\n/JavaScript https://evil.example/login\n/OpenAction\n');

    const job = await createFileAnalysisJob(
      [
        {
          filename: 'invoice.pdf',
          contentBase64: suspiciousPdf.toString('base64'),
          contentType: 'application/pdf',
        },
      ],
      undefined,
      async () => ({
        status: 'clean',
        malicious: 0,
        suspicious: 0,
        reference: null,
      }),
      () => 'job_file_cortex',
      async () => ({
        enrichment: {
          status: 'completed',
          extractedUrls: ['https://evil.example/login'],
          extractedDomains: ['evil.example'],
          results: [],
          summary: 'Checked 1 extracted IOC with no malicious listings returned.',
          updatedAt: '2026-04-12T12:00:00.000Z',
        },
        indicators: [],
      }),
      async () => ({
        status: 'malicious',
        analyzerCount: 2,
        matchedAnalyzerCount: 1,
        summary: 'Cortex found prior malicious reputation for this file hash.',
      }),
    );

    expect(job.results[0].externalScans.cortex).toEqual(expect.objectContaining({
      status: 'malicious',
      analyzerCount: 2,
      matchedAnalyzerCount: 1,
    }));
    expect(job.results[0].indicators).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'cortex_malicious' }),
    ]));
  });

  it('parses Office OpenXML containers and flags embedded macro payloads', async () => {
    const zip = new JSZip();
    zip.file('[Content_Types].xml', '<Types></Types>');
    zip.file('word/document.xml', '<w:document></w:document>');
    zip.file('word/vbaProject.bin', 'macro');
    const officePayload = await zip.generateAsync({ type: 'nodebuffer' });

    const job = await createFileAnalysisJob(
      [
        {
          filename: 'invoice.docm',
          contentBase64: officePayload.toString('base64'),
          contentType: 'application/vnd.ms-word.document.macroEnabled.12',
        },
      ],
      undefined,
      async () => ({
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
      }),
      () => 'job_file_456',
    );

    expect(job.results[0].detectedType).toBe('office-openxml');
    expect(job.results[0].riskScoreBreakdown).toEqual(
      expect.objectContaining({
        totalScore: job.results[0].riskScore,
        factors: expect.arrayContaining([
          expect.objectContaining({ label: 'Office Macro', severity: 'high' }),
        ]),
      }),
    );
    expect(job.results[0].parserReports).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          parser: 'office-openxml',
          extractedTree: expect.objectContaining({
            totalEntries: expect.any(Number),
            root: expect.objectContaining({
              filename: 'invoice.docm',
              children: expect.arrayContaining([
                expect.objectContaining({
                  path: 'word',
                  children: expect.arrayContaining([
                    expect.objectContaining({ path: 'word/vbaProject.bin' }),
                  ]),
                }),
              ]),
            }),
          }),
        }),
      ]),
    );
    expect(job.results[0].indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'office_macro' }),
      ]),
    );
  });

  it('builds an archive tree for nested zip files and explains the risk score', async () => {
    const innerZip = new JSZip();
    innerZip.file('payload.js', 'eval("console.log(1)")\nhttps://evil.example/nested');
    const innerBuffer = await innerZip.generateAsync({ type: 'nodebuffer' });

    const outerZip = new JSZip();
    outerZip.file('docs/readme.txt', 'hello');
    outerZip.file('nested/payload.zip', innerBuffer);
    const archivePayload = await outerZip.generateAsync({ type: 'nodebuffer' });

    const job = await createFileAnalysisJob(
      [
        {
          filename: 'bundle.zip',
          contentBase64: archivePayload.toString('base64'),
          contentType: 'application/zip',
        },
      ],
      undefined,
      async () => ({
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
      }),
      () => 'job_file_nested',
    );

    const archiveReport = job.results[0].parserReports.find((report) => report.parser === 'archive');

    expect(job.results[0].riskScoreBreakdown).toEqual(
      expect.objectContaining({
        totalScore: job.results[0].riskScore,
        factors: expect.arrayContaining([
          expect.objectContaining({ label: 'Archive Container', severity: 'medium' }),
        ]),
      }),
    );
    expect(archiveReport).toEqual(
      expect.objectContaining({
        extractedTree: expect.objectContaining({
          maxDepth: expect.any(Number),
          root: expect.objectContaining({
            filename: 'bundle.zip',
            children: expect.arrayContaining([
              expect.objectContaining({
                path: 'docs',
                children: expect.arrayContaining([
                  expect.objectContaining({ path: 'docs/readme.txt' }),
                ]),
              }),
              expect.objectContaining({
                path: 'nested',
                children: expect.arrayContaining([
                  expect.objectContaining({
                    path: 'nested/payload.zip',
                    children: expect.arrayContaining([
                  expect.objectContaining({ path: 'nested/payload.zip::payload.js' }),
                    ]),
                  }),
                ]),
              }),
            ]),
          }),
        }),
      }),
    );
  }, 10000);

  it('extracts 7z archives and analyzes the extracted contents', async () => {
    const archiveBuffer = await createSevenZipArchive({
      'docs/readme.txt': 'hello',
      'payload.js': 'eval("alert(1)")\nhttps://evil.example/payload',
    });

    const job = await createFileAnalysisJob(
      [
        {
          filename: 'bundle.7z',
          contentBase64: archiveBuffer.toString('base64'),
          contentType: 'application/x-7z-compressed',
        },
      ],
      undefined,
      async () => ({
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
      }),
      () => 'job_file_7z',
      async () => ({
        enrichment: {
          status: 'completed',
          extractedUrls: ['https://evil.example/payload'],
          extractedDomains: ['evil.example'],
          results: [],
          summary: 'Checked 1 extracted IOC with no malicious listings returned.',
          updatedAt: '2026-04-12T12:00:00.000Z',
        },
        indicators: [],
      }),
    );

    const archiveReport = job.results[0].parserReports.find((report) => report.parser === 'archive');

    expect(job.results[0].detectedType).toBe('archive');
    expect(job.results[0].indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'archive' }),
        expect.objectContaining({ kind: 'suspicious_script' }),
      ]),
    );
    expect(archiveReport).toEqual(
      expect.objectContaining({
        extractedTree: expect.objectContaining({
          root: expect.objectContaining({
            children: expect.arrayContaining([
              expect.objectContaining({ path: 'docs' }),
              expect.objectContaining({ path: 'payload.js' }),
            ]),
          }),
        }),
      }),
    );
  });

  it('routes RAR archives through the explicit 7zip extraction path', () => {
    const rarV4Signature = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0xcf, 0x90, 0x73, 0x00]);

    expect(__fileAnalysisTestUtils.detectFileType(rarV4Signature, 'rar', 'bundle.rar')).toBe('archive');
    expect(__fileAnalysisTestUtils.detectArchiveFormat(rarV4Signature, 'bundle.rar')).toBe('rar');
    expect(__fileAnalysisTestUtils.selectArchiveExtractionStrategy(rarV4Signature, 'bundle.rar')).toBe('seven-zip');
  });

  it('extracts tar.gz archives and analyzes the extracted contents', async () => {
    const archiveBuffer = await createTarGzArchive({
      'nested/run.ps1': 'Invoke-Expression "calc"\nhttps://evil.example/tgz',
    });

    const job = await createFileAnalysisJob(
      [
        {
          filename: 'bundle.tar.gz',
          contentBase64: archiveBuffer.toString('base64'),
          contentType: 'application/gzip',
        },
      ],
      undefined,
      async () => ({
        status: 'unavailable',
        malicious: null,
        suspicious: null,
        reference: null,
      }),
      () => 'job_file_tgz',
      async () => ({
        enrichment: {
          status: 'completed',
          extractedUrls: ['https://evil.example/tgz'],
          extractedDomains: ['evil.example'],
          results: [],
          summary: 'Checked 1 extracted IOC with no malicious listings returned.',
          updatedAt: '2026-04-12T12:00:00.000Z',
        },
        indicators: [],
      }),
    );

    const archiveReport = job.results[0].parserReports.find((report) => report.parser === 'archive');

    expect(job.results[0].detectedType).toBe('archive');
    expect(job.results[0].indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'archive' }),
        expect.objectContaining({ kind: 'suspicious_script' }),
      ]),
    );
    expect(archiveReport).toEqual(
      expect.objectContaining({
        extractedTree: expect.objectContaining({
          root: expect.objectContaining({
            children: expect.arrayContaining([
              expect.objectContaining({
                path: 'nested',
                children: expect.arrayContaining([
                  expect.objectContaining({ path: 'nested/run.ps1' }),
                ]),
              }),
            ]),
          }),
        }),
      }),
    );
  });

  it('publishes pending IOC enrichment results while the async file job is still running', async () => {
    let releaseEnrichment = () => {};
    const enrichmentGate = new Promise<void>((resolve) => {
      releaseEnrichment = resolve;
    });

    const queuedJob = await enqueueFileAnalysisJob(
      [
        {
          filename: 'invoice.pdf',
          contentBase64: Buffer.from('%PDF-1.7\nhttps://evil.example/login\n/JavaScript').toString('base64'),
          contentType: 'application/pdf',
        },
      ],
      undefined,
      async () => {
        await enrichmentGate;
        return {
          status: 'unavailable',
          malicious: null,
          suspicious: null,
          reference: null,
        };
      },
      () => 'job_file_progressive',
      async (urls) => {
        await enrichmentGate;
        return {
          enrichment: {
            status: 'completed',
            extractedUrls: urls,
            extractedDomains: ['evil.example'],
            results: [
              {
                type: 'url',
                value: 'https://evil.example/login',
                derivedFrom: null,
                verdict: 'malicious',
                summary: 'https://evil.example/login flagged by URLhaus.',
                providerResults: [
                  {
                    provider: 'urlhaus',
                    status: 'listed',
                    detail: 'phishing',
                    reference: 'https://urlhaus.example/report',
                  },
                ],
              },
            ],
            summary: '1 malicious and 0 suspicious IOC found across extracted URLs and domains.',
            updatedAt: '2026-04-12T12:00:00.000Z',
          },
          indicators: [
            {
              kind: 'ioc_malicious_url',
              severity: 'high',
              value: 'https://evil.example/login flagged by URLhaus.',
            },
          ],
        };
      },
    );

    expect(queuedJob.status).toBe('queued');

    let runningJob = await getFileAnalysisJob('job_file_progressive');
    for (let index = 0; index < 20 && (!runningJob || runningJob.results.length === 0); index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      runningJob = await getFileAnalysisJob('job_file_progressive');
    }

    expect(runningJob).toEqual(
      expect.objectContaining({
        status: 'running',
      }),
    );
    expect(runningJob?.results[0]).toEqual(
      expect.objectContaining({
        iocEnrichment: expect.objectContaining({
          status: 'pending',
        }),
        externalScans: expect.objectContaining({
          virustotal: expect.objectContaining({ status: 'pending' }),
        }),
      }),
    );

    releaseEnrichment();

    let completedJob = await getFileAnalysisJob('job_file_progressive');
    for (let index = 0; index < 20 && completedJob?.status !== 'completed'; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      completedJob = await getFileAnalysisJob('job_file_progressive');
    }

    expect(completedJob?.results[0]).toEqual(
      expect.objectContaining({
        verdict: 'malicious',
        iocEnrichment: expect.objectContaining({
          status: 'completed',
        }),
        indicators: expect.arrayContaining([
          expect.objectContaining({ kind: 'ioc_malicious_url' }),
        ]),
      }),
    );
  });

  it('marks queued jobs as failed when async post-processing rejects unexpectedly', async () => {
    const queuedJob = await enqueueFileAnalysisJob(
      [
        {
          filename: 'invoice.pdf',
          contentBase64: Buffer.from('%PDF-1.7\n1 0 obj\n/JavaScript\n').toString('base64'),
          contentType: 'application/pdf',
        },
      ],
      undefined,
      async () => ({
        status: 'invalid',
      } as never),
      () => 'job_file_789',
    );

    expect(queuedJob.status).toBe('queued');

    let completedJob = await getFileAnalysisJob('job_file_789');
    for (let index = 0; index < 20 && completedJob?.status === 'running'; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      completedJob = await getFileAnalysisJob('job_file_789');
    }

    expect(completedJob).toEqual(
      expect.objectContaining({
        jobId: 'job_file_789',
        status: 'failed',
      }),
    );
    expect(completedJob?.results[0]).toEqual(
      expect.objectContaining({
        filename: 'invoice.pdf',
        summary: expect.stringContaining('Invalid input'),
      }),
    );
  });
});

async function createSevenZipArchive(files: Record<string, string>) {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'phish-7z-test-'));
  const inputRoot = path.join(tempRoot, 'input');
  const archivePath = path.join(tempRoot, 'payload.7z');

  await fs.mkdir(inputRoot, { recursive: true });
  try {
    for (const [relativePath, content] of Object.entries(files)) {
      const absolutePath = path.join(inputRoot, ...relativePath.split('/'));
      await fs.mkdir(path.dirname(absolutePath), { recursive: true });
      await fs.writeFile(absolutePath, content, 'utf8');
    }

    await runProcess(path7za, ['a', archivePath, '.'], inputRoot);
    return fs.readFile(archivePath);
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
}

async function createTarGzArchive(files: Record<string, string>) {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'phish-tgz-test-'));
  const inputRoot = path.join(tempRoot, 'input');
  const archivePath = path.join(tempRoot, 'payload.tar.gz');

  await fs.mkdir(inputRoot, { recursive: true });
  try {
    for (const [relativePath, content] of Object.entries(files)) {
      const absolutePath = path.join(inputRoot, ...relativePath.split('/'));
      await fs.mkdir(path.dirname(absolutePath), { recursive: true });
      await fs.writeFile(absolutePath, content, 'utf8');
    }

    await tar.c({ gzip: true, cwd: inputRoot, file: archivePath }, Object.keys(files));
    return fs.readFile(archivePath);
  } finally {
    await fs.rm(tempRoot, { recursive: true, force: true });
  }
}

async function runProcess(command: string, args: string[], cwd: string) {
  await ensureCommandIsExecutable(command);

  return new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';

    child.stderr.on('data', (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
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
