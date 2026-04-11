import { describe, expect, it } from 'vitest';
import JSZip from 'jszip';

import { createFileAnalysisJob, enqueueFileAnalysisJob, getFileAnalysisJob } from './services/file-analysis.js';

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
    expect(job.results[0].parserReports).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ parser: 'office-openxml' }),
      ]),
    );
    expect(job.results[0].indicators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'office_macro' }),
      ]),
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
