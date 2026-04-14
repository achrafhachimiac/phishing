import { describe, expect, it, vi } from 'vitest';

import type { FileUpload } from '../shared/analysis-types.js';
import { enqueueRemoteFileAnalysisJob } from './services/remote-file-analysis.js';

describe('enqueueRemoteFileAnalysisJob', () => {
  it('rejects private and loopback targets before any fetch occurs', async () => {
    const fetchSpy = vi.fn();

    await expect(
      enqueueRemoteFileAnalysisJob('http://127.0.0.1/secrets.pdf', async () => {
        throw new Error('should not enqueue');
      }, fetchSpy as typeof fetch),
    ).rejects.toMatchObject({
      code: 'remote_file_private_host',
    });

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('downloads a public file, derives its filename, and enqueues it into the file pipeline', async () => {
    const enqueueSpy = vi.fn(async (files: FileUpload[]) => ({
      jobId: 'file_job_remote',
      status: 'queued' as const,
      queuedFiles: files.map((file) => file.filename),
      results: [],
    }));

    const fetchSpy = vi.fn(async () => new Response(Buffer.from('%PDF-1.7 remote payload'), {
      status: 200,
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': 'attachment; filename="invoice.pdf"',
        'content-length': '23',
      },
    }));

    const job = await enqueueRemoteFileAnalysisJob(
      'https://93.184.216.34/files/invoice.pdf',
      enqueueSpy,
      fetchSpy as typeof fetch,
    );

    expect(job.jobId).toBe('file_job_remote');
    expect(enqueueSpy).toHaveBeenCalledWith([
      expect.objectContaining({
        filename: 'invoice.pdf',
        contentType: 'application/pdf',
      }),
    ]);
  });
});