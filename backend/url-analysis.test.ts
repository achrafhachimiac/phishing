import { describe, expect, it } from 'vitest';

import { createUrlAnalysisJob } from './services/url-analysis.js';

describe('createUrlAnalysisJob', () => {
  it('rejects local or private targets before any browser execution', async () => {
    await expect(
      createUrlAnalysisJob(
        ['http://127.0.0.1/login'],
        async () => ({
          finalUrl: 'http://127.0.0.1/login',
          title: 'forbidden',
          screenshotPath: 'none',
          tracePath: null,
          redirectChain: [],
          requestedDomains: [],
          scriptUrls: [],
          consoleErrors: [],
          status: 'completed',
          error: null,
        }),
      ),
    ).rejects.toMatchObject({
      code: 'invalid_url_target',
    });
  });

  it('creates a completed job with captured URL evidence', async () => {
    const job = await createUrlAnalysisJob(
      ['https://example.org'],
      async (url) => ({
        finalUrl: `${url}/`,
        title: 'Example Domain',
        screenshotPath: 'storage/screenshots/job_test/example-org.png',
        tracePath: 'storage/traces/job_test/example-org.zip',
        redirectChain: [url, `${url}/`],
        requestedDomains: ['example.org'],
        scriptUrls: ['https://example.org/app.js'],
        consoleErrors: [],
        status: 'completed',
        error: null,
      }),
      async () => ({
        urlhaus: {
          status: 'not_listed',
          reference: null,
          tags: [],
          permalink: null,
        },
        virustotal: {
          status: 'not_configured',
          malicious: null,
          suspicious: null,
          reference: null,
        },
        urlscan: {
          status: 'not_configured',
          resultUrl: null,
        },
        alienVault: {
          status: 'unavailable',
          pulseCount: null,
          reference: null,
        },
      }),
      () => 'job_test_123',
    );

    expect(job.jobId).toBe('job_test_123');
    expect(job.status).toBe('completed');
    expect(job.results[0]).toEqual(
      expect.objectContaining({
        originalUrl: 'https://example.org',
        title: 'Example Domain',
        requestedDomains: ['example.org'],
        tracePath: 'storage/traces/job_test/example-org.zip',
        externalScans: expect.objectContaining({
          urlhaus: expect.objectContaining({
            status: 'not_listed',
          }),
          urlscan: expect.objectContaining({
            status: 'not_configured',
          }),
          alienVault: expect.objectContaining({
            status: 'unavailable',
          }),
        }),
      }),
    );
  });
});